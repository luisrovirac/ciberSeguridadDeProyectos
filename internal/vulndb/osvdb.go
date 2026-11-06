// Package vulndb implements a local, offline copy of the public OSV database
// (https://osv.dev) and a matcher for resolved dependencies. The database is
// only downloaded by the explicit `secureprojects db update` command.
package vulndb

import (
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/secureprojects/secureprojects/internal/vulndb/lockfiles"
)

// OSV is the subset of the OSV schema (https://ossf.github.io/osv-schema/) we use.
type OSV struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary,omitempty"`
	Details   string   `json:"details,omitempty"`
	Aliases   []string `json:"aliases,omitempty"`
	Published string   `json:"published,omitempty"`
	Modified  string   `json:"modified,omitempty"`
	Withdrawn string   `json:"withdrawn,omitempty"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity,omitempty"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl,omitempty"`
		} `json:"package"`
		Ranges []struct {
			Type   string           `json:"type"`
			Events []map[string]any `json:"events"`
		} `json:"ranges,omitempty"`
		Versions          []string        `json:"versions,omitempty"`
		DatabaseSpecific  json.RawMessage `json:"database_specific,omitempty"`
		EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references,omitempty"`
	DatabaseSpecific struct {
		Severity string   `json:"severity,omitempty"`
		CWEIDs   []string `json:"cwe_ids,omitempty"`
	} `json:"database_specific,omitempty"`
}

// Event is one OSV range event.
type Event struct {
	Introduced   string `json:"i,omitempty"`
	Fixed        string `json:"f,omitempty"`
	LastAffected string `json:"l,omitempty"`
	Limit        string `json:"m,omitempty"`
}

// Range is a compact OSV range.
type Range struct {
	Type   string  `json:"t"`
	Events []Event `json:"e"`
}

// Affected is a compact OSV affected entry for a single package.
type Affected struct {
	Name     string   `json:"n"`
	Ranges   []Range  `json:"r,omitempty"`
	Versions []string `json:"v,omitempty"`
}

// Vuln is the compact record stored in the index.
type Vuln struct {
	ID         string     `json:"id"`
	Summary    string     `json:"s,omitempty"`
	Details    string     `json:"d,omitempty"`
	Aliases    []string   `json:"a,omitempty"`
	Published  string     `json:"p,omitempty"`
	Severity   []string   `json:"sv,omitempty"` // CVSS vectors
	DBSeverity string     `json:"ds,omitempty"`
	CWE        []string   `json:"c,omitempty"`
	References []string   `json:"rf,omitempty"`
	Affected   []Affected `json:"af"`
}

// Index is a per-ecosystem lookup table.
type Index struct {
	Ecosystem string           `json:"ecosystem"`
	BuiltAt   time.Time        `json:"builtAt"`
	Source    string           `json:"source"`
	Vulns     []Vuln           `json:"vulns"`
	Packages  map[string][]int `json:"packages"` // normalized name -> indexes into Vulns
}

// NormalizeName canonicalizes package names for lookups.
func NormalizeName(eco, name string) string {
	switch strings.ToLower(eco) {
	case "pypi":
		return lockfiles.NormalizePyPI(name)
	case "npm", "nuget", "packagist":
		return strings.ToLower(name)
	default:
		return name
	}
}

// Compact converts a full OSV record into the compact form, keeping only
// affected entries of the given ecosystem. ok=false if nothing remains.
func Compact(o *OSV, eco string) (Vuln, bool) {
	if o.Withdrawn != "" || o.ID == "" {
		return Vuln{}, false
	}
	v := Vuln{ID: o.ID, Summary: o.Summary, Aliases: o.Aliases, Published: o.Published, DBSeverity: o.DatabaseSpecific.Severity, CWE: o.DatabaseSpecific.CWEIDs}
	if len(o.Details) > 1500 {
		v.Details = o.Details[:1500] + "..."
	} else {
		v.Details = o.Details
	}
	for _, s := range o.Severity {
		if strings.HasPrefix(s.Type, "CVSS") {
			v.Severity = append(v.Severity, s.Score)
		}
	}
	for i, r := range o.References {
		if i >= 12 {
			break
		}
		v.References = append(v.References, r.URL)
	}
	for _, a := range o.Affected {
		if !strings.EqualFold(ecoBase(a.Package.Ecosystem), eco) {
			continue
		}
		ca := Affected{Name: NormalizeName(eco, a.Package.Name), Versions: a.Versions}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			cr := Range{Type: r.Type}
			for _, e := range r.Events {
				var ev Event
				if s, ok := e["introduced"].(string); ok {
					ev.Introduced = s
				}
				if s, ok := e["fixed"].(string); ok {
					ev.Fixed = s
				}
				if s, ok := e["last_affected"].(string); ok {
					ev.LastAffected = s
				}
				if s, ok := e["limit"].(string); ok {
					ev.Limit = s
				}
				cr.Events = append(cr.Events, ev)
			}
			ca.Ranges = append(ca.Ranges, cr)
		}
		// GHSA records frequently carry the severity per-affected entry.
		if v.DBSeverity == "" && len(a.DatabaseSpecific) > 0 {
			var ds struct {
				Severity string `json:"severity"`
			}
			if json.Unmarshal(a.DatabaseSpecific, &ds) == nil {
				v.DBSeverity = ds.Severity
			}
		}
		if len(ca.Ranges) > 0 || len(ca.Versions) > 0 {
			v.Affected = append(v.Affected, ca)
		}
	}
	return v, len(v.Affected) > 0
}

// ecoBase strips ecosystem suffixes like "Debian:11" -> "Debian".
func ecoBase(e string) string {
	b, _, _ := strings.Cut(e, ":")
	return b
}

// NewIndex creates an empty index.
func NewIndex(eco, source string) *Index {
	return &Index{Ecosystem: eco, Source: source, BuiltAt: time.Now().UTC(), Packages: map[string][]int{}}
}

// Add inserts a record.
func (ix *Index) Add(v Vuln) {
	pos := len(ix.Vulns)
	ix.Vulns = append(ix.Vulns, v)
	seen := map[string]bool{}
	for _, a := range v.Affected {
		if seen[a.Name] {
			continue
		}
		seen[a.Name] = true
		ix.Packages[a.Name] = append(ix.Packages[a.Name], pos)
	}
}

// AddOSVJSON parses one OSV JSON document and adds it.
func (ix *Index) AddOSVJSON(data []byte) error {
	var o OSV
	if err := json.Unmarshal(data, &o); err != nil {
		return err
	}
	if v, ok := Compact(&o, ix.Ecosystem); ok {
		ix.Add(v)
	}
	return nil
}

// BuildFromZip builds an index from an OSV "all.zip" export.
func BuildFromZip(zipPath, eco string) (*Index, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	ix := NewIndex(eco, "https://osv-vulnerabilities.storage.googleapis.com/"+eco+"/all.zip")
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > 50<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(rc, 50<<20))
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		_ = ix.AddOSVJSON(data) // skip malformed records
	}
	return ix, nil
}

// BuildFromDir builds an index from a directory of OSV JSON files (tests, mirrors).
func BuildFromDir(dir, eco string) (*Index, error) {
	ix := NewIndex(eco, "dir:"+filepath.Base(dir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // controlled dir
		if err != nil {
			return nil, err
		}
		if err := ix.AddOSVJSON(b); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
	}
	return ix, nil
}

// Save writes the index as gzip-compressed JSON atomically.
func (ix *Index) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "idx-*")
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(tmp)
	if err := json.NewEncoder(gz).Encode(ix); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := gz.Close(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), IndexPath(dir, ix.Ecosystem))
}

// IndexPath returns the on-disk path of an ecosystem index.
func IndexPath(dir, eco string) string {
	safe := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(eco)
	return filepath.Join(dir, safe+".idx.json.gz")
}

// ErrNoIndex means the ecosystem was never downloaded.
var ErrNoIndex = errors.New("OSV index not found")

// Load reads an ecosystem index.
func Load(dir, eco string) (*Index, error) {
	f, err := os.Open(IndexPath(dir, eco)) //nolint:gosec // inside db dir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoIndex
		}
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	var ix Index
	if err := json.NewDecoder(gz).Decode(&ix); err != nil {
		return nil, fmt.Errorf("corrupt OSV index for %s: %w", eco, err)
	}
	return &ix, nil
}

// Info returns build times of the available indexes.
func Info(dir string, ecos []string) map[string]time.Time {
	out := map[string]time.Time{}
	for _, e := range ecos {
		if st, err := os.Stat(IndexPath(dir, e)); err == nil {
			out[e] = st.ModTime().UTC()
		}
	}
	return out
}

// DefaultDir is the per-user database directory.
func DefaultDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "secureprojects", "osv")
}

// SortedEcosystems returns a stable list of ecosystems with indexes.
func SortedEcosystems(m map[string]time.Time) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
