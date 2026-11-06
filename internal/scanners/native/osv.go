package native

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/detector"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/execx"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/normalizer"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/vulndb"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/vulndb/lockfiles"
)

// OSVMatcher matches resolved dependencies against the local OSV database.
// Findings are Kind=vulnerability: they come from a curated vulnerability
// database matched against an exact installed version.
type OSVMatcher struct {
	base
	// Indexes can be injected (tests); otherwise they are loaded from DBDir.
	Indexes map[string]*vulndb.Index
	DBDir   string
}

// NewOSVMatcher creates the matcher reading indexes from dir.
func NewOSVMatcher(dir string) *OSVMatcher {
	if dir == "" {
		dir = vulndb.DefaultDir()
	}
	return &OSVMatcher{base: base{"native-osv"}, DBDir: dir}
}

// Applicable when dependency manifests/lockfiles exist.
func (m *OSVMatcher) Applicable(p *detector.Profile, _ *config.Config) bool { return p.HasManifests() }

// CacheKey invalidates cached results whenever an index is rebuilt.
func (m *OSVMatcher) CacheKey(req *scanners.Request) (string, bool) {
	if m.Indexes != nil {
		return "", false
	}
	var b strings.Builder
	info := vulndb.Info(m.DBDir, req.Config.VulnDB.Ecosystems)
	for _, e := range vulndb.SortedEcosystems(info) {
		b.WriteString(e + "=" + info[e].String() + ";")
	}
	return b.String(), true
}

// ParseProjectPackages parses every supported lockfile in the file list.
// When a directory has both a lockfile and a looser manifest for the same
// ecosystem, the lockfile wins to avoid duplicates.
func ParseProjectPackages(ctx context.Context, req *scanners.Request) []lockfiles.Package {
	var pkgs []lockfiles.Package
	_ = eachFile(ctx, req, func(rel string) bool { return lockfiles.ParserFor(rel) != nil }, func(rel string, data []byte) {
		pkgs = append(pkgs, lockfiles.ParserFor(rel)(rel, data)...)
	})
	return pkgs
}

// Scan implements scanners.Scanner.
func (m *OSVMatcher) Scan(ctx context.Context, req *scanners.Request, _ execx.Resolution) ([]finding.Finding, error) {
	pkgs := ParseProjectPackages(ctx, req)
	if len(pkgs) == 0 {
		return nil, nil
	}
	byEco := map[string][]lockfiles.Package{}
	for _, p := range pkgs {
		byEco[p.Ecosystem] = append(byEco[p.Ecosystem], p)
	}
	ecos := make([]string, 0, len(byEco))
	for e := range byEco {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)

	var out []finding.Finding
	var missing []string
	for _, eco := range ecos {
		ix := m.Indexes[eco]
		if ix == nil && m.Indexes == nil {
			loaded, err := vulndb.Load(m.DBDir, eco)
			if errors.Is(err, vulndb.ErrNoIndex) {
				missing = append(missing, eco)
				continue
			}
			if err != nil {
				return out, err
			}
			ix = loaded
			if age := time.Since(ix.BuiltAt); req.Config.VulnDB.MaxAgeDays > 0 && age > time.Duration(req.Config.VulnDB.MaxAgeDays)*24*time.Hour {
				req.Log.Warn("OSV database is stale; run 'secureprojects db update'", "ecosystem", eco, "age_days", int(age.Hours()/24))
			}
		}
		if ix == nil {
			missing = append(missing, eco)
			continue
		}
		for _, p := range byEco[eco] {
			for _, mt := range ix.Lookup(p.Name, p.Version) {
				out = append(out, osvFinding(p, mt))
			}
		}
	}
	if len(missing) > 0 && len(out) == 0 && len(missing) == len(ecos) {
		return nil, scanners.Skip(fmt.Sprintf("dependency CVE scanning not available: no local OSV database for %s (run 'secureprojects db update')", strings.Join(missing, ", ")))
	}
	if len(missing) > 0 {
		req.Log.Warn("no local OSV database for some ecosystems; their dependencies were NOT checked", "ecosystems", missing)
	}
	return out, nil
}

func osvFinding(p lockfiles.Package, mt vulndb.Match) finding.Finding {
	v := mt.Vuln
	var cves, aliases []string
	for _, a := range append([]string{v.ID}, v.Aliases...) {
		if finding.IsCVE(a) {
			cves = append(cves, a)
		} else if a != v.ID {
			aliases = append(aliases, a)
		}
	}
	aliases = append(aliases, v.ID)

	f := finding.Finding{
		Kind:       finding.KindVulnerability,
		Category:   finding.CategoryDependencyVuln,
		RuleID:     v.ID,
		CVE:        cves,
		Aliases:    aliases,
		Confidence: finding.ConfidenceHigh,
		Location:   finding.Location{Path: p.File, StartLine: p.Line, EndLine: p.Line},
		Package:    &finding.Package{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem, FixedVersions: mt.Fixed, Direct: p.Direct},
		References: append([]string{"https://osv.dev/vulnerability/" + v.ID}, v.References...),
		Tags:       []string{"osv"},
		Evidence:   p.Name + "@" + p.Version,
	}
	if !mt.ExactMatch {
		switch strings.ToLower(p.Ecosystem) {
		case "maven", "rubygems", "nuget", "packagist":
			f.Confidence = finding.ConfidenceMedium // simplified comparators
		}
	}
	for _, c := range v.CWE {
		if n := finding.NormalizeCWE(c); n != "" {
			f.CWE = append(f.CWE, n)
		}
	}
	title := v.Summary
	if title == "" {
		title = firstLine(v.Details)
	}
	id := finding.CanonicalVulnID(append([]string{v.ID}, v.Aliases...)...)
	f.Title = fmt.Sprintf("%s in %s@%s", id, p.Name, p.Version)
	if title != "" {
		f.Title += ": " + title
	}
	f.Description = v.Details
	if f.Description == "" {
		f.Description = v.Summary
	}

	// Severity: computed CVSS v3 > CVSS v2 > database severity label > unknown.
	for _, vec := range v.Severity {
		if c, ok := normalizer.CVSSFromVector(vec, "osv"); ok && (f.CVSS == nil || c.Version > f.CVSS.Version) {
			f.CVSS = c
		}
	}
	switch {
	case strings.HasPrefix(v.ID, "MAL-"):
		f.Severity = finding.SeverityCritical
		f.Title = fmt.Sprintf("Malicious package %s@%s (%s)", p.Name, p.Version, v.ID)
		f.Tags = append(f.Tags, "malware")
	case f.CVSS != nil && f.CVSS.Score > 0:
		f.Severity = finding.SeverityFromScore(f.CVSS.Score)
	case v.DBSeverity != "":
		f.Severity = finding.ParseSeverity(v.DBSeverity)
	default:
		f.Severity = finding.SeverityUnknown
	}

	if len(mt.Fixed) > 0 {
		f.Remediation = fmt.Sprintf("Upgrade %s to a fixed version (%s).", p.Name, strings.Join(mt.Fixed, ", "))
	} else {
		f.Remediation = fmt.Sprintf("No fixed version is published for %s; consider replacing the package or mitigating the issue.", p.Name)
	}
	return f
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}
