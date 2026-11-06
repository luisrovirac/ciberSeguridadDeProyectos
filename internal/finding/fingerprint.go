package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

var (
	cveRe  = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)
	ghsaRe = regexp.MustCompile(`(?i)^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
	cweRe  = regexp.MustCompile(`(?i)CWE-?(\d+)`)
)

// IsCVE reports whether id looks like a CVE identifier.
func IsCVE(id string) bool { return cveRe.MatchString(strings.TrimSpace(id)) }

// NormalizeCWE converts "CWE-79: ..." / "79" / "cwe79" into "CWE-79".
func NormalizeCWE(s string) string {
	s = strings.TrimSpace(s)
	if m := cweRe.FindStringSubmatch(s); m != nil {
		return "CWE-" + m[1]
	}
	if s != "" && strings.Trim(s, "0123456789") == "" {
		return "CWE-" + s
	}
	return ""
}

// CanonicalVulnID picks a stable identifier among a vulnerability's ids:
// CVE first, then GHSA, then the lexicographically smallest remaining id.
func CanonicalVulnID(ids ...string) string {
	var cves, ghsas, others []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		switch {
		case id == "":
		case IsCVE(id):
			cves = append(cves, strings.ToUpper(id))
		case ghsaRe.MatchString(id):
			ghsas = append(ghsas, strings.ToUpper(id[:4])+strings.ToLower(id[4:]))
		default:
			others = append(others, id)
		}
	}
	for _, set := range [][]string{cves, ghsas, others} {
		if len(set) > 0 {
			sort.Strings(set)
			return set[0]
		}
	}
	return ""
}

// AllVulnIDs returns the union of ID, CVE and Aliases for a vulnerability finding.
func (f *Finding) AllVulnIDs() []string {
	ids := append([]string{}, f.CVE...)
	ids = append(ids, f.Aliases...)
	if f.RuleID != "" {
		ids = append(ids, f.RuleID)
	}
	return uniqueSorted(ids)
}

// ComputeFingerprint returns a stable identity hash that ignores line numbers
// so that moving code around does not create "new" findings.
func (f *Finding) ComputeFingerprint() string {
	var parts []string
	if f.Category == CategoryDependencyVuln && f.Package != nil {
		parts = []string{
			string(f.Category),
			strings.ToLower(f.Package.Ecosystem),
			strings.ToLower(f.Package.Name),
			f.Package.Version,
			CanonicalVulnID(f.AllVulnIDs()...),
		}
	} else {
		rule := f.RuleFamily
		if rule == "" {
			rule = f.RuleID
		}
		parts = []string{
			string(f.Category),
			rule,
			f.Location.Path,
			f.Location.Resource,
			normalizeEvidence(f.Evidence),
		}
		if f.Location.Commit != "" {
			parts = append(parts, f.Location.Commit)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func normalizeEvidence(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// UniqueSorted is exported for other packages that merge string sets.
func UniqueSorted(in []string) []string { return uniqueSorted(in) }
