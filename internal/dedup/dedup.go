// Package dedup merges duplicate findings reported by several tools and
// assigns group identifiers to related findings.
//
// Merge strategy (documented in docs/architecture.md):
//  1. Same fingerprint                      -> duplicates.
//  2. Dependency vulns: same package@version and at least one shared
//     identifier (CVE/GHSA/OSV id, aliases included) -> duplicates.
//  3. Location findings (secret, sast, container, iac): same file, lines
//     within 1 of each other and a compatible rule (same rule family, or a
//     shared CWE for SAST, or any secret on the same line) -> duplicates.
//
// When several tools agree, the merged finding's confidence is raised one
// level (independent corroboration).
package dedup

import (
	"sort"
	"strings"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/vulndb"
)

// Merge deduplicates findings and returns them in a stable order.
func Merge(in []finding.Finding) []finding.Finding {
	n := len(in)
	if n == 0 {
		return nil
	}
	uf := newUnionFind(n)

	// 1. identical fingerprints
	byFP := map[string]int{}
	for i, f := range in {
		if j, ok := byFP[f.Fingerprint]; ok {
			uf.union(i, j)
		} else {
			byFP[f.Fingerprint] = i
		}
	}

	// 2. dependency vulnerabilities sharing an identifier on the same package version
	idOwner := map[string]int{}
	for i, f := range in {
		if f.Category != finding.CategoryDependencyVuln || f.Package == nil {
			continue
		}
		pk := pkgKey(f.Package)
		for _, id := range f.AllVulnIDs() {
			k := pk + "|" + strings.ToUpper(id)
			if j, ok := idOwner[k]; ok {
				uf.union(i, j)
			} else {
				idOwner[k] = i
			}
		}
	}

	// 3. location-based duplicates
	byPath := map[string][]int{}
	for i, f := range in {
		switch f.Category {
		case finding.CategorySecret, finding.CategorySAST, finding.CategoryContainer, finding.CategoryIaC:
			if f.Location.Path != "" {
				byPath[string(f.Category)+"|"+f.Location.Path] = append(byPath[string(f.Category)+"|"+f.Location.Path], i)
			}
		}
	}
	for _, idx := range byPath {
		for a := 0; a < len(idx); a++ {
			for b := a + 1; b < len(idx); b++ {
				if sameIssue(&in[idx[a]], &in[idx[b]]) {
					uf.union(idx[a], idx[b])
				}
			}
		}
	}

	groups := map[int][]int{}
	for i := range in {
		r := uf.find(i)
		groups[r] = append(groups[r], i)
	}
	out := make([]finding.Finding, 0, len(groups))
	for _, members := range groups {
		fs := make([]finding.Finding, len(members))
		for k, m := range members {
			fs[k] = in[m]
		}
		out = append(out, mergeGroup(fs))
	}
	assignGroups(out)
	Sort(out)
	return out
}

func pkgKey(p *finding.Package) string {
	name := strings.ToLower(p.Name)
	if strings.EqualFold(p.Ecosystem, "PyPI") || strings.EqualFold(p.Ecosystem, "pip") {
		name = vulndb.NormalizeName("PyPI", name)
	}
	return name + "@" + strings.TrimPrefix(p.Version, "v")
}

func sameIssue(a, b *finding.Finding) bool {
	if a.Location.Commit != b.Location.Commit {
		return false
	}
	// A single tool reporting two findings near each other means two issues;
	// location-based merging only applies across different tools.
	for _, ta := range a.Tools {
		for _, tb := range b.Tools {
			if ta == tb {
				return false
			}
		}
	}
	la, lb := a.Location.StartLine, b.Location.StartLine
	// File-level issues (e.g. "container runs as root") have no meaningful
	// line: tools point at FROM, the last line, or nothing at all.
	if a.RuleFamily != "" && a.RuleFamily == b.RuleFamily && fileLevelFamilies[a.RuleFamily] {
		return true
	}
	// IaC/container tools anchor the same issue to different lines of the
	// same resource (resource start, container block, offending key):
	// same family + same resource or overlapping line ranges is a duplicate.
	if a.RuleFamily != "" && a.RuleFamily == b.RuleFamily && (a.Category == finding.CategoryIaC || a.Category == finding.CategoryContainer) {
		if ra, rb := normResource(a.Location.Resource), normResource(b.Location.Resource); ra != "" && ra == rb {
			return true
		}
		if la > 0 && lb > 0 && rangesOverlap(a.Location, b.Location) {
			return true
		}
	}
	if la > 0 && lb > 0 {
		d := la - lb
		if d < -1 || d > 1 {
			return false
		}
	} else if a.Location.Resource == "" || a.Location.Resource != b.Location.Resource {
		if la != 0 || lb != 0 {
			return false
		}
	}
	if a.RuleFamily != "" && a.RuleFamily == b.RuleFamily {
		return true
	}
	switch a.Category {
	case finding.CategorySecret:
		// Two secret detectors firing on the same line describe the same leak.
		return la > 0 && la == lb
	case finding.CategorySAST:
		// CWE-only matches require the exact same line to avoid chaining
		// neighbouring issues together.
		if la != lb {
			return false
		}
		for _, c := range a.CWE {
			for _, d := range b.CWE {
				if c == d {
					return true
				}
			}
		}
	}
	return false
}

// fileLevelFamilies describe a property of a whole file.
var fileLevelFamilies = map[string]bool{
	"dockerfile.root-user":      true,
	"dockerfile.no-healthcheck": true,
}

func rangesOverlap(a, b finding.Location) bool {
	ae, be := max(a.StartLine, a.EndLine), max(b.StartLine, b.EndLine)
	return a.StartLine <= be+1 && b.StartLine <= ae+1
}

// normResource makes "Deployment/goapp" and "Deployment.default.goapp" comparable.
func normResource(r string) string {
	parts := strings.FieldsFunc(strings.ToLower(r), func(c rune) bool { return c == '/' || c == '.' || c == ' ' })
	out := parts[:0]
	for _, p := range parts {
		if p != "default" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ".")
}

var confUp = map[finding.Confidence]finding.Confidence{
	finding.ConfidenceLow: finding.ConfidenceMedium, finding.ConfidenceMedium: finding.ConfidenceHigh, finding.ConfidenceHigh: finding.ConfidenceHigh,
}

func mergeGroup(fs []finding.Finding) finding.Finding {
	if len(fs) == 1 {
		return fs[0]
	}
	// Primary: most informative member.
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if (a.CVSS != nil) != (b.CVSS != nil) {
			return a.CVSS != nil
		}
		if a.Confidence.Rank() != b.Confidence.Rank() {
			return a.Confidence.Rank() > b.Confidence.Rank()
		}
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if len(a.Description) != len(b.Description) {
			return len(a.Description) > len(b.Description)
		}
		return a.Fingerprint < b.Fingerprint
	})
	m := fs[0]
	tools := map[string]bool{}
	fp := ""
	nativeFP := ""
	for _, f := range fs {
		for _, t := range f.Tools {
			tools[t] = true
		}
		m.CVE = append(m.CVE, f.CVE...)
		m.Aliases = append(m.Aliases, f.Aliases...)
		m.CWE = append(m.CWE, f.CWE...)
		m.References = append(m.References, f.References...)
		m.Tags = append(m.Tags, f.Tags...)
		if f.Kind == finding.KindVulnerability {
			m.Kind = finding.KindVulnerability
		}
		if m.CVSS == nil && f.CVSS != nil {
			m.CVSS = f.CVSS
		}
		if m.Remediation == "" {
			m.Remediation = f.Remediation
		}
		if m.Evidence == "" {
			m.Evidence = f.Evidence
		}
		if m.RuleFamily == "" {
			m.RuleFamily = f.RuleFamily
		}
		if m.Location.StartLine == 0 && f.Location.StartLine > 0 {
			m.Location = f.Location
		}
		if m.Package != nil && f.Package != nil {
			m.Package.FixedVersions = append(m.Package.FixedVersions, f.Package.FixedVersions...)
			if m.Package.PURL == "" {
				m.Package.PURL = f.Package.PURL
			}
			if m.Package.Direct == nil {
				m.Package.Direct = f.Package.Direct
			}
		}
		if f.Severity.Rank() > m.Severity.Rank() && (m.CVSS == nil || m.CVSS.Score == 0) {
			m.Severity = f.Severity
		}
		if f.Triage.Status != finding.TriageOpen && m.Triage.Status == finding.TriageOpen {
			m.Triage = f.Triage
		}
		if fp == "" || f.Fingerprint < fp {
			fp = f.Fingerprint
		}
		if isNativeOnly(f.Tools) && (nativeFP == "" || f.Fingerprint < nativeFP) {
			nativeFP = f.Fingerprint
		}
	}
	// Prefer the native fingerprint: native analyzers always run, so the
	// identity stays stable when external tools are installed or removed.
	if nativeFP != "" {
		fp = nativeFP
	}
	m.Fingerprint = fp
	m.Tools = keys(tools)
	if m.Package != nil {
		m.Package.FixedVersions = finding.UniqueSorted(m.Package.FixedVersions)
	}
	if len(m.Tools) > 1 {
		m.Confidence = confUp[m.Confidence]
		m.Tags = append(m.Tags, "corroborated")
	}
	m.Normalize()
	return m
}

func isNativeOnly(tools []string) bool {
	for _, t := range tools {
		if !strings.HasPrefix(t, "native-") {
			return false
		}
	}
	return len(tools) > 0
}

// assignGroups sets GroupID so related (non-duplicate) findings can be grouped.
func assignGroups(fs []finding.Finding) {
	for i := range fs {
		f := &fs[i]
		switch {
		case f.Package != nil && f.Category == finding.CategoryDependencyVuln:
			f.GroupID = "dep:" + pkgKey(f.Package)
		case f.Location.Path != "":
			f.GroupID = string(f.Category) + ":" + f.Location.Path
		case f.Location.Resource != "":
			f.GroupID = string(f.Category) + ":" + f.Location.Resource
		default:
			f.GroupID = string(f.Category)
		}
	}
}

// Sort orders findings by priority, severity, then fingerprint (stable output).
func Sort(fs []finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.Fingerprint < b.Fingerprint
	})
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type unionFind struct{ p []int }

func newUnionFind(n int) *unionFind {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	return &unionFind{p}
}

func (u *unionFind) find(x int) int {
	for u.p[x] != x {
		u.p[x] = u.p[u.p[x]]
		x = u.p[x]
	}
	return x
}

func (u *unionFind) union(a, b int) {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	if ra < rb {
		u.p[rb] = ra
	} else {
		u.p[ra] = rb
	}
}
