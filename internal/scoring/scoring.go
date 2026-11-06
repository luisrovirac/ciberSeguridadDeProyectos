// Package scoring computes a 0-100 priority for each finding.
//
// The formula is documented in docs/scoring.md:
//
//	base       = CVSS base score if available, else a severity weight
//	             (critical 9.5, high 7.5, medium 5.0, low 2.5, info 0.5, unknown 5.0)
//	confidence = high 1.0 | medium 0.75 | low 0.5
//	kind       = vulnerability 1.0 | potential-risk 0.8
//	exposure   = 1.0, x1.2 when the issue is directly exposed (direct
//	             dependency, deployable manifest, secret, malware),
//	             x0.7 when it lives in tests/fixtures/examples
//	fix        = x1.05 when a fixed version exists (actionable)
//	priority   = min(100, base * 10 * confidence * kind * exposure * fix)
package scoring

import (
	"math"
	"slices"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/fsutil"
)

// SeverityWeight is the base score used when no CVSS score exists.
func SeverityWeight(s finding.Severity) float64 {
	switch s {
	case finding.SeverityCritical:
		return 9.5
	case finding.SeverityHigh:
		return 7.5
	case finding.SeverityMedium:
		return 5.0
	case finding.SeverityLow:
		return 2.5
	case finding.SeverityInfo:
		return 0.5
	default:
		return 5.0
	}
}

// Score sets f.Priority (and fills Severity from CVSS when unknown).
func Score(f *finding.Finding) {
	base := SeverityWeight(f.Severity)
	if f.CVSS != nil && f.CVSS.Score > 0 {
		base = f.CVSS.Score
		if f.Severity == finding.SeverityUnknown {
			f.Severity = finding.SeverityFromScore(f.CVSS.Score)
		}
	}
	conf := map[finding.Confidence]float64{finding.ConfidenceHigh: 1.0, finding.ConfidenceMedium: 0.75, finding.ConfidenceLow: 0.5}[f.Confidence]
	if conf == 0 {
		conf = 0.75
	}
	kind := 0.8
	if f.Kind == finding.KindVulnerability {
		kind = 1.0
	}
	exposure := 1.0
	switch {
	case f.Location.Path != "" && fsutil.IsTestPath(f.Location.Path):
		exposure = 0.7
	case f.Package != nil && f.Package.Direct != nil && *f.Package.Direct:
		exposure = 1.2
	case f.Category == finding.CategorySecret:
		exposure = 1.2
	case f.Category == finding.CategoryContainer || f.Category == finding.CategoryIaC:
		exposure = 1.1
	case slices.Contains(f.Tags, "malware"):
		exposure = 1.2
	}
	fix := 1.0
	if f.Package != nil && len(f.Package.FixedVersions) > 0 {
		fix = 1.05
	}
	p := base * 10 * conf * kind * exposure * fix
	f.Priority = math.Round(math.Min(100, p)*10) / 10
}

// ScoreAll scores every finding.
func ScoreAll(fs []finding.Finding) {
	for i := range fs {
		Score(&fs[i])
	}
}

// Label returns a human label for a priority value.
func Label(p float64) string {
	switch {
	case p >= 80:
		return "P1"
	case p >= 55:
		return "P2"
	case p >= 30:
		return "P3"
	default:
		return "P4"
	}
}
