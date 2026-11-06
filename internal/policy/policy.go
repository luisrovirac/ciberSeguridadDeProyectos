// Package policy applies triage decisions (ignore file, known false
// positives), baseline comparison and the CI fail-on threshold.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/secureprojects/secureprojects/internal/finding"
	"github.com/secureprojects/secureprojects/internal/fsutil"
)

// IgnoreRule suppresses findings. Reason is mandatory: every suppression
// must be justified so it can be audited.
type IgnoreRule struct {
	Fingerprint string `yaml:"fingerprint,omitempty"`
	Rule        string `yaml:"rule,omitempty"` // RuleID or RuleFamily
	Path        string `yaml:"path,omitempty"` // glob
	CVE         string `yaml:"cve,omitempty"`  // any vuln id/alias
	Package     string `yaml:"package,omitempty"`
	Status      string `yaml:"status,omitempty"` // ignored (default) | false-positive | accepted
	Reason      string `yaml:"reason"`
	Expires     string `yaml:"expires,omitempty"` // YYYY-MM-DD
}

// IgnoreFile is the YAML schema of .secureprojects-ignore.yaml.
type IgnoreFile struct {
	Ignores []IgnoreRule `yaml:"ignores"`
}

// LoadIgnoreFile reads an ignore file. A missing file is not an error.
func LoadIgnoreFile(path string) ([]IgnoreRule, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // user-provided path
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f IgnoreFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("ignore file %s: %w", path, err)
	}
	for i, r := range f.Ignores {
		if strings.TrimSpace(r.Reason) == "" {
			return nil, fmt.Errorf("ignore file %s: entry #%d has no reason (justification is mandatory)", path, i+1)
		}
		if r.Fingerprint == "" && r.Rule == "" && r.CVE == "" && r.Path == "" {
			return nil, fmt.Errorf("ignore file %s: entry #%d matches nothing (set fingerprint, rule, cve or path)", path, i+1)
		}
		switch r.Status {
		case "", "ignored", "false-positive", "accepted":
		default:
			return nil, fmt.Errorf("ignore file %s: entry #%d has invalid status %q", path, i+1, r.Status)
		}
		if r.Expires != "" {
			if _, err := time.Parse("2006-01-02", r.Expires); err != nil {
				return nil, fmt.Errorf("ignore file %s: entry #%d has invalid expires %q (YYYY-MM-DD)", path, i+1, r.Expires)
			}
		}
	}
	return f.Ignores, nil
}

func (r IgnoreRule) expired(now time.Time) bool {
	if r.Expires == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", r.Expires)
	return err == nil && now.After(t.Add(24*time.Hour))
}

func (r IgnoreRule) matches(f *finding.Finding) bool {
	if r.Fingerprint != "" && r.Fingerprint != f.Fingerprint {
		return false
	}
	if r.Rule != "" && !strings.EqualFold(r.Rule, f.RuleID) && !strings.EqualFold(r.Rule, f.RuleFamily) {
		return false
	}
	if r.Path != "" && !fsutil.MatchGlob(r.Path, f.Location.Path) {
		return false
	}
	if r.CVE != "" {
		found := false
		for _, id := range f.AllVulnIDs() {
			if strings.EqualFold(id, r.CVE) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.Package != "" && (f.Package == nil || !strings.EqualFold(f.Package.Name, r.Package)) {
		return false
	}
	return true
}

// ApplyIgnores sets the triage status of matching findings and returns the
// number of expired rules (which are not applied).
func ApplyIgnores(fs []finding.Finding, rules []IgnoreRule, now time.Time) (expired int) {
	for _, r := range rules {
		if r.expired(now) {
			expired++
		}
	}
	for i := range fs {
		f := &fs[i]
		for _, r := range rules {
			if r.expired(now) || !r.matches(f) {
				continue
			}
			st := finding.TriageStatus(r.Status)
			if st == "" {
				st = finding.TriageIgnored
			}
			f.Triage = finding.Triage{Status: st, Justification: r.Reason, Expires: r.Expires, Source: "ignore-file"}
			break
		}
	}
	return expired
}

// knownFP describes a well-known false positive pattern.
type knownFP struct {
	match         func(f *finding.Finding) bool
	justification string
}

var knownFalsePositives = []knownFP{
	{
		match: func(f *finding.Finding) bool {
			return f.Category == finding.CategorySecret && slices.Contains(f.Tags, "placeholder")
		},
		justification: "Value looks like a documented placeholder (e.g. contains EXAMPLE, like the AWS documentation key AKIAIOSFODNN7EXAMPLE), not a live credential.",
	},
	{
		match: func(f *finding.Finding) bool {
			return f.Category == finding.CategorySecret && (strings.HasSuffix(f.Location.Path, ".lock") || strings.HasSuffix(f.Location.Path, "-lock.json") || strings.HasSuffix(f.Location.Path, "go.sum"))
		},
		justification: "Integrity hashes in lockfiles look like high-entropy secrets but are public checksums.",
	},
}

// MarkKnownFalsePositives flags well-known false positives (still reported, never gating).
func MarkKnownFalsePositives(fs []finding.Finding) {
	for i := range fs {
		f := &fs[i]
		if f.Triage.Status != finding.TriageOpen {
			continue
		}
		for _, k := range knownFalsePositives {
			if k.match(f) {
				f.Triage = finding.Triage{Status: finding.TriageFalsePositive, Justification: k.justification, Source: "known-fp"}
				break
			}
		}
	}
}

// LoadBaseline reads fingerprints from a previous SecureProjects JSON report.
func LoadBaseline(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path) //nolint:gosec // user-provided path
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	var r struct {
		SchemaVersion string `json:"schemaVersion"`
		Findings      []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("baseline %s is not a SecureProjects JSON report: %w", path, err)
	}
	if r.SchemaVersion == "" {
		return nil, fmt.Errorf("baseline %s is not a SecureProjects JSON report (missing schemaVersion)", path)
	}
	set := make(map[string]bool, len(r.Findings))
	for _, f := range r.Findings {
		set[f.Fingerprint] = true
	}
	return set, nil
}

// MarkNew sets IsNew on every finding according to the baseline.
func MarkNew(fs []finding.Finding, baseline map[string]bool) {
	for i := range fs {
		isNew := !baseline[fs[i].Fingerprint]
		fs[i].IsNew = &isNew
	}
}

// OnlyNew keeps findings absent from the baseline.
func OnlyNew(fs []finding.Finding) []finding.Finding {
	out := fs[:0:0]
	for _, f := range fs {
		if f.IsNew == nil || *f.IsNew {
			out = append(out, f)
		}
	}
	return out
}

// Gate decides whether the findings exceed the CI threshold.
// Suppressed findings never gate. Potential risks below minPotentialConf never gate.
func Gate(fs []finding.Finding, failOn string, minPotentialConf finding.Confidence) (failing []finding.Finding) {
	if failOn == "none" || failOn == "" {
		return nil
	}
	threshold := finding.ParseSeverity(failOn).Rank()
	for _, f := range fs {
		if f.Triage.Status.Suppressed() {
			continue
		}
		if f.Kind == finding.KindPotentialRisk && minPotentialConf != "" && f.Confidence.Rank() < minPotentialConf.Rank() {
			continue
		}
		sev := f.Severity
		if sev == finding.SeverityUnknown && f.Kind == finding.KindVulnerability {
			sev = finding.SeverityMedium // unknown-severity CVEs are treated as medium
		}
		if sev.Rank() >= threshold {
			failing = append(failing, f)
		}
	}
	return failing
}
