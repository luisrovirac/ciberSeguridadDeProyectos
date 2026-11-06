// Package finding defines the normalized finding model shared by every
// scanner, the deduplicator, the scorer and the reporters.
package finding

import (
	"fmt"
	"strings"
)

// Kind separates tool/database-confirmed vulnerabilities from heuristic risks.
type Kind string

const (
	// KindVulnerability means a vulnerability database or a dedicated tool
	// matched a known issue (for example a CVE affecting an exact package version).
	KindVulnerability Kind = "vulnerability"
	// KindPotentialRisk means a heuristic or pattern match. It is never a confirmed CVE.
	KindPotentialRisk Kind = "potential-risk"
)

// Category groups findings by domain.
type Category string

const (
	CategoryDependencyVuln Category = "dependency-vuln"
	CategorySecret         Category = "secret"
	CategoryIaC            Category = "iac-misconfig"
	CategoryContainer      Category = "container"
	CategorySAST           Category = "sast"
	CategoryDependencyRisk Category = "dependency-risk"
	CategoryDAST           Category = "dast"
	CategoryCustom         Category = "custom"
)

// Severity is the normalized severity scale.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityUnknown  Severity = "unknown"
)

// Rank returns an orderable number; higher is more severe.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// AllSeverities lists severities from most to least severe.
var AllSeverities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo, SeverityUnknown}

// ParseSeverity maps the many tool-specific spellings to the normalized scale.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return SeverityCritical
	case "high", "error", "severe":
		return SeverityHigh
	case "medium", "moderate", "warning", "warn":
		return SeverityMedium
	case "low", "style", "note":
		return SeverityLow
	case "info", "informational", "negligible", "none":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// SeverityFromScore maps a CVSS base score to the CVSS v3 qualitative scale.
func SeverityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// Confidence expresses how sure we are that the finding is a true positive.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Rank returns an orderable number; higher is more confident.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// ParseConfidence parses tool confidence labels.
func ParseConfidence(s string) Confidence {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "certain", "confirmed":
		return ConfidenceHigh
	case "medium", "firm", "moderate":
		return ConfidenceMedium
	case "low", "tentative", "undefined":
		return ConfidenceLow
	default:
		return ConfidenceMedium
	}
}

// TriageStatus records the result of human review.
type TriageStatus string

const (
	TriageOpen          TriageStatus = "open"
	TriageIgnored       TriageStatus = "ignored"
	TriageFalsePositive TriageStatus = "false-positive"
	TriageAccepted      TriageStatus = "accepted"
)

// Suppressed reports whether the status removes the finding from gating.
func (t TriageStatus) Suppressed() bool {
	return t == TriageIgnored || t == TriageFalsePositive || t == TriageAccepted
}

// CVSS holds a CVSS score and vector.
type CVSS struct {
	Version string  `json:"version,omitempty"`
	Vector  string  `json:"vector,omitempty"`
	Score   float64 `json:"score"`
	Source  string  `json:"source,omitempty"`
}

// Location points at the code that produced the finding.
type Location struct {
	Path      string `json:"path,omitempty"` // relative, forward slashes
	StartLine int    `json:"startLine,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	Commit    string `json:"commit,omitempty"`
	Resource  string `json:"resource,omitempty"` // IaC resource / k8s object / URL
}

// Package describes the affected dependency, if any.
type Package struct {
	Name          string   `json:"name"`
	Version       string   `json:"version,omitempty"`
	Ecosystem     string   `json:"ecosystem,omitempty"`
	PURL          string   `json:"purl,omitempty"`
	FixedVersions []string `json:"fixedVersions,omitempty"`
	Direct        *bool    `json:"direct,omitempty"`
}

// Triage stores the review state for a finding.
type Triage struct {
	Status        TriageStatus `json:"status"`
	Justification string       `json:"justification,omitempty"`
	Expires       string       `json:"expires,omitempty"`
	Source        string       `json:"source,omitempty"` // ignore-file / baseline / known-fp
}

// Finding is the normalized result shape. All scanners must produce it.
type Finding struct {
	ID          string     `json:"id"`
	Fingerprint string     `json:"fingerprint"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Kind        Kind       `json:"kind"`
	Category    Category   `json:"category"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	CVSS        *CVSS      `json:"cvss,omitempty"`
	Priority    float64    `json:"priority"`
	// Tools lists every scanner that reported this finding (after dedup).
	Tools       []string `json:"tools"`
	RuleID      string   `json:"ruleId,omitempty"`
	RuleFamily  string   `json:"ruleFamily,omitempty"`
	Location    Location `json:"location"`
	Package     *Package `json:"package,omitempty"`
	CVE         []string `json:"cve,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	CWE         []string `json:"cwe,omitempty"`
	Evidence    string   `json:"evidence,omitempty"` // always redacted
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
	Triage      Triage   `json:"triage"`
	GroupID     string   `json:"groupId,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	// AIExplanation is optional, non-authoritative text from an LLM.
	AIExplanation string `json:"aiExplanation,omitempty"`
	// IsNew is set when a baseline comparison was performed.
	IsNew *bool `json:"isNew,omitempty"`
}

// Validate checks the minimum invariants a scanner must respect.
func (f *Finding) Validate() error {
	if f.Title == "" {
		return fmt.Errorf("finding without title (rule %q)", f.RuleID)
	}
	if f.Kind != KindVulnerability && f.Kind != KindPotentialRisk {
		return fmt.Errorf("finding %q has invalid kind %q", f.Title, f.Kind)
	}
	if len(f.Tools) == 0 {
		return fmt.Errorf("finding %q has no tool", f.Title)
	}
	return nil
}

// Normalize fills defaults so every finding is well-formed.
func (f *Finding) Normalize() {
	if f.Severity == "" {
		f.Severity = SeverityUnknown
	}
	if f.Confidence == "" {
		f.Confidence = ConfidenceMedium
	}
	if f.Triage.Status == "" {
		f.Triage.Status = TriageOpen
	}
	f.Location.Path = strings.TrimPrefix(strings.ReplaceAll(f.Location.Path, "\\", "/"), "./")
	f.CVE = uniqueSorted(f.CVE)
	f.Aliases = uniqueSorted(f.Aliases)
	f.CWE = uniqueSorted(f.CWE)
	f.References = uniqueSorted(f.References)
	f.Tools = uniqueSorted(f.Tools)
	f.Tags = uniqueSorted(f.Tags)
}
