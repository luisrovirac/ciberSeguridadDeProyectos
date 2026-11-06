package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/secureprojects/secureprojects/internal/finding"
)

// SARIF 2.1.0 structures (subset). Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool                     sarifTool                `json:"tool"`
	Results                  []sarifResult            `json:"results"`
	OriginalURIBaseIDs       map[string]sarifArtifact `json:"originalUriBaseIds,omitempty"`
	VersionControlProvenance []sarifVCP               `json:"versionControlProvenance,omitempty"`
	Invocations              []sarifInvocation        `json:"invocations,omitempty"`
	Properties               map[string]any           `json:"properties,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifVCP struct {
	RepositoryURI string `json:"repositoryUri"`
	RevisionID    string `json:"revisionId,omitempty"`
	Branch        string `json:"branch,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name,omitempty"`
	ShortDescription     sarifMessage     `json:"shortDescription"`
	FullDescription      *sarifMessage    `json:"fullDescription,omitempty"`
	HelpURI              string           `json:"helpUri,omitempty"`
	Help                 *sarifMessage    `json:"help,omitempty"`
	DefaultConfiguration *sarifRuleConfig `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any   `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level"`
	Message             sarifMessage       `json:"message"`
	Locations           []sarifLocation    `json:"locations,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	Message          *sarifMessage  `json:"message,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifLogical struct {
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
	Region           *sarifRegion     `json:"region,omitempty"`
}

type sarifArtifactLoc struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium, finding.SeverityUnknown:
		return "warning"
	default:
		return "note"
	}
}

func precision(c finding.Confidence) string {
	switch c {
	case finding.ConfidenceHigh:
		return "high"
	case finding.ConfidenceMedium:
		return "medium"
	default:
		return "low"
	}
}

// securitySeverity returns the numeric score GitHub code scanning uses.
func securitySeverity(f *finding.Finding) string {
	if f.CVSS != nil && f.CVSS.Score > 0 {
		return fmt.Sprintf("%.1f", f.CVSS.Score)
	}
	switch f.Severity {
	case finding.SeverityCritical:
		return "9.5"
	case finding.SeverityHigh:
		return "7.5"
	case finding.SeverityMedium:
		return "5.0"
	case finding.SeverityLow:
		return "2.5"
	case finding.SeverityInfo:
		return "0.5"
	}
	return "5.0"
}

func ruleIDFor(f *finding.Finding) string {
	if f.RuleID != "" {
		return f.RuleID
	}
	if f.RuleFamily != "" {
		return f.RuleFamily
	}
	return string(f.Category)
}

// MarshalSARIF renders the report as SARIF 2.1.0.
func MarshalSARIF(r *Report) ([]byte, error) {
	ruleIdx := map[string]int{}
	var rules []sarifRule
	// Deterministic rule order: by rule id.
	ids := map[string]*finding.Finding{}
	for i := range r.Findings {
		f := &r.Findings[i]
		id := ruleIDFor(f)
		if prev, ok := ids[id]; !ok || f.Severity.Rank() > prev.Severity.Rank() {
			ids[id] = f
		}
	}
	keys := make([]string, 0, len(ids))
	for k := range ids {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, id := range keys {
		f := ids[id]
		short := f.Title
		if f.Category == finding.CategoryDependencyVuln && f.Package != nil {
			short = strings.TrimSpace(strings.Replace(f.Title, " in "+f.Package.Name+"@"+f.Package.Version, "", 1))
		}
		rule := sarifRule{
			ID: id, Name: sarifRuleName(id),
			ShortDescription:     sarifMessage{Text: truncate(short, 300)},
			DefaultConfiguration: &sarifRuleConfig{Level: sarifLevel(f.Severity)},
			Properties: map[string]any{
				"security-severity": securitySeverity(f),
				"precision":         precision(f.Confidence),
				"tags":              sarifTags(f),
			},
		}
		if f.Description != "" {
			rule.FullDescription = &sarifMessage{Text: truncate(f.Description, 1000)}
		}
		if len(f.References) > 0 {
			rule.HelpURI = f.References[0]
		}
		help := f.Remediation
		if f.Kind == finding.KindPotentialRisk {
			help = strings.TrimSpace("[potential risk - heuristic, not a confirmed vulnerability] " + help)
		}
		if help != "" {
			rule.Help = &sarifMessage{Text: help}
		}
		ruleIdx[id] = len(rules)
		rules = append(rules, rule)
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for i := range r.Findings {
		f := &r.Findings[i]
		id := ruleIDFor(f)
		msg := f.Title
		if f.Kind == finding.KindPotentialRisk {
			msg = "[potential risk, confidence " + string(f.Confidence) + "] " + msg
		}
		if f.Remediation != "" {
			msg += ". Remediation: " + f.Remediation
		}
		res := sarifResult{
			RuleID: id, RuleIndex: ruleIdx[id], Level: sarifLevel(f.Severity),
			Message:             sarifMessage{Text: truncate(msg, 2000)},
			PartialFingerprints: map[string]string{"secureprojects/v1": f.Fingerprint},
			Properties: map[string]any{
				"kind": f.Kind, "category": f.Category, "severity": f.Severity, "confidence": f.Confidence,
				"priority": f.Priority, "tools": f.Tools,
			},
		}
		if len(f.CVE) > 0 {
			res.Properties["cve"] = f.CVE
		}
		if len(f.CWE) > 0 {
			res.Properties["cwe"] = f.CWE
		}
		if f.Package != nil {
			res.Properties["package"] = f.Package
		}
		if f.Location.Path != "" {
			loc := sarifLocation{PhysicalLocation: &sarifPhysical{ArtifactLocation: sarifArtifactLoc{URI: escapeURI(f.Location.Path), URIBaseID: "%SRCROOT%"}}}
			if f.Location.StartLine > 0 {
				reg := &sarifRegion{StartLine: f.Location.StartLine}
				if f.Location.EndLine >= f.Location.StartLine {
					reg.EndLine = f.Location.EndLine
				}
				loc.PhysicalLocation.Region = reg
			}
			res.Locations = []sarifLocation{loc}
		} else if f.Location.Resource != "" {
			res.Locations = []sarifLocation{{LogicalLocations: []sarifLogical{{Name: f.Location.Resource, Kind: "resource"}}}}
		}
		if f.Triage.Status.Suppressed() {
			res.Suppressions = []sarifSuppression{{Kind: "external", Status: "accepted", Justification: string(f.Triage.Status) + ": " + f.Triage.Justification}}
		}
		results = append(results, res)
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name: "SecureProjects", Version: r.Tool.Version, InformationURI: r.Tool.URL, Rules: rules,
		}},
		Results:            results,
		OriginalURIBaseIDs: map[string]sarifArtifact{"%SRCROOT%": {}},
		Properties: map[string]any{
			"disclaimer": Disclaimer,
			"scanners":   r.Scan.Scanners,
		},
	}
	if rules == nil {
		run.Tool.Driver.Rules = []sarifRule{}
	}
	if r.Scan.Repository != "" && r.Scan.Commit != "" {
		run.VersionControlProvenance = []sarifVCP{{RepositoryURI: r.Scan.Repository, RevisionID: r.Scan.Commit, Branch: r.Scan.Branch}}
	}
	inv := sarifInvocation{ExecutionSuccessful: true}
	for _, s := range r.Scan.Scanners {
		switch s.Status {
		case "error":
			inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{Level: "error", Message: sarifMessage{Text: s.Name + ": " + s.Message}})
		case "skipped":
			inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{Level: "note", Message: sarifMessage{Text: s.Name + " skipped: " + s.Message}})
		}
	}
	run.Invocations = []sarifInvocation{inv}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	b, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// WriteSARIF writes the SARIF file.
func WriteSARIF(r *Report, path string) error {
	b, err := MarshalSARIF(r)
	if err != nil {
		return err
	}
	return writeFile(path, b)
}

func sarifTags(f *finding.Finding) []string {
	tags := []string{"security", string(f.Category), string(f.Kind)}
	for _, c := range f.CWE {
		tags = append(tags, "external/cwe/"+strings.ToLower(c))
	}
	return tags
}

func sarifRuleName(id string) string {
	var b strings.Builder
	up := true
	for _, r := range id {
		if r == '-' || r == '_' || r == '.' || r == '/' || r == ' ' {
			up = true
			continue
		}
		if up {
			b.WriteString(strings.ToUpper(string(r)))
			up = false
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func escapeURI(p string) string {
	return strings.ReplaceAll(strings.ReplaceAll(p, "%", "%25"), " ", "%20")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
