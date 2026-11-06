// Package report builds the versioned report model and renders it as
// JSON, SARIF 2.1.0, self-contained HTML and console tables.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/secureprojects/secureprojects/internal/config"
	"github.com/secureprojects/secureprojects/internal/detector"
	"github.com/secureprojects/secureprojects/internal/finding"
	"github.com/secureprojects/secureprojects/internal/scanners"
)

// SchemaVersion of the JSON report. Bump the major version on breaking changes.
const SchemaVersion = "1.0.0"

// ToolInfo identifies the SecureProjects build.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	URL     string `json:"url,omitempty"`
}

// ScanInfo describes the scan context.
type ScanInfo struct {
	StartedAt  time.Time         `json:"startedAt"`
	FinishedAt time.Time         `json:"finishedAt"`
	DurationMs int64             `json:"durationMs"`
	Target     string            `json:"target"`
	TargetType string            `json:"targetType"` // local | repository | merged
	Repository string            `json:"repository,omitempty"`
	Commit     string            `json:"commit,omitempty"`
	Branch     string            `json:"branch,omitempty"`
	Offline    bool              `json:"offline"`
	Safe       bool              `json:"safe"`
	ActiveScan bool              `json:"activeScan"`
	Profile    *detector.Profile `json:"profile,omitempty"`
	Config     *config.Config    `json:"config,omitempty"`
	Scanners   []scanners.Status `json:"scanners"`
	Warnings   []string          `json:"warnings,omitempty"`
}

// Gate is the CI decision.
type Gate struct {
	FailOn       string `json:"failOn"`
	Failed       bool   `json:"failed"`
	FailingCount int    `json:"failingCount"`
}

// Summary aggregates findings.
type Summary struct {
	Total      int            `json:"total"`
	Open       int            `json:"open"`
	Suppressed int            `json:"suppressed"`
	New        *int           `json:"new,omitempty"`
	BySeverity map[string]int `json:"bySeverity"`
	ByKind     map[string]int `json:"byKind"`
	ByCategory map[string]int `json:"byCategory"`
	ByTool     map[string]int `json:"byTool"`
	ByFile     map[string]int `json:"byFile"`
	Gate       Gate           `json:"gate"`
}

// Report is the complete, versioned output document.
type Report struct {
	SchemaVersion string            `json:"schemaVersion"`
	Tool          ToolInfo          `json:"tool"`
	Scan          ScanInfo          `json:"scan"`
	Summary       Summary           `json:"summary"`
	Findings      []finding.Finding `json:"findings"`
	Disclaimer    string            `json:"disclaimer"`
}

// Disclaimer is embedded in every report.
const Disclaimer = "Findings of kind 'vulnerability' were matched by a vulnerability database or a dedicated tool against an exact component version. " +
	"Findings of kind 'potential-risk' come from heuristics or policy checks and are NOT confirmed vulnerabilities; review them before acting. " +
	"Absence of findings does not prove absence of vulnerabilities. Only scan projects you own or are authorized to test."

// Summarize computes the summary (gate is set by the caller).
func Summarize(fs []finding.Finding) Summary {
	s := Summary{
		BySeverity: map[string]int{}, ByKind: map[string]int{}, ByCategory: map[string]int{},
		ByTool: map[string]int{}, ByFile: map[string]int{},
	}
	for _, sev := range finding.AllSeverities {
		s.BySeverity[string(sev)] = 0
	}
	newCount, hasNew := 0, false
	for _, f := range fs {
		s.Total++
		if f.Triage.Status.Suppressed() {
			s.Suppressed++
			continue
		}
		s.Open++
		s.BySeverity[string(f.Severity)]++
		s.ByKind[string(f.Kind)]++
		s.ByCategory[string(f.Category)]++
		for _, t := range f.Tools {
			s.ByTool[t]++
		}
		if f.Location.Path != "" {
			s.ByFile[f.Location.Path]++
		}
		if f.IsNew != nil {
			hasNew = true
			if *f.IsNew {
				newCount++
			}
		}
	}
	if hasNew {
		s.New = &newCount
	}
	return s
}

// WriteJSON writes the report as indented JSON (stable key order).
func WriteJSON(r *Report, path string) error {
	b, err := MarshalJSON(r)
	if err != nil {
		return err
	}
	return writeFile(path, b)
}

// MarshalJSON renders the report as indented JSON.
func MarshalJSON(r *Report) ([]byte, error) {
	if r.Findings == nil {
		r.Findings = []finding.Finding{}
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ReadJSON loads a SecureProjects JSON report.
func ReadJSON(path string) (*Report, error) {
	b, err := os.ReadFile(path) //nolint:gosec // user-provided path
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if r.SchemaVersion == "" {
		return nil, fmt.Errorf("%s: not a SecureProjects JSON report", path)
	}
	return &r, nil
}

func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// TopFiles returns up to n files sorted by finding count.
func TopFiles(m map[string]int, n int) []KV {
	return topN(m, n)
}

// KV is a key/count pair.
type KV struct {
	Key   string
	Count int
}

func topN(m map[string]int, n int) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		if v > 0 {
			out = append(out, KV{k, v})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
