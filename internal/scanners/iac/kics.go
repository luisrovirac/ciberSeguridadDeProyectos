package iac

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/detector"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/execx"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/normalizer"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
)

// KICS is the Checkmarx KICS adapter. Disabled by default because Checkov
// covers the same ground and KICS performs a version check against GitHub
// that cannot be turned off (in docker it runs with --network none offline).
type KICS struct{}

// NewKICS creates the adapter.
func NewKICS() *KICS { return &KICS{} }

// Name implements scanners.Scanner.
func (*KICS) Name() string { return "kics" }

// Native implements scanners.Scanner.
func (*KICS) Native() bool { return false }

// Tool implements scanners.Scanner.
func (*KICS) Tool() *execx.Tool {
	return &execx.Tool{
		Name: "kics", Binary: "kics", Image: "checkmarx/kics:v2.2.0",
		VersionArgs: []string{"version"},
		InstallHint: "Install KICS: https://docs.kics.io/latest/getting-started/ (docker image checkmarx/kics recommended).",
	}
}

// Applicable when IaC exists and the user enabled KICS explicitly.
func (*KICS) Applicable(p *detector.Profile, cfg *config.Config) bool {
	return (p.HasIaC() || len(p.Dockerfile) > 0) && cfg.Scanners.For("kics").IsEnabled(false)
}

// Scan implements scanners.Scanner.
func (k *KICS) Scan(ctx context.Context, req *scanners.Request, res execx.Resolution) ([]finding.Finding, error) {
	outDir := filepath.Join(req.WorkDir, "kics")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	args := []string{"scan", "-p", "{{src}}", "-o", "{{out}}", "--report-formats", "json", "--output-name", "results",
		"--no-progress", "--ci", "--disable-secrets", "--ignore-on-exit", "results"}
	args = append(args, req.Config.Scanners.For("kics").Args...)
	if _, err := req.Exec.Run(ctx, *k.Tool(), res, execx.Spec{
		Args: args, SrcDir: req.Root, OutDir: outDir, AcceptExit: []int{20, 30, 40, 50, 60},
		Env: map[string]string{"DISABLE_CRASH_REPORT": "0"},
	}); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(outDir, "results.json")) //nolint:gosec // our work dir
	if err != nil {
		return nil, fmt.Errorf("kics results not found: %w", err)
	}
	return ParseKICS(data, req.Root)
}

type kicsReport struct {
	Queries []struct {
		QueryName   string `json:"query_name"`
		QueryID     string `json:"query_id"`
		QueryURL    string `json:"query_url"`
		Severity    string `json:"severity"`
		Platform    string `json:"platform"`
		Category    string `json:"category"`
		Description string `json:"description"`
		CWE         string `json:"cwe"`
		Files       []struct {
			FileName      string `json:"file_name"`
			Line          int    `json:"line"`
			ResourceName  string `json:"resource_name"`
			ExpectedValue string `json:"expected_value"`
			ActualValue   string `json:"actual_value"`
		} `json:"files"`
	} `json:"queries"`
}

// ParseKICS converts a KICS results.json into findings.
func ParseKICS(data []byte, root string) ([]finding.Finding, error) {
	var r kicsReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse kics output: %w", err)
	}
	var out []finding.Finding
	for _, q := range r.Queries {
		cat := finding.CategoryIaC
		if q.Platform == "Dockerfile" {
			cat = finding.CategoryContainer
		}
		for _, f := range q.Files {
			fd := finding.Finding{
				Kind: finding.KindPotentialRisk, Category: cat,
				Title: q.QueryName, Description: q.Description,
				Severity: finding.ParseSeverity(q.Severity), Confidence: finding.ConfidenceHigh,
				RuleID:      "kics-" + q.QueryID,
				Location:    finding.Location{Path: normalizer.RelPath(root, f.FileName), StartLine: f.Line, EndLine: f.Line, Resource: f.ResourceName},
				Evidence:    "expected: " + f.ExpectedValue + "; actual: " + f.ActualValue,
				Remediation: f.ExpectedValue,
				Tools:       []string{"kics"}, Tags: []string{"policy-check"},
			}
			if q.QueryURL != "" {
				fd.References = []string{q.QueryURL}
			}
			if c := finding.NormalizeCWE(q.CWE); c != "" {
				fd.CWE = []string{c}
			}
			out = append(out, fd)
		}
	}
	return out, nil
}
