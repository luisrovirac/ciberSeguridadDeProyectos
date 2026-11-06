// Package hadolint adapts Hadolint (Dockerfile linter).
package hadolint

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/detector"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/execx"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/normalizer"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
)

// Scanner is the Hadolint adapter.
type Scanner struct{}

// New creates the adapter.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (*Scanner) Name() string { return "hadolint" }

// Native implements scanners.Scanner.
func (*Scanner) Native() bool { return false }

// Tool implements scanners.Scanner.
func (*Scanner) Tool() *execx.Tool {
	return &execx.Tool{
		Name: "hadolint", Binary: "hadolint", Image: "hadolint/hadolint:v2.15.1",
		Entrypoint: []string{"/bin/hadolint"}, VersionArgs: []string{"--version"},
		InstallHint: "Install Hadolint: https://github.com/hadolint/hadolint#install (brew install hadolint | scoop install hadolint).",
	}
}

// Applicable when Dockerfiles exist.
func (*Scanner) Applicable(p *detector.Profile, _ *config.Config) bool { return len(p.Dockerfile) > 0 }

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request, res execx.Resolution) ([]finding.Finding, error) {
	args := []string{"--format", "json", "--no-fail", "--no-color"}
	args = append(args, req.Config.Scanners.For("hadolint").Args...)
	for _, df := range req.Profile.Dockerfile {
		args = append(args, "{{src}}/"+df)
	}
	out, err := req.Exec.Run(ctx, *s.Tool(), res, execx.Spec{Args: args, SrcDir: req.Root, AcceptExit: []int{1}})
	if err != nil {
		return nil, err
	}
	return Parse(out.Stdout, req.Root)
}

// Item is one Hadolint result.
type Item struct {
	Code    string `json:"code"`
	Column  int    `json:"column"`
	File    string `json:"file"`
	Level   string `json:"level"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// Parse converts Hadolint JSON into findings.
func Parse(data []byte, root string) ([]finding.Finding, error) {
	if strings.TrimSpace(string(data)) == "" {
		return nil, nil
	}
	var items []Item
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("parse hadolint output: %w", err)
	}
	out := make([]finding.Finding, 0, len(items))
	for _, it := range items {
		sev := finding.SeverityLow
		switch it.Level {
		case "error":
			sev = finding.SeverityMedium
		case "warning":
			sev = finding.SeverityLow
		case "info", "style":
			sev = finding.SeverityInfo
		}
		fam := Families[it.Code]
		if it.Code == "DL3002" {
			sev = finding.SeverityHigh
		}
		ref := "https://github.com/hadolint/hadolint/wiki/" + it.Code
		if strings.HasPrefix(it.Code, "SC") {
			ref = "https://www.shellcheck.net/wiki/" + it.Code
		}
		out = append(out, finding.Finding{
			Kind: finding.KindPotentialRisk, Category: finding.CategoryContainer,
			Title: it.Code + ": " + it.Message, Description: it.Message,
			Severity: sev, Confidence: finding.ConfidenceHigh, RuleID: it.Code, RuleFamily: fam,
			Location:   finding.Location{Path: normalizer.RelPath(root, it.File), StartLine: it.Line, EndLine: it.Line},
			References: []string{ref}, Tools: []string{"hadolint"},
		})
	}
	return out, nil
}

// Families maps Hadolint codes to cross-tool rule families.
var Families = map[string]string{
	"DL3002": "dockerfile.root-user",
	"DL3006": "dockerfile.unpinned-image",
	"DL3007": "dockerfile.unpinned-image",
	"DL3020": "dockerfile.add-instead-of-copy",
	"DL3004": "dockerfile.sudo",
	"DL4006": "dockerfile.curl-pipe-shell",
	"DL3064": "dockerfile.secret-in-env",
}
