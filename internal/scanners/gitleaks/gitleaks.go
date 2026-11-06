// Package gitleaks adapts Gitleaks for secrets in files and Git history.
package gitleaks

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
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/redact"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
)

// Scanner is the Gitleaks adapter.
type Scanner struct{}

// New creates the adapter.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (*Scanner) Name() string { return "gitleaks" }

// Native implements scanners.Scanner.
func (*Scanner) Native() bool { return false }

// Tool implements scanners.Scanner.
func (*Scanner) Tool() *execx.Tool {
	return &execx.Tool{
		Name: "gitleaks", Binary: "gitleaks", Image: "zricethezav/gitleaks:v8.30.1",
		VersionArgs: []string{"version"},
		InstallHint: "Install Gitleaks: https://github.com/gitleaks/gitleaks#installing (brew install gitleaks | choco install gitleaks | go install github.com/zricethezav/gitleaks/v8@latest).",
	}
}

// Applicable for every project.
func (*Scanner) Applicable(*detector.Profile, *config.Config) bool { return true }

// Scan runs "gitleaks dir" and, when the project is a Git repository and
// history scanning is enabled, "gitleaks git" as well. Secrets are redacted
// by gitleaks itself (--redact=100) so they never reach our process.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request, res execx.Resolution) ([]finding.Finding, error) {
	common := []string{"--report-format", "json", "--report-path", "-", "--redact=100", "--no-banner",
		"--exit-code", "0", "--log-level", "error", "--max-target-megabytes", fmt.Sprint(max(1, req.Config.Limits.MaxFileSizeBytes>>20))}
	common = append(common, req.Config.Scanners.For("gitleaks").Args...)
	env := map[string]string{
		// Allow reading a repository owned by another user (docker bind mounts).
		"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*",
	}
	run := func(mode string) ([]finding.Finding, error) {
		args := append([]string{mode}, common...)
		args = append(args, "{{src}}")
		out, err := req.Exec.Run(ctx, *s.Tool(), res, execx.Spec{Args: args, SrcDir: req.Root, Env: env})
		if err != nil {
			return nil, err
		}
		return Parse(out.Stdout, req.Root, mode == "git")
	}
	fs, err := run("dir")
	if err != nil {
		return nil, err
	}
	if req.Profile.HasGit && req.Config.ScanGitHistory {
		hist, herr := run("git")
		if herr != nil {
			req.Log.Warn("gitleaks history scan failed", "error", herr)
		}
		fs = append(fs, hist...)
	}
	return fs, nil
}

// Leak mirrors a gitleaks JSON finding (keys are Go field names).
type Leak struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Date        string   `json:"Date"`
	Tags        []string `json:"Tags"`
	Fingerprint string   `json:"Fingerprint"`
}

// Parse converts gitleaks JSON into findings.
func Parse(data []byte, root string, history bool) ([]finding.Finding, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var leaks []Leak
	if err := json.Unmarshal([]byte(trimmed), &leaks); err != nil {
		return nil, fmt.Errorf("parse gitleaks output: %w", err)
	}
	out := make([]finding.Finding, 0, len(leaks))
	for _, l := range leaks {
		path := normalizer.RelPath(root, l.File)
		f := finding.Finding{
			Kind: finding.KindPotentialRisk, Category: finding.CategorySecret,
			Title:       l.Description + " in " + path,
			Description: fmt.Sprintf("Gitleaks rule %q matched (entropy %.2f).", l.RuleID, l.Entropy),
			Severity:    finding.SeverityHigh, Confidence: finding.ConfidenceHigh,
			RuleID: "gitleaks-" + l.RuleID, RuleFamily: Family(l.RuleID),
			Location: finding.Location{Path: path, StartLine: l.StartLine, EndLine: l.EndLine},
			// Defense in depth: mask the secret again even though --redact is set.
			Evidence:    redact.Value(l.Match, l.Secret),
			CWE:         []string{"CWE-798"},
			Remediation: "Revoke and rotate the credential, remove it from code and Git history (git filter-repo/BFG), and use a secret manager.",
			Tools:       []string{"gitleaks"},
			Tags:        l.Tags,
		}
		if l.RuleID == "generic-api-key" {
			f.Severity, f.Confidence = finding.SeverityMedium, finding.ConfidenceMedium
		}
		if history {
			f.Location.Commit = l.Commit
			f.Tags = append(f.Tags, "git-history")
			f.Title = l.Description + " in Git history (" + path + ")"
		}
		out = append(out, f)
	}
	return out, nil
}

// Family maps gitleaks rule IDs to cross-tool families.
func Family(rule string) string {
	switch {
	case strings.HasPrefix(rule, "aws-access"):
		return "secret.aws-access-key"
	case strings.HasPrefix(rule, "github"):
		return "secret.github-token"
	case strings.HasPrefix(rule, "gitlab"):
		return "secret.gitlab-token"
	case rule == "private-key":
		return "secret.private-key"
	case strings.HasPrefix(rule, "slack-webhook"):
		return "secret.slack-webhook"
	case strings.HasPrefix(rule, "slack"):
		return "secret.slack-token"
	case strings.HasPrefix(rule, "stripe"):
		return "secret.stripe-key"
	case strings.HasPrefix(rule, "gcp-api-key"):
		return "secret.gcp-api-key"
	case rule == "jwt":
		return "secret.jwt"
	case strings.HasPrefix(rule, "npm"):
		return "secret.npm-token"
	case rule == "generic-api-key":
		return "secret.generic"
	}
	return "secret." + rule
}
