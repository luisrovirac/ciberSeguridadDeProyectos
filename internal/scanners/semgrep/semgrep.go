// Package semgrep adapts Semgrep CE (multi-language SAST).
package semgrep

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/detector"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/execx"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/normalizer"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
)

// builtinRules is a small offline ruleset shipped with SecureProjects so
// Semgrep is useful even when the registry cannot be reached.
//
//go:embed rules.yml
var builtinRules []byte

// Scanner is the Semgrep adapter.
type Scanner struct{}

// New creates the adapter.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (*Scanner) Name() string { return "semgrep" }

// Native implements scanners.Scanner.
func (*Scanner) Native() bool { return false }

// Tool implements scanners.Scanner.
func (*Scanner) Tool() *execx.Tool {
	return &execx.Tool{
		Name: "semgrep", Binary: "semgrep", Image: "semgrep/semgrep:1.184.0", Entrypoint: []string{"semgrep"},
		VersionArgs: []string{"--version"},
		InstallHint: "Install Semgrep: pip install semgrep (or brew install semgrep); on Windows prefer the docker image semgrep/semgrep.",
	}
}

var sastLangs = []string{"Go", "Python", "JavaScript", "TypeScript", "Java", "Kotlin", "Ruby", "PHP", "C#", "Rust", "C", "C++", "Scala", "Swift"}

// Applicable when source code exists.
func (*Scanner) Applicable(p *detector.Profile, _ *config.Config) bool {
	for _, l := range sastLangs {
		if p.Has(l) {
			return true
		}
	}
	return false
}

// Scan implements scanners.Scanner. Metrics and version checks are disabled.
// Online mode adds the public "p/default" registry ruleset; offline mode uses
// the embedded ruleset plus any user-configured rule files.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request, res execx.Resolution) ([]finding.Finding, error) {
	rulesDir := filepath.Join(req.WorkDir, "semgrep")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "secureprojects.yml"), builtinRules, 0o600); err != nil {
		return nil, err
	}
	args := []string{"scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
		"--timeout", "30", "--max-target-bytes", fmt.Sprint(req.Config.Limits.MaxFileSizeBytes),
		"--config", "{{out}}/secureprojects.yml"}
	if !req.Config.Offline {
		args = append(args, "--config", "p/default")
	}
	if c := req.Config.Scanners.For("semgrep").Config; c != "" {
		if res.Mode == execx.ModeDocker {
			req.Log.Warn("custom semgrep config is ignored in docker mode unless it lives inside the project", "config", c)
			if rel, err := filepath.Rel(req.Root, c); err == nil && !strings.HasPrefix(rel, "..") {
				args = append(args, "--config", execx.ContainerSrc+"/"+filepath.ToSlash(rel))
			}
		} else {
			args = append(args, "--config", c)
		}
	}
	for _, ex := range req.Config.Exclude {
		args = append(args, "--exclude", strings.TrimSuffix(strings.TrimPrefix(ex, "**/"), "/**"))
	}
	args = append(args, req.Config.Scanners.For("semgrep").Args...)
	args = append(args, "{{src}}")
	out, err := req.Exec.Run(ctx, *s.Tool(), res, execx.Spec{
		Args: args, SrcDir: req.Root, OutDir: rulesDir, AcceptExit: []int{1}, Network: !req.Config.Offline,
		Env: map[string]string{"SEMGREP_SEND_METRICS": "off", "XDG_CONFIG_HOME": "{{out}}"},
	})
	if err != nil {
		return nil, err
	}
	return Parse(out.Stdout, req.Root)
}

// Output mirrors Semgrep's JSON output.
type Output struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Message  string         `json:"message"`
			Severity string         `json:"severity"`
			Lines    string         `json:"lines"`
			Metadata map[string]any `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Level   string `json:"level"`
		Message string `json:"message"`
	} `json:"errors"`
}

// Parse converts Semgrep JSON into findings.
func Parse(data []byte, root string) ([]finding.Finding, error) {
	var o Output
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("parse semgrep output: %w", err)
	}
	var out []finding.Finding
	for _, r := range o.Results {
		md := r.Extra.Metadata
		// Rules loaded from a local file get the file's directory as an id prefix.
		if i := strings.Index(r.CheckID, "secureprojects."); i > 0 {
			r.CheckID = r.CheckID[i:]
		}
		f := finding.Finding{
			Kind: finding.KindPotentialRisk, Category: finding.CategorySAST,
			Title:       titleFor(r.CheckID, r.Extra.Message),
			Description: r.Extra.Message,
			RuleID:      r.CheckID,
			Severity:    severity(r.Extra.Severity, md),
			Confidence:  finding.ParseConfidence(str(md["confidence"])),
			Location:    finding.Location{Path: normalizer.RelPath(root, r.Path), StartLine: r.Start.Line, EndLine: r.End.Line},
			Evidence:    r.Extra.Lines,
			Tools:       []string{"semgrep"},
		}
		if f.Evidence == "requires login" {
			f.Evidence = ""
		}
		for _, c := range list(md["cwe"]) {
			if n := finding.NormalizeCWE(c); n != "" {
				f.CWE = append(f.CWE, n)
			}
		}
		f.References = list(md["references"])
		if src := str(md["source"]); src != "" {
			f.References = append(f.References, src)
		}
		if fam := str(md["secureprojects-family"]); fam != "" {
			f.RuleFamily = fam
		}
		classify(&f, r.CheckID)
		out = append(out, f)
	}
	return out, nil
}

func titleFor(id, msg string) string {
	parts := strings.Split(id, ".")
	name := parts[len(parts)-1]
	name = strings.ReplaceAll(name, "-", " ")
	if name == "" {
		name = msg
	}
	if len(name) > 0 {
		name = strings.ToUpper(name[:1]) + name[1:]
	}
	return name
}

// severity maps Semgrep ERROR/WARNING/INFO, preferring metadata impact when set.
func severity(s string, md map[string]any) finding.Severity {
	if impact := strings.ToLower(str(md["impact"])); impact != "" {
		switch impact {
		case "high":
			return finding.SeverityHigh
		case "medium":
			return finding.SeverityMedium
		case "low":
			return finding.SeverityLow
		}
	}
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "ERROR", "HIGH":
		return finding.SeverityHigh
	case "WARNING", "MEDIUM":
		return finding.SeverityMedium
	case "INFO", "LOW":
		return finding.SeverityLow
	}
	return finding.SeverityUnknown
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		if len(x) > 0 {
			return str(x[0])
		}
	}
	return ""
}

func list(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// classify moves Semgrep secret and Dockerfile rules to the matching
// categories so they deduplicate with other tools' findings.
func classify(f *finding.Finding, id string) {
	low := strings.ToLower(id)
	base := strings.ToLower(f.Location.Path)
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	switch {
	case strings.Contains(low, ".secrets.") || strings.HasPrefix(low, "secrets."):
		f.Category = finding.CategorySecret
		if f.RuleFamily == "" {
			f.RuleFamily = "secret.generic"
		}
	case strings.HasPrefix(low, "dockerfile.") || base == "dockerfile" || strings.HasSuffix(base, ".dockerfile"):
		f.Category = finding.CategoryContainer
		switch {
		case strings.Contains(low, "missing-user") || strings.Contains(low, "last-user-is-root"):
			f.RuleFamily = "dockerfile.root-user"
		case strings.Contains(low, "latest"):
			f.RuleFamily = "dockerfile.unpinned-image"
		}
	}
}
