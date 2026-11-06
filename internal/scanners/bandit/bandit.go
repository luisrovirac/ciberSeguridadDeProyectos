// Package bandit adapts PyCQA Bandit (Python SAST).
package bandit

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

// Scanner is the Bandit adapter (local binary only: there is no official image).
type Scanner struct{}

// New creates the adapter.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (*Scanner) Name() string { return "bandit" }

// Native implements scanners.Scanner.
func (*Scanner) Native() bool { return false }

// Tool implements scanners.Scanner.
func (*Scanner) Tool() *execx.Tool {
	return &execx.Tool{
		Name: "bandit", Binary: "bandit", VersionArgs: []string{"--version"},
		InstallHint: "Install Bandit: pip install bandit (or pipx install bandit).",
	}
}

// Applicable when Python sources exist.
func (*Scanner) Applicable(p *detector.Profile, _ *config.Config) bool { return p.Has("Python") }

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request, res execx.Resolution) ([]finding.Finding, error) {
	args := []string{"-r", "-f", "json", "-q"}
	var excl []string
	for _, e := range req.Config.Exclude {
		excl = append(excl, "*/"+strings.Trim(strings.TrimPrefix(e, "**/"), "/*")+"/*")
	}
	if len(excl) > 0 {
		args = append(args, "-x", strings.Join(excl, ","))
	}
	args = append(args, req.Config.Scanners.For("bandit").Args...)
	args = append(args, "{{src}}")
	out, err := req.Exec.Run(ctx, *s.Tool(), res, execx.Spec{Args: args, SrcDir: req.Root, AcceptExit: []int{1}})
	if err != nil {
		return nil, err
	}
	return Parse(out.Stdout, req.Root)
}

// Output mirrors Bandit's JSON formatter.
type Output struct {
	Results []struct {
		Filename        string `json:"filename"`
		LineNumber      int    `json:"line_number"`
		LineRange       []int  `json:"line_range"`
		IssueSeverity   string `json:"issue_severity"`
		IssueConfidence string `json:"issue_confidence"`
		IssueText       string `json:"issue_text"`
		TestID          string `json:"test_id"`
		TestName        string `json:"test_name"`
		IssueCWE        struct {
			ID   int    `json:"id"`
			Link string `json:"link"`
		} `json:"issue_cwe"`
		MoreInfo string `json:"more_info"`
		Code     string `json:"code"`
	} `json:"results"`
}

// Parse converts Bandit JSON into findings.
func Parse(data []byte, root string) ([]finding.Finding, error) {
	var o Output
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("parse bandit output: %w", err)
	}
	var out []finding.Finding
	for _, r := range o.Results {
		end := r.LineNumber
		if n := len(r.LineRange); n > 0 {
			end = r.LineRange[n-1]
		}
		f := finding.Finding{
			Kind: finding.KindPotentialRisk, Category: finding.CategorySAST,
			Title: r.TestID + " " + r.TestName, Description: r.IssueText,
			Severity: finding.ParseSeverity(r.IssueSeverity), Confidence: finding.ParseConfidence(r.IssueConfidence),
			RuleID: r.TestID, RuleFamily: Families[r.TestID],
			Location: finding.Location{Path: normalizer.RelPath(root, r.Filename), StartLine: r.LineNumber, EndLine: end},
			Evidence: r.Code, Tools: []string{"bandit"},
		}
		if r.IssueCWE.ID > 0 {
			f.CWE = []string{fmt.Sprintf("CWE-%d", r.IssueCWE.ID)}
		}
		if r.MoreInfo != "" {
			f.References = []string{r.MoreInfo}
		}
		out = append(out, f)
	}
	return out, nil
}

// Families maps Bandit test IDs to cross-tool families.
var Families = map[string]string{
	"B307": "sast.code-injection", "B102": "sast.code-injection",
	"B301": "sast.insecure-deserialization", "B403": "sast.insecure-deserialization", "B506": "sast.insecure-deserialization",
	"B602": "sast.command-injection", "B605": "sast.command-injection", "B604": "sast.command-injection",
	"B501": "sast.tls-no-verify", "B323": "sast.tls-no-verify",
	"B303": "sast.weak-hash", "B324": "sast.weak-hash",
	"B201": "sast.debug-enabled", "B608": "sast.sql-injection",
}
