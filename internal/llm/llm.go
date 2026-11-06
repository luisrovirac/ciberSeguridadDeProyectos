// Package llm provides the OPTIONAL, opt-in explanation feature.
//
// Guarantees:
//   - Disabled by default; requires llm.enabled AND explicit consent.
//   - Never decides whether something is a vulnerability: it only receives
//     already-produced findings and returns explanatory text, stored in
//     Finding.AIExplanation and labelled as non-authoritative.
//   - Never sends source files. By default only finding metadata is sent
//     (title, category, rule, CWE/CVE, package, severity). The redacted
//     evidence line is sent only with llm.send_snippets: true.
package llm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/redact"
)

// Explainer produces non-authoritative explanations.
type Explainer interface {
	Explain(ctx context.Context, prompt string) (string, error)
}

const systemPrompt = `You are a security assistant helping a developer understand a finding produced by automated scanners.
Rules:
- You do NOT decide whether the finding is a real vulnerability; the scanner result is given as-is. If it is labelled "potential-risk", say it needs human verification.
- Explain in at most 120 words: what the issue means, how it could be exploited in general terms, and concrete remediation steps.
- Never invent CVE identifiers, versions or facts that are not in the input. If unsure, say so.
- Do not provide exploit code.`

// BuildPrompt renders the data sent to the model for one finding.
func BuildPrompt(f *finding.Finding, sendSnippet bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Title: %s\nKind: %s\nCategory: %s\nSeverity: %s\nConfidence: %s\n", f.Title, f.Kind, f.Category, f.Severity, f.Confidence)
	if f.RuleID != "" {
		fmt.Fprintf(&b, "Rule: %s\n", f.RuleID)
	}
	if len(f.CWE) > 0 {
		fmt.Fprintf(&b, "CWE: %s\n", strings.Join(f.CWE, ", "))
	}
	if len(f.CVE) > 0 {
		fmt.Fprintf(&b, "CVE: %s\n", strings.Join(f.CVE, ", "))
	}
	if f.Package != nil {
		fmt.Fprintf(&b, "Package: %s@%s (%s); fixed: %s\n", f.Package.Name, f.Package.Version, f.Package.Ecosystem, strings.Join(f.Package.FixedVersions, ", "))
	}
	if d := f.Description; d != "" {
		if len(d) > 800 {
			d = d[:800] + "..."
		}
		fmt.Fprintf(&b, "Scanner description: %s\n", redact.String(d))
	}
	if sendSnippet && f.Evidence != "" {
		fmt.Fprintf(&b, "Redacted evidence: %s\n", redact.String(f.Evidence))
	}
	return b.String()
}

// Anthropic implements Explainer with the official Anthropic Go SDK.
type Anthropic struct {
	client anthropic.Client
	model  string
}

// NewAnthropic creates the client. The API key is read from the env var
// named in config (default ANTHROPIC_API_KEY); without it the SDK falls back
// to its standard credential chain.
func NewAnthropic(cfg config.LLM) *Anthropic {
	opts := []option.RequestOption{option.WithRequestTimeout(90 * time.Second)}
	if k := os.Getenv(cfg.APIKeyEnv); k != "" && cfg.APIKeyEnv != "" {
		opts = append(opts, option.WithAPIKey(k))
	}
	if cfg.Endpoint != "" {
		opts = append(opts, option.WithBaseURL(cfg.Endpoint))
	}
	model := cfg.Model
	if model == "" {
		model = "claude-opus-5-5"
	}
	return &Anthropic{client: anthropic.NewClient(opts...), model: model}
}

// Explain implements Explainer.
func (a *Anthropic) Explain(ctx context.Context, prompt string) (string, error) {
	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     a.model,
		MaxTokens: 2000,
		System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
		OutputConfig: anthropic.OutputConfigParam{
			Effort: anthropic.OutputConfigEffortLow,
		},
		Messages: []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(prompt))},
	})
	if err != nil {
		return "", err
	}
	if resp.StopReason == anthropic.StopReasonRefusal {
		return "", errors.New("model declined to explain this finding")
	}
	var out strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			out.WriteString(t.Text)
		}
	}
	return strings.TrimSpace(out.String()), nil
}

// Enrich adds explanations to the most important open findings.
func Enrich(ctx context.Context, cfg config.LLM, ex Explainer, fs []finding.Finding, log *slog.Logger) int {
	if !cfg.Enabled || !cfg.Consent {
		return 0
	}
	min := finding.ParseSeverity(cfg.MinSeverity)
	done := 0
	for i := range fs {
		if done >= cfg.MaxFindings {
			break
		}
		f := &fs[i]
		if f.Triage.Status.Suppressed() || f.Severity.Rank() < min.Rank() {
			continue
		}
		text, err := ex.Explain(ctx, BuildPrompt(f, cfg.SendSnippets))
		if err != nil {
			log.Warn("LLM explanation failed; continuing without it", "error", redact.String(err.Error()))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		f.AIExplanation = redact.String(text)
		done++
	}
	return done
}
