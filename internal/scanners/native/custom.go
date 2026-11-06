package native

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/detector"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/execx"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
)

// CustomRulesFile is the YAML schema for user-defined rules.
type CustomRulesFile struct {
	Rules []PatternRule `yaml:"rules"`
}

// LoadCustomRules reads and validates a rules file.
func LoadCustomRules(path string) ([]PatternRule, error) {
	b, err := os.ReadFile(path) //nolint:gosec // user-provided path
	if err != nil {
		return nil, err
	}
	var f CustomRulesFile
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("custom rules %s: %w", path, err)
	}
	seen := map[string]bool{}
	for i := range f.Rules {
		r := &f.Rules[i]
		if r.ID == "" || r.Pattern == "" || r.Title == "" {
			return nil, fmt.Errorf("custom rule #%d: id, title and pattern are required", i+1)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("custom rule %s: duplicate id", r.ID)
		}
		seen[r.ID] = true
		if finding.ParseSeverity(r.Severity) == finding.SeverityUnknown {
			return nil, fmt.Errorf("custom rule %s: invalid severity %q", r.ID, r.Severity)
		}
		if r.Confidence == "" {
			r.Confidence = "low"
		}
		if err := r.Compile(); err != nil {
			return nil, fmt.Errorf("custom rule %s: %w", r.ID, err)
		}
	}
	return f.Rules, nil
}

// Custom runs user-defined regex rules. Results are always potential risks.
type Custom struct {
	base
	rules []PatternRule
}

// NewCustom creates the analyzer with preloaded rules (may be empty).
func NewCustom(rules []PatternRule) *Custom {
	return &Custom{base: base{"native-custom"}, rules: rules}
}

// Applicable when the user configured rules.
func (c *Custom) Applicable(_ *detector.Profile, _ *config.Config) bool { return len(c.rules) > 0 }

// Scan implements scanners.Scanner.
func (c *Custom) Scan(ctx context.Context, req *scanners.Request, _ execx.Resolution) ([]finding.Finding, error) {
	return applyPatternRules(ctx, req, c.rules, finding.CategoryCustom, []string{"heuristic", "custom-rule"})
}
