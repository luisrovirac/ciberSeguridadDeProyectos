// Package zap adapts the OWASP ZAP baseline scan (DAST). It is strictly
// opt-in: it only runs with --allow-active-scan, a --target-url and an
// explicit authorization acknowledgement. The baseline scan spiders the
// target and runs passive rules only (no attack payloads).
package zap

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/secureprojects/secureprojects/internal/config"
	"github.com/secureprojects/secureprojects/internal/detector"
	"github.com/secureprojects/secureprojects/internal/execx"
	"github.com/secureprojects/secureprojects/internal/finding"
	"github.com/secureprojects/secureprojects/internal/scanners"
)

// Scanner is the ZAP baseline adapter (docker only).
type Scanner struct{}

// New creates the adapter.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (*Scanner) Name() string { return "zap-baseline" }

// Native implements scanners.Scanner.
func (*Scanner) Native() bool { return false }

// Tool implements scanners.Scanner.
func (*Scanner) Tool() *execx.Tool {
	return &execx.Tool{
		Name: "zap-baseline", Binary: "zap-baseline.py", Image: "ghcr.io/zaproxy/zaproxy:stable",
		InstallHint: "ZAP runs through docker: install Docker and allow pulling ghcr.io/zaproxy/zaproxy:stable.",
	}
}

// Applicable only when active scanning was explicitly authorized.
func (*Scanner) Applicable(_ *detector.Profile, cfg *config.Config) bool {
	return cfg.Active.Allowed && cfg.Active.Authorized && cfg.Active.TargetURL != "" && !cfg.Offline
}

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request, res execx.Resolution) ([]finding.Finding, error) {
	outDir := filepath.Join(req.WorkDir, "zap")
	if err := os.MkdirAll(outDir, 0o777); err != nil { //nolint:gosec // container user must write here
		return nil, err
	}
	_ = os.Chmod(outDir, 0o777) //nolint:gosec // ZAP container runs as a non-root user
	mins := max(1, req.Config.Active.MaxMinutes)
	t := *s.Tool()
	if req.Config.Active.ZAPImage != "" {
		res.Image = req.Config.Active.ZAPImage
	}
	// zap-baseline.py writes reports to /zap/wrk, which must be a mount.
	args := []string{"zap-baseline.py", "-t", req.Config.Active.TargetURL, "-J", "zap.json", "-m", strconv.Itoa(mins), "-I"}
	_, err := req.Exec.Run(ctx, t, res, execx.Spec{Args: args, OutDir: outDir, ContainerOut: "/zap/wrk", Network: true, AcceptExit: []int{1, 2}})
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(outDir, "zap.json")) //nolint:gosec // our work dir
	if err != nil {
		return nil, fmt.Errorf("zap report not found: %w", err)
	}
	return Parse(data)
}

// Report mirrors ZAP's traditional JSON report (all values are strings).
type Report struct {
	Site []struct {
		Name   string `json:"@name"`
		Alerts []struct {
			PluginID   string `json:"pluginid"`
			Alert      string `json:"alert"`
			RiskCode   string `json:"riskcode"`
			Confidence string `json:"confidence"`
			Desc       string `json:"desc"`
			Solution   string `json:"solution"`
			Reference  string `json:"reference"`
			CWEID      string `json:"cweid"`
			Instances  []struct {
				URI      string `json:"uri"`
				Method   string `json:"method"`
				Param    string `json:"param"`
				Evidence string `json:"evidence"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

var tagRe = regexp.MustCompile(`<[^>]+>`)

func clean(s string) string {
	return strings.TrimSpace(html.UnescapeString(tagRe.ReplaceAllString(s, " ")))
}

// Parse converts the ZAP report into findings (one per alert instance URL).
func Parse(data []byte) ([]finding.Finding, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse zap output: %w", err)
	}
	var out []finding.Finding
	for _, site := range r.Site {
		for _, a := range site.Alerts {
			sev := map[string]finding.Severity{"3": finding.SeverityHigh, "2": finding.SeverityMedium, "1": finding.SeverityLow, "0": finding.SeverityInfo}[a.RiskCode]
			conf := map[string]finding.Confidence{"4": finding.ConfidenceHigh, "3": finding.ConfidenceHigh, "2": finding.ConfidenceMedium, "1": finding.ConfidenceLow}[a.Confidence]
			var refs []string
			for _, l := range strings.Fields(clean(a.Reference)) {
				if strings.HasPrefix(l, "http") {
					refs = append(refs, l)
				}
			}
			insts := a.Instances
			if len(insts) == 0 {
				insts = append(insts, struct {
					URI      string `json:"uri"`
					Method   string `json:"method"`
					Param    string `json:"param"`
					Evidence string `json:"evidence"`
				}{URI: site.Name})
			}
			for _, in := range insts {
				f := finding.Finding{
					Kind: finding.KindPotentialRisk, Category: finding.CategoryDAST,
					Title: a.Alert, Description: clean(a.Desc), Remediation: clean(a.Solution),
					Severity: sev, Confidence: conf, RuleID: "zap-" + a.PluginID,
					Location: finding.Location{Resource: strings.TrimSpace(in.Method + " " + in.URI)},
					Evidence: in.Evidence, References: refs, Tools: []string{"zap-baseline"}, Tags: []string{"dast", "passive"},
				}
				if c := finding.NormalizeCWE(a.CWEID); c != "" && a.CWEID != "0" && a.CWEID != "-1" {
					f.CWE = []string{c}
				}
				out = append(out, f)
			}
		}
	}
	return out, nil
}
