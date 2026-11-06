// Package iac adapts dedicated IaC scanners: Checkov and KICS.
package iac

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/secureprojects/secureprojects/internal/config"
	"github.com/secureprojects/secureprojects/internal/detector"
	"github.com/secureprojects/secureprojects/internal/execx"
	"github.com/secureprojects/secureprojects/internal/finding"
	"github.com/secureprojects/secureprojects/internal/normalizer"
	"github.com/secureprojects/secureprojects/internal/scanners"
)

// Checkov is the Checkov adapter.
type Checkov struct{}

// NewCheckov creates the adapter.
func NewCheckov() *Checkov { return &Checkov{} }

// Name implements scanners.Scanner.
func (*Checkov) Name() string { return "checkov" }

// Native implements scanners.Scanner.
func (*Checkov) Native() bool { return false }

// Tool implements scanners.Scanner.
func (*Checkov) Tool() *execx.Tool {
	return &execx.Tool{
		Name: "checkov", Binary: "checkov", Image: "bridgecrew/checkov:3.4.3",
		Entrypoint: []string{"checkov"}, VersionArgs: []string{"--version"},
		InstallHint: "Install Checkov: pip install checkov (or brew install checkov).",
	}
}

// Applicable when IaC or Dockerfiles exist.
func (*Checkov) Applicable(p *detector.Profile, _ *config.Config) bool {
	return p.HasIaC() || len(p.Dockerfile) > 0
}

// Scan implements scanners.Scanner. Network features are disabled:
// --skip-download avoids fetching guidelines, no API key means no upload.
func (c *Checkov) Scan(ctx context.Context, req *scanners.Request, res execx.Resolution) ([]finding.Finding, error) {
	args := []string{"-d", "{{src}}", "-o", "json", "--quiet", "--compact", "--skip-download",
		"--framework", "terraform,cloudformation,kubernetes,helm,dockerfile,arm,bicep",
		"--skip-results-upload"}
	args = append(args, req.Config.Scanners.For("checkov").Args...)
	out, err := req.Exec.Run(ctx, *c.Tool(), res, execx.Spec{
		Args: args, SrcDir: req.Root, AcceptExit: []int{1},
		Env: map[string]string{"CKV_SKIP_PACKAGE_UPDATE_CHECK": "true", "BC_SKIP_MAPPING": "TRUE", "CHECKOV_EXPERIMENTAL_TERRAFORM_MANAGED_MODULES": "false"},
	})
	if err != nil {
		return nil, err
	}
	return ParseCheckov(out.Stdout, req.Root)
}

type checkovReport struct {
	CheckType string `json:"check_type"`
	Results   struct {
		FailedChecks []struct {
			CheckID       string `json:"check_id"`
			CheckName     string `json:"check_name"`
			FilePath      string `json:"file_path"`
			FileLineRange []int  `json:"file_line_range"`
			Resource      string `json:"resource"`
			Severity      string `json:"severity"`
			Guideline     string `json:"guideline"`
		} `json:"failed_checks"`
	} `json:"results"`
}

// ParseCheckov handles checkov's single-object, list and summary-only shapes.
func ParseCheckov(data []byte, root string) ([]finding.Finding, error) {
	t := strings.TrimSpace(string(data))
	if t == "" {
		return nil, nil
	}
	var reports []checkovReport
	if strings.HasPrefix(t, "[") {
		if err := json.Unmarshal([]byte(t), &reports); err != nil {
			return nil, fmt.Errorf("parse checkov output: %w", err)
		}
	} else {
		var r checkovReport
		if err := json.Unmarshal([]byte(t), &r); err != nil {
			return nil, fmt.Errorf("parse checkov output: %w", err)
		}
		reports = []checkovReport{r}
	}
	var out []finding.Finding
	for _, r := range reports {
		for _, fc := range r.Results.FailedChecks {
			start, end := 0, 0
			if len(fc.FileLineRange) == 2 {
				start, end = fc.FileLineRange[0], fc.FileLineRange[1]
			}
			sev := finding.ParseSeverity(fc.Severity)
			if sev == finding.SeverityUnknown {
				// Checkov only exposes severities with a platform API key.
				sev = finding.SeverityMedium
			}
			cat := finding.CategoryIaC
			if r.CheckType == "dockerfile" {
				cat = finding.CategoryContainer
			}
			f := finding.Finding{
				Kind: finding.KindPotentialRisk, Category: cat,
				Title: fc.CheckName, Description: fc.CheckName + " (" + fc.CheckID + ")",
				Severity: sev, Confidence: finding.ConfidenceHigh, RuleID: fc.CheckID, RuleFamily: CheckovFamilies[fc.CheckID],
				Location: finding.Location{Path: normalizer.RelPath(root, strings.TrimPrefix(fc.FilePath, "/")), StartLine: start, EndLine: end, Resource: fc.Resource},
				Tools:    []string{"checkov"}, Tags: []string{"policy-check"},
			}
			if fc.Guideline != "" {
				f.References = []string{fc.Guideline}
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// CheckovFamilies maps Checkov IDs to cross-tool rule families.
var CheckovFamilies = map[string]string{
	"CKV_AWS_24": "iac.public-ingress", "CKV_AWS_25": "iac.public-ingress", "CKV_AWS_260": "iac.public-ingress", "CKV_AWS_277": "iac.public-ingress",
	"CKV_AWS_20": "iac.storage-public-acl", "CKV_AWS_57": "iac.storage-public-acl",
	"CKV_AWS_17": "iac.publicly-accessible",
	"CKV_AWS_3":  "iac.unencrypted-storage", "CKV_AWS_16": "iac.unencrypted-storage",
	"CKV_DOCKER_8": "dockerfile.root-user", "CKV_DOCKER_3": "dockerfile.root-user",
	"CKV_DOCKER_7": "dockerfile.unpinned-image", "CKV_DOCKER_4": "dockerfile.add-instead-of-copy",
	"CKV_DOCKER_2": "dockerfile.no-healthcheck", "CKV_DOCKER_1": "dockerfile.expose-ssh",
	"CKV_K8S_16": "k8s.privileged-container", "CKV_K8S_20": "k8s.privilege-escalation",
	"CKV_K8S_23": "k8s.run-as-root", "CKV_K8S_22": "k8s.writable-root-fs",
	"CKV_K8S_19": "k8s.host-namespace", "CKV_K8S_17": "k8s.host-namespace", "CKV_K8S_18": "k8s.host-namespace",
	"CKV_K8S_11": "k8s.no-resource-limits", "CKV_K8S_13": "k8s.no-resource-limits",
	"CKV_K8S_14": "k8s.unpinned-image",
}
