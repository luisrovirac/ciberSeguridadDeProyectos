// Package kubelinter adapts StackRox kube-linter (Kubernetes manifests / Helm).
package kubelinter

import (
	"context"
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

// Scanner is the kube-linter adapter.
type Scanner struct{}

// New creates the adapter.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (*Scanner) Name() string { return "kube-linter" }

// Native implements scanners.Scanner.
func (*Scanner) Native() bool { return false }

// Tool implements scanners.Scanner.
func (*Scanner) Tool() *execx.Tool {
	return &execx.Tool{
		Name: "kube-linter", Binary: "kube-linter", Image: "stackrox/kube-linter:v0.8.3",
		Entrypoint: []string{"/kube-linter"}, VersionArgs: []string{"version"},
		InstallHint: "Install kube-linter: go install golang.stackrox.io/kube-linter/cmd/kube-linter@latest, or brew install kube-linter.",
	}
}

// Applicable when Kubernetes manifests or Helm charts exist.
func (*Scanner) Applicable(p *detector.Profile, _ *config.Config) bool {
	return len(p.K8s) > 0 || len(p.Helm) > 0
}

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request, res execx.Resolution) ([]finding.Finding, error) {
	args := []string{"lint", "--format", "json"}
	args = append(args, req.Config.Scanners.For("kube-linter").Args...)
	args = append(args, "{{src}}")
	out, err := req.Exec.Run(ctx, *s.Tool(), res, execx.Spec{Args: args, SrcDir: req.Root, AcceptExit: []int{1}})
	if err != nil {
		return nil, err
	}
	return Parse(out.Stdout, req.Root)
}

// Output mirrors kube-linter's JSON output.
type Output struct {
	Reports []struct {
		Diagnostic struct {
			Message string `json:"Message"`
		} `json:"Diagnostic"`
		Check       string `json:"Check"`
		Remediation string `json:"Remediation"`
		Object      struct {
			Metadata struct {
				FilePath string `json:"FilePath"`
			} `json:"Metadata"`
			K8sObject struct {
				Namespace        string `json:"Namespace"`
				Name             string `json:"Name"`
				GroupVersionKind struct {
					Kind string `json:"Kind"`
				} `json:"GroupVersionKind"`
			} `json:"K8sObject"`
		} `json:"Object"`
	} `json:"Reports"`
}

// Parse converts kube-linter JSON into findings. kube-linter reports no line
// numbers, so we locate the object's "name:" line in the file when possible.
func Parse(data []byte, root string) ([]finding.Finding, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	var o Output
	if err := json.Unmarshal([]byte(trimmed), &o); err != nil {
		return nil, fmt.Errorf("parse kube-linter output: %w", err)
	}
	var out []finding.Finding
	for _, r := range o.Reports {
		obj := r.Object.K8sObject.GroupVersionKind.Kind + "/" + r.Object.K8sObject.Name
		path := normalizer.RelPath(root, r.Object.Metadata.FilePath)
		out = append(out, finding.Finding{
			Kind: finding.KindPotentialRisk, Category: finding.CategoryIaC,
			Title: r.Check + ": " + obj, Description: r.Diagnostic.Message,
			Severity: Severity(r.Check), Confidence: finding.ConfidenceHigh,
			RuleID: r.Check, RuleFamily: Families[r.Check],
			Location:    finding.Location{Path: path, StartLine: findLine(root, path, r.Object.K8sObject.Name), Resource: obj},
			Remediation: r.Remediation,
			References:  []string{"https://docs.kubelinter.io/#/generated/checks?id=" + r.Check},
			Tools:       []string{"kube-linter"},
		})
	}
	return out, nil
}

func findLine(root, rel, name string) int {
	if rel == "" || name == "" {
		return 0
	}
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) //nolint:gosec // inside project
	if err != nil {
		return 0
	}
	for i, l := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(l)
		if t == "name: "+name || t == `name: "`+name+`"` {
			return i + 1
		}
	}
	return 0
}

// Severity assigns a severity to kube-linter checks (which have none).
func Severity(check string) finding.Severity {
	switch check {
	case "privileged-container", "host-network", "host-pid", "host-ipc", "docker-sock", "access-to-create-pods", "cluster-admin-role-binding", "sensitive-host-mounts", "privilege-escalation-container":
		return finding.SeverityHigh
	case "run-as-non-root", "env-var-secret", "read-secret-from-env-var", "writable-host-mount", "unsafe-sysctls", "drop-net-raw-capability":
		return finding.SeverityMedium
	case "no-read-only-root-fs", "unset-cpu-requirements", "unset-memory-requirements", "latest-tag":
		return finding.SeverityLow
	}
	return finding.SeverityLow
}

// Families maps kube-linter checks to cross-tool rule families.
var Families = map[string]string{
	"privileged-container":           "k8s.privileged-container",
	"privilege-escalation-container": "k8s.privilege-escalation",
	"run-as-non-root":                "k8s.run-as-root",
	"no-read-only-root-fs":           "k8s.writable-root-fs",
	"host-network":                   "k8s.host-namespace",
	"host-pid":                       "k8s.host-namespace",
	"host-ipc":                       "k8s.host-namespace",
	"unset-cpu-requirements":         "k8s.no-resource-limits",
	"unset-memory-requirements":      "k8s.no-resource-limits",
	"latest-tag":                     "k8s.unpinned-image",
	"docker-sock":                    "container.docker-socket",
}
