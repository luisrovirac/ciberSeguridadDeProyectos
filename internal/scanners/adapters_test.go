package scanners_test

// Parser tests run against REAL outputs recorded from the pinned tool
// versions (see testdata/tool-outputs/README.md for the exact commands).

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/secureprojects/secureprojects/internal/finding"
	"github.com/secureprojects/secureprojects/internal/scanners/gitleaks"
	"github.com/secureprojects/secureprojects/internal/scanners/hadolint"
	"github.com/secureprojects/secureprojects/internal/scanners/iac"
	"github.com/secureprojects/secureprojects/internal/scanners/kubelinter"
	"github.com/secureprojects/secureprojects/internal/scanners/osv"
	"github.com/secureprojects/secureprojects/internal/scanners/semgrep"
	"github.com/secureprojects/secureprojects/internal/scanners/trivy"
)

func output(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "tool-outputs", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hasCVE(fs []finding.Finding, cve string) *finding.Finding {
	for i := range fs {
		if slices.Contains(fs[i].CVE, cve) {
			return &fs[i]
		}
	}
	return nil
}

func TestTrivyParser(t *testing.T) {
	fs, err := trivy.Parse(output(t, "trivy-node-app.json"), "/src")
	if err != nil {
		t.Fatal(err)
	}
	f := hasCVE(fs, "CVE-2020-8203")
	if f == nil {
		t.Fatal("CVE-2020-8203 missing")
	}
	if f.Kind != finding.KindVulnerability || f.Package.Name != "lodash" || f.Package.Version != "4.17.15" || f.Package.Ecosystem != "npm" || f.Location.Path != "package-lock.json" {
		t.Errorf("%+v %+v", f, f.Package)
	}
	if f.CVSS == nil || f.CVSS.Score == 0 || len(f.Package.FixedVersions) == 0 {
		t.Errorf("CVSS/fix missing: %+v", f)
	}
	var fams, secrets []string
	for _, x := range fs {
		if x.RuleFamily != "" {
			fams = append(fams, x.RuleFamily)
		}
		if x.Category == finding.CategorySecret {
			secrets = append(secrets, x.Evidence)
			if x.Kind != finding.KindPotentialRisk {
				t.Error("secret must be potential risk")
			}
		}
	}
	for _, want := range []string{"dockerfile.root-user", "dockerfile.unpinned-image", "dockerfile.no-healthcheck", "secret.aws-access-key"} {
		if !slices.Contains(fams, want) {
			t.Errorf("family %s missing in %v", want, fams)
		}
	}
	if len(secrets) != 1 || !strings.Contains(secrets[0], "****") {
		t.Errorf("trivy secret must arrive masked: %v", secrets)
	}
}

func TestOSVScannerParser(t *testing.T) {
	fs, err := osv.Parse(output(t, "osv-scanner-node-app.json"), "/src")
	if err != nil {
		t.Fatal(err)
	}
	f := hasCVE(fs, "CVE-2020-8203")
	if f == nil {
		t.Fatalf("CVE-2020-8203 missing (%d findings)", len(fs))
	}
	if !slices.Contains(f.Aliases, "GHSA-p6mc-m468-83gw") || f.Severity == finding.SeverityUnknown || !slices.Contains(f.Package.FixedVersions, "4.17.19") {
		t.Errorf("%+v", f)
	}
	if f.RuleID != "CVE-2020-8203" || !strings.HasPrefix(f.Title, "CVE-2020-8203 in lodash@4.17.15") {
		t.Errorf("canonical id: %s / %s", f.RuleID, f.Title)
	}
}

func TestGitleaksParser(t *testing.T) {
	fs, err := gitleaks.Parse(output(t, "gitleaks-python-app.json"), "/src", false)
	if err != nil {
		t.Fatal(err)
	}
	var fams []string
	for _, f := range fs {
		fams = append(fams, f.RuleFamily)
		if f.Kind != finding.KindPotentialRisk || f.Category != finding.CategorySecret {
			t.Errorf("%+v", f)
		}
		if strings.Contains(f.Location.Path, "/src") {
			t.Errorf("container path leaked: %s", f.Location.Path)
		}
	}
	for _, want := range []string{"secret.github-token", "secret.stripe-key"} {
		if !slices.Contains(fams, want) {
			t.Errorf("missing %s in %v", want, fams)
		}
	}
	if fs, err := gitleaks.Parse([]byte("[]"), "/src", false); err != nil || len(fs) != 0 {
		t.Fatal("empty report")
	}
	hist, _ := gitleaks.Parse(output(t, "gitleaks-python-app.json"), "/src", true)
	if !slices.Contains(hist[0].Tags, "git-history") {
		t.Fatal("history findings must be tagged")
	}
}

func TestSemgrepParser(t *testing.T) {
	fs, err := semgrep.Parse(output(t, "semgrep-python-app.json"), "/src")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 {
		t.Fatalf("want 3 findings, got %d", len(fs))
	}
	for _, f := range fs {
		if !strings.HasPrefix(f.RuleID, "secureprojects.") || len(f.CWE) == 0 || f.RuleFamily == "" || f.Evidence != "" {
			t.Errorf("%+v", f)
		}
		if f.Location.Path != "app.py" {
			t.Errorf("path %q", f.Location.Path)
		}
	}
}

func TestHadolintParser(t *testing.T) {
	fs, err := hadolint.Parse(output(t, "hadolint-node-app.json"), "/src")
	if err != nil {
		t.Fatal(err)
	}
	var codes []string
	for _, f := range fs {
		codes = append(codes, f.RuleID)
		if f.Location.Path != "Dockerfile" || f.Location.StartLine == 0 {
			t.Errorf("%+v", f.Location)
		}
	}
	if !slices.Contains(codes, "DL3007") {
		t.Errorf("DL3007 (latest tag) expected: %v", codes)
	}
}

func TestKubeLinterParser(t *testing.T) {
	fs, err := kubelinter.Parse(output(t, "kube-linter-go-app.json"), "/src")
	if err != nil {
		t.Fatal(err)
	}
	var fams []string
	for _, f := range fs {
		fams = append(fams, f.RuleFamily)
		if f.Location.Path != "deploy/deployment.yaml" || f.Location.Resource != "Deployment/goapp" {
			t.Errorf("%+v", f.Location)
		}
	}
	for _, want := range []string{"k8s.privileged-container", "k8s.host-namespace", "k8s.unpinned-image"} {
		if !slices.Contains(fams, want) {
			t.Errorf("missing %s in %v", want, fams)
		}
	}
}

func TestCheckovParser(t *testing.T) {
	fs, err := iac.ParseCheckov(output(t, "checkov-iac.json"), "/src")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.RuleID)
		if f.Location.Path == "" || strings.HasPrefix(f.Location.Path, "/") {
			t.Errorf("bad path %q", f.Location.Path)
		}
	}
	for _, want := range []string{"CKV_AWS_24", "CKV_AWS_20"} { // SSH open to 0.0.0.0/0, public-read ACL
		if !slices.Contains(ids, want) {
			t.Errorf("missing %s in %v", want, ids)
		}
	}
	if fs, err := iac.ParseCheckov([]byte(`[{"check_type":"terraform","results":{"failed_checks":[]}}]`), "/src"); err != nil || len(fs) != 0 {
		t.Fatal("list form")
	}
}
