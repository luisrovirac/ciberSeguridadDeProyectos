package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/report"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/vulndb"
)

func testdata(p ...string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(append([]string{filepath.Dir(file), "..", "..", "testdata"}, p...)...)
}

// testConfig builds a config whose OSV DB contains the real records from
// testdata/osv and where every external tool is guaranteed to be missing,
// so the test behaves the same on every machine.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	db := t.TempDir()
	for _, eco := range []string{"npm", "PyPI", "Go"} {
		ix, err := vulndb.BuildFromDir(testdata("osv", eco), eco)
		if err != nil {
			t.Fatal(err)
		}
		if err := ix.Save(db); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.VulnDB.Dir = db
	cfg.Cache.Enabled = false
	cfg.Output = t.TempDir()
	cfg.Formats = []string{"json", "sarif", "html"}
	cfg.Scanners.Runner = config.RunnerLocal
	cfg.Scanners.Settings = map[string]config.ScannerConfig{}
	for _, n := range []string{"trivy", "osv-scanner", "gitleaks", "semgrep", "hadolint", "kube-linter", "checkov", "kics", "bandit"} {
		cfg.Scanners.Settings[n] = config.ScannerConfig{Path: "secureprojects-test-missing-" + n}
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return &cfg
}

func secrets(t *testing.T) []string {
	b, _ := os.ReadFile(testdata("fixture-secrets.txt"))
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func TestEndToEndFixtures(t *testing.T) {
	type expect struct {
		cve   string
		rules []string
	}
	cases := map[string]expect{
		"node-app":   {"CVE-2020-8203", []string{"SP-SECRET-AWS-ACCESS-KEY-ID", "SP-DOCKER-ROOT-USER", "SP-JS-EVAL"}},
		"python-app": {"CVE-2020-14343", []string{"SP-SECRET-GITHUB-PAT", "SP-DOCKER-ROOT-USER", "SP-PY-YAML-LOAD"}},
		"go-app":     {"CVE-2022-32149", []string{"SP-K8S-PRIVILEGED", "SP-GO-TLS-SKIP-VERIFY"}},
		"iac":        {"", []string{"SP-IAC-OPEN-INGRESS", "SP-IAC-PUBLIC-ACL"}},
	}
	for app, want := range cases {
		t.Run(app, func(t *testing.T) {
			cfg := testConfig(t)
			rep, err := Scan(context.Background(), cfg, Options{Target: testdata("fixtures", app)})
			if err != nil {
				t.Fatal(err)
			}
			// missing tools are skipped with install hints, never fatal
			for _, s := range rep.Scan.Scanners {
				if !s.Native && s.Status != scanners.StatusSkipped && s.Status != scanners.StatusNotApplicable && s.Status != scanners.StatusDisabled {
					t.Errorf("external %s status %s", s.Name, s.Status)
				}
				if s.Status == scanners.StatusSkipped && !s.Native && s.InstallHint == "" {
					t.Errorf("%s skipped without install hint", s.Name)
				}
				if s.Native && s.Status == scanners.StatusError {
					t.Errorf("native %s failed: %s", s.Name, s.Message)
				}
			}
			var rules []string
			found := want.cve == ""
			for _, f := range rep.Findings {
				rules = append(rules, f.RuleID)
				if slices.Contains(f.CVE, want.cve) {
					found = true
					if f.Kind != finding.KindVulnerability {
						t.Error("CVE must be kind=vulnerability")
					}
				}
				if f.Category == finding.CategorySecret && f.Kind != finding.KindPotentialRisk {
					t.Error("heuristic secret reported as confirmed")
				}
			}
			if !found {
				t.Errorf("%s not found", want.cve)
			}
			for _, r := range want.rules {
				if !slices.Contains(rules, r) {
					t.Errorf("rule %s missing in %v", r, rules)
				}
			}
			if !rep.Summary.Gate.Failed {
				t.Error("fixtures have high findings: gate must fail")
			}

			written, err := WriteOutputs(rep, cfg, os.Stdout)
			if err != nil || len(written) != 3 {
				t.Fatalf("%v %v", err, written)
			}
			for _, p := range written {
				b, _ := os.ReadFile(p)
				for _, s := range secrets(t) {
					if strings.Contains(string(b), s) {
						t.Errorf("secret %q leaked in %s", s, filepath.Base(p))
					}
				}
				if strings.Contains(string(b), "Sup3rS3cretPassw0rd") {
					t.Errorf("Dockerfile ENV password leaked in %s", filepath.Base(p))
				}
			}
		})
	}
}

func TestBaselineDiff(t *testing.T) {
	cfg := testConfig(t)
	target := testdata("fixtures", "node-app")
	first, err := Scan(context.Background(), cfg, Options{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "base.json")
	if err := report.WriteJSON(first, base); err != nil {
		t.Fatal(err)
	}
	cfg.Baseline, cfg.DiffOnly = base, true
	second, err := Scan(context.Background(), cfg, Options{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Findings) != 0 || second.Summary.Gate.Failed {
		t.Fatalf("nothing changed: diff must be empty, got %d", len(second.Findings))
	}
	// Identical runs produce identical findings (stable JSON apart from timestamps).
	a, _ := json.Marshal(first.Findings)
	cfg.Baseline, cfg.DiffOnly = "", false
	third, _ := Scan(context.Background(), cfg, Options{Target: target})
	b, _ := json.Marshal(third.Findings)
	if string(a) != string(b) {
		t.Fatal("findings are not deterministic across runs")
	}
}

func TestIgnoreFileAndFailOnNone(t *testing.T) {
	cfg := testConfig(t)
	dir := t.TempDir()
	ign := filepath.Join(dir, "ignore.yaml")
	_ = os.WriteFile(ign, []byte("ignores:\n  - rule: SP-DOCKER-ROOT-USER\n    reason: base image drops privileges at runtime\n    status: accepted\n"), 0o600)
	cfg.IgnoreFile = ign
	cfg.FailOn = "none"
	rep, err := Scan(context.Background(), cfg, Options{Target: testdata("fixtures", "node-app")})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Gate.Failed {
		t.Fatal("--fail-on none never fails")
	}
	for _, f := range rep.Findings {
		if f.RuleID == "SP-DOCKER-ROOT-USER" && f.Triage.Status != finding.TriageAccepted {
			t.Fatalf("ignore not applied: %+v", f.Triage)
		}
	}
	if rep.Summary.Suppressed == 0 {
		t.Fatal("suppressed count")
	}
}

func TestMissingOSVDatabaseWarns(t *testing.T) {
	cfg := testConfig(t)
	cfg.VulnDB.Dir = t.TempDir()
	rep, err := Scan(context.Background(), cfg, Options{Target: testdata("fixtures", "node-app")})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rep.Scan.Warnings, "\n")
	if !strings.Contains(joined, "dependency CVE scanning not available") {
		t.Fatalf("expected an explicit warning, got %q", joined)
	}
}

func TestInvalidTargetIsConfigError(t *testing.T) {
	cfg := testConfig(t)
	_, err := Scan(context.Background(), cfg, Options{Target: filepath.Join(t.TempDir(), "nope")})
	if !config.IsInvalid(err) {
		t.Fatalf("want config error, got %v", err)
	}
	_, err = Scan(context.Background(), cfg, Options{RepoURL: "ext::sh -c id"})
	if !config.IsInvalid(err) {
		t.Fatalf("dangerous repo URL must be rejected as config error, got %v", err)
	}
}
