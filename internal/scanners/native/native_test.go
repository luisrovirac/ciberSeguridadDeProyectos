package native

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/secureprojects/secureprojects/internal/config"
	"github.com/secureprojects/secureprojects/internal/detector"
	"github.com/secureprojects/secureprojects/internal/execx"
	"github.com/secureprojects/secureprojects/internal/finding"
	"github.com/secureprojects/secureprojects/internal/scanners"
	"github.com/secureprojects/secureprojects/internal/vulndb"
)

func fixture(parts ...string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(append([]string{filepath.Dir(file), "..", "..", "..", "testdata"}, parts...)...)
}

func request(t *testing.T, app string) *scanners.Request {
	t.Helper()
	cfg := config.Default()
	root := fixture("fixtures", app)
	p, err := detector.Detect(root, cfg.Exclude, cfg.Limits.MaxFiles)
	if err != nil {
		t.Fatal(err)
	}
	req := &scanners.Request{Root: p.Root, Profile: p, Config: &cfg, Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}
	if err := scanners.ListFiles(req); err != nil {
		t.Fatal(err)
	}
	return req
}

func run(t *testing.T, s scanners.Scanner, req *scanners.Request) []finding.Finding {
	t.Helper()
	if !s.Applicable(req.Profile, req.Config) {
		t.Fatalf("%s not applicable", s.Name())
	}
	fs, err := s.Scan(context.Background(), req, execx.Resolution{})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func rules(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func fakeSecrets(t *testing.T) []string {
	b, err := os.ReadFile(fixture("fixture-secrets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if !strings.HasPrefix(l, "#") {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

func TestSecretsDetectedAndRedacted(t *testing.T) {
	for _, app := range []string{"node-app", "python-app"} {
		fs := run(t, NewSecrets(), request(t, app))
		if len(fs) == 0 {
			t.Fatalf("%s: no secrets found", app)
		}
		for _, f := range fs {
			if f.Kind != finding.KindPotentialRisk || f.Category != finding.CategorySecret {
				t.Errorf("secret must be a potential risk: %+v", f)
			}
			for _, s := range fakeSecrets(t) {
				if strings.Contains(f.Evidence, s) || strings.Contains(f.Title, s) || strings.Contains(f.Description, s) {
					t.Errorf("secret %q leaked in finding %+v", s, f)
				}
			}
		}
	}
	got := rules(run(t, NewSecrets(), request(t, "python-app")))
	for _, want := range []string{"SP-SECRET-GITHUB-PAT", "SP-SECRET-STRIPE-KEY"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
}

func TestSecretsPlaceholdersAndEntropy(t *testing.T) {
	fs := ScanSecrets("a.py", []byte("aws = \"AKIAIOSFODNN7EXAMPLE\"\npassword = \"changeme\"\napi_key = os.getenv(\"API_KEY\")\ntoken = \"aaaaaaaaaaaaaaaaaaaa\"\n"))
	if len(fs) != 1 {
		t.Fatalf("want only the AWS example key, got %v", rules(fs))
	}
	if fs[0].Confidence != finding.ConfidenceLow || !slices.Contains(fs[0].Tags, "placeholder") {
		t.Fatalf("documented example key must be low confidence placeholder: %+v", fs[0])
	}
	if ShannonEntropy("aaaa") != 0 || ShannonEntropy("ab") != 1 {
		t.Fatal("entropy")
	}
}

func TestDockerfile(t *testing.T) {
	got := rules(run(t, NewDockerfile(), request(t, "node-app")))
	for _, want := range []string{"SP-DOCKER-ROOT-USER", "SP-DOCKER-LATEST-TAG", "SP-DOCKER-CURL-PIPE-SH"} {
		if !slices.Contains(got, want) {
			t.Errorf("node-app: missing %s in %v", want, got)
		}
	}
	got = rules(run(t, NewDockerfile(), request(t, "python-app")))
	for _, want := range []string{"SP-DOCKER-ROOT-USER", "SP-DOCKER-SECRET-IN-ENV"} {
		if !slices.Contains(got, want) {
			t.Errorf("python-app: missing %s in %v", want, got)
		}
	}
	// go-app's Dockerfile is hardened: multi-stage, distroless, USER nonroot.
	if got := rules(run(t, NewDockerfile(), request(t, "go-app"))); len(got) != 0 {
		t.Errorf("hardened Dockerfile flagged: %v", got)
	}
}

func TestParseDockerfileContinuations(t *testing.T) {
	ins := ParseDockerfile([]byte("FROM alpine:3.20\n# c\nRUN apk add \\\n    curl \\\n  && echo ok\nUSER 1000\n"))
	if len(ins) != 3 || ins[1].Cmd != "RUN" || ins[1].Line != 3 || !strings.Contains(ins[1].Args, "echo ok") {
		t.Fatalf("%+v", ins)
	}
}

func TestIaC(t *testing.T) {
	got := rules(run(t, NewIaC(), request(t, "iac")))
	for _, want := range []string{"SP-IAC-OPEN-INGRESS", "SP-IAC-PUBLIC-ACL", "SP-IAC-PUBLIC-DB", "SP-IAC-UNENCRYPTED", "SP-COMPOSE-PRIVILEGED", "SP-COMPOSE-DOCKER-SOCKET"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	// egress 0.0.0.0/0 is normal and must not be flagged
	n := 0
	for _, r := range got {
		if r == "SP-IAC-OPEN-INGRESS" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected exactly one open ingress (egress ignored), got %d", n)
	}
	k8s := rules(run(t, NewIaC(), request(t, "go-app")))
	for _, want := range []string{"SP-K8S-PRIVILEGED", "SP-K8S-HOST-NAMESPACE", "SP-K8S-LATEST-TAG", "SP-K8S-RUN-AS-ROOT"} {
		if !slices.Contains(k8s, want) {
			t.Errorf("missing %s in %v", want, k8s)
		}
	}
}

func TestDangerous(t *testing.T) {
	cases := map[string][]string{
		"node-app":   {"SP-JS-EVAL", "SP-JS-CHILD-EXEC"},
		"python-app": {"SP-PY-SHELL-TRUE", "SP-PY-YAML-LOAD", "SP-PY-PICKLE", "SP-PY-DEBUG"},
		"go-app":     {"SP-GO-TLS-SKIP-VERIFY", "SP-GO-SHELL-EXEC"},
	}
	for app, want := range cases {
		got := rules(run(t, NewDangerous(), request(t, app)))
		for _, w := range want {
			if !slices.Contains(got, w) {
				t.Errorf("%s: missing %s in %v", app, w, got)
			}
		}
	}
	// safe variants are not flagged
	if fs := applyOnText(t, "a.py", "yaml.load(x, Loader=yaml.SafeLoader)\nast.literal_eval(x)\n"); len(fs) != 0 {
		t.Errorf("false positives: %v", rules(fs))
	}
}

func applyOnText(t *testing.T, name, content string) []finding.Finding {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	req := &scanners.Request{Root: dir, Config: &cfg, Files: []string{name}}
	fs, err := applyPatternRules(context.Background(), req, dangerousRules, finding.CategorySAST, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestDeps(t *testing.T) {
	got := rules(run(t, NewDepsRisk(), request(t, "node-app")))
	if !slices.Contains(got, "SP-DEPS-NPM-WILDCARD") {
		t.Errorf("express '*' not flagged: %v", got)
	}
	got = rules(run(t, NewDepsRisk(), request(t, "python-app")))
	if len(got) != 1 || got[0] != "SP-DEPS-PY-UNPINNED" {
		t.Errorf("only flask is unpinned: %v", got)
	}
}

func TestCustomRules(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.yaml")
	_ = os.WriteFile(p, []byte("rules:\n  - id: ORG-TODO-SEC\n    title: Security TODO\n    pattern: 'TODO\\(security\\)'\n    extensions: [.go]\n    severity: low\n    message: unresolved security TODO\n"), 0o600)
	rs, err := LoadCustomRules(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "x.go"), []byte("package x\n// TODO(security): validate input\n"), 0o600)
	cfg := config.Default()
	req := &scanners.Request{Root: dir, Config: &cfg, Files: []string{"x.go"}}
	fs, err := NewCustom(rs).Scan(context.Background(), req, execx.Resolution{})
	if err != nil || len(fs) != 1 || fs[0].Location.StartLine != 2 || fs[0].Confidence != finding.ConfidenceLow {
		t.Fatalf("%v %+v", err, fs)
	}
	_ = os.WriteFile(p, []byte("rules:\n  - id: X\n    title: x\n    pattern: '('\n    severity: low\n"), 0o600)
	if _, err := LoadCustomRules(p); err == nil {
		t.Fatal("invalid regex accepted")
	}
}

func TestOSVMatcherWithRealRecords(t *testing.T) {
	idx := map[string]*vulndb.Index{}
	for _, eco := range []string{"npm", "PyPI", "Go"} {
		ix, err := vulndb.BuildFromDir(fixture("osv", eco), eco)
		if err != nil {
			t.Fatal(err)
		}
		idx[eco] = ix
	}
	m := &OSVMatcher{base: base{"native-osv"}, Indexes: idx}
	want := map[string]string{"node-app": "CVE-2020-8203", "python-app": "CVE-2020-14343", "go-app": "CVE-2022-32149"}
	for app, cve := range want {
		fs := run(t, m, request(t, app))
		found := false
		for _, f := range fs {
			if f.Kind != finding.KindVulnerability {
				t.Errorf("OSV match must be kind=vulnerability")
			}
			if slices.Contains(f.CVE, cve) {
				found = true
				if f.Package == nil || len(f.Package.FixedVersions) == 0 || f.Location.Path == "" {
					t.Errorf("incomplete finding: %+v", f)
				}
			}
		}
		if !found {
			t.Errorf("%s: %s not found in %v", app, cve, rules(fs))
		}
	}
	// No index for the ecosystem -> skipped, not "0 vulnerabilities".
	empty := &OSVMatcher{base: base{"native-osv"}, DBDir: t.TempDir()}
	_, err := empty.Scan(context.Background(), request(t, "node-app"), execx.Resolution{})
	var skip *scanners.SkipError
	if err == nil || !errorsAs(err, &skip) {
		t.Fatalf("expected SkipError, got %v", err)
	}
}
