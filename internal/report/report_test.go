package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/secureprojects/secureprojects/internal/finding"
	"github.com/secureprojects/secureprojects/internal/scanners"
)

func testdata(p ...string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(append([]string{filepath.Dir(file), "..", "..", "testdata"}, p...)...)
}

func sample() *Report {
	direct := true
	fs := []finding.Finding{
		{ID: "1", Fingerprint: "aaa", Title: "CVE-2020-8203 in lodash@4.17.15: Prototype Pollution", Kind: finding.KindVulnerability, Category: finding.CategoryDependencyVuln,
			Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh, CVSS: &finding.CVSS{Version: "3.1", Score: 7.4, Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			Tools: []string{"native-osv", "trivy"}, RuleID: "GHSA-p6mc-m468-83gw", CVE: []string{"CVE-2020-8203"}, CWE: []string{"CWE-1321"},
			Location: finding.Location{Path: "package-lock.json", StartLine: 15}, Package: &finding.Package{Name: "lodash", Version: "4.17.15", Ecosystem: "npm", FixedVersions: []string{"4.17.19"}, Direct: &direct},
			References: []string{"https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw", "javascript:alert(1)"}, Remediation: "Upgrade lodash to 4.17.19.", Triage: finding.Triage{Status: finding.TriageOpen}, Priority: 93},
		{Fingerprint: "bbb", Title: "AWS access key ID in config.js <script>alert(1)</script>", Kind: finding.KindPotentialRisk, Category: finding.CategorySecret,
			Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh, Tools: []string{"native-secrets"}, RuleID: "SP-SECRET-AWS-ACCESS-KEY-ID",
			Location: finding.Location{Path: "src/my config.js", StartLine: 3}, Evidence: `awsAccessKeyId: "****REDACTED****",`, Triage: finding.Triage{Status: finding.TriageOpen}, Priority: 72},
		{Fingerprint: "ccc", Title: "No HEALTHCHECK", Kind: finding.KindPotentialRisk, Category: finding.CategoryContainer, Severity: finding.SeverityInfo, Confidence: finding.ConfidenceHigh,
			Tools: []string{"native-dockerfile"}, RuleID: "SP-DOCKER-NO-HEALTHCHECK", Location: finding.Location{Path: "Dockerfile", StartLine: 1},
			Triage: finding.Triage{Status: finding.TriageAccepted, Justification: "probes in k8s", Source: "ignore-file"}, Priority: 4},
		{Fingerprint: "ddd", Title: "Missing security header", Kind: finding.KindPotentialRisk, Category: finding.CategoryDAST, Severity: finding.SeverityLow, Confidence: finding.ConfidenceMedium,
			Tools: []string{"zap-baseline"}, RuleID: "zap-10038", Location: finding.Location{Resource: "GET https://staging.example.com/"}, Triage: finding.Triage{Status: finding.TriageOpen}},
	}
	ts := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	sum := Summarize(fs)
	sum.Gate = Gate{FailOn: "high", Failed: true, FailingCount: 2}
	return &Report{
		SchemaVersion: SchemaVersion,
		Tool:          ToolInfo{Name: "SecureProjects", Version: "1.2.3", URL: "https://example.com"},
		Scan: ScanInfo{StartedAt: ts, FinishedAt: ts.Add(2 * time.Second), DurationMs: 2000, Target: "fixture", TargetType: "local",
			Repository: "https://github.com/o/r", Commit: "0123456789abcdef", Offline: true, Safe: true,
			Scanners: []scanners.Status{{Name: "native-secrets", Native: true, Status: "ok", Findings: 1}, {Name: "trivy", Status: "skipped", Message: "not found", InstallHint: "install it"}}},
		Summary: sum, Findings: fs, Disclaimer: Disclaimer,
	}
}

func TestSummarize(t *testing.T) {
	s := sample().Summary
	if s.Total != 4 || s.Open != 3 || s.Suppressed != 1 || s.BySeverity["high"] != 2 || s.ByKind["vulnerability"] != 1 || s.ByTool["trivy"] != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestJSONStableAndGolden(t *testing.T) {
	a, err := MarshalJSON(sample())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := MarshalJSON(sample())
	if !bytes.Equal(a, b) {
		t.Fatal("JSON output is not deterministic")
	}
	golden := testdata("golden", "report.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		_ = os.MkdirAll(filepath.Dir(golden), 0o750)
		_ = os.WriteFile(golden, a, 0o600)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("missing golden file (run with UPDATE_GOLDEN=1): %v", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), a) {
		t.Fatal("JSON schema/output changed; if intentional bump SchemaVersion and run UPDATE_GOLDEN=1 go test ./internal/report")
	}
	var back Report
	if err := json.Unmarshal(a, &back); err != nil || back.SchemaVersion != SchemaVersion || len(back.Findings) != 4 {
		t.Fatal("round trip")
	}
}

func TestSARIFValidAgainstOfficialSchema(t *testing.T) {
	out, err := MarshalSARIF(sample())
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(testdata("sarif-schema-2.1.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	schemaDoc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("sarif.json", schemaDoc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("sarif.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("SARIF does not validate against the 2.1.0 schema: %v", err)
	}
	s := string(out)
	for _, want := range []string{`"version": "2.1.0"`, `"secureprojects/v1": "aaa"`, `"security-severity": "7.4"`, `"uriBaseId": "%SRCROOT%"`, `"uri": "src/my%20config.js"`, `"kind": "external"`, "[potential risk"} {
		if !strings.Contains(s, want) {
			t.Errorf("SARIF missing %s", want)
		}
	}
}

func TestHTMLSelfContainedAndEscaped(t *testing.T) {
	out, err := RenderHTML(sample())
	if err != nil {
		t.Fatal(err)
	}
	h := string(out)
	if strings.Contains(h, "<script>alert(1)</script>") {
		t.Fatal("title not escaped")
	}
	if strings.Contains(h, `href="javascript:`) {
		t.Fatal("javascript: URL rendered as link")
	}
	if strings.Contains(h, "src=\"http") || strings.Contains(h, "<link ") {
		t.Fatal("external resources referenced")
	}
	for _, want := range []string{"Content-Security-Policy", "'sha256-", "CONFIRMED", "POTENTIAL", "CVE-2020-8203", "0123456789abcdef", "1.2.3", "Upgrade lodash to 4.17.19."} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

func TestTable(t *testing.T) {
	var buf bytes.Buffer
	WriteTable(&buf, sample(), false, 10)
	s := buf.String()
	for _, want := range []string{"Summary", "Confirmed vulnerabilities: 1", "CI gate: FAILED", "CONFIRMED", "potential", "install it"} {
		if !strings.Contains(s, want) {
			t.Errorf("table missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "No HEALTHCHECK") {
		t.Error("suppressed findings must not be listed in the table")
	}
}
