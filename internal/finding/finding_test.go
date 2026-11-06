package finding

import "testing"

func TestCanonicalVulnID(t *testing.T) {
	cases := []struct {
		ids  []string
		want string
	}{
		{[]string{"GHSA-p6mc-m468-83gw", "CVE-2020-8203"}, "CVE-2020-8203"},
		{[]string{"GO-2022-1059", "GHSA-69ch-w2m2-3vjp"}, "GHSA-69ch-w2m2-3vjp"},
		{[]string{"PYSEC-2020-96", "MAL-2024-1"}, "MAL-2024-1"},
		{[]string{"cve-2021-1", "CVE-2020-1000"}, "CVE-2020-1000"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := CanonicalVulnID(c.ids...); got != c.want {
			t.Errorf("CanonicalVulnID(%v) = %q, want %q", c.ids, got, c.want)
		}
	}
}

func TestNormalizeCWE(t *testing.T) {
	for in, want := range map[string]string{"CWE-79: XSS": "CWE-79", "79": "CWE-79", "cwe89": "CWE-89", "nope": ""} {
		if got := NormalizeCWE(in); got != want {
			t.Errorf("NormalizeCWE(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFingerprintIgnoresLineAndToolSpecificIDs(t *testing.T) {
	a := Finding{Category: CategoryDependencyVuln, RuleID: "GHSA-p6mc-m468-83gw", CVE: []string{"CVE-2020-8203"},
		Package: &Package{Name: "lodash", Version: "4.17.15", Ecosystem: "npm"}, Location: Location{Path: "package-lock.json", StartLine: 10}}
	b := Finding{Category: CategoryDependencyVuln, RuleID: "CVE-2020-8203", CVE: []string{"CVE-2020-8203"},
		Package: &Package{Name: "lodash", Version: "4.17.15", Ecosystem: "npm"}, Location: Location{Path: "package-lock.json", StartLine: 99}}
	if a.ComputeFingerprint() != b.ComputeFingerprint() {
		t.Fatal("same CVE on same package version must have the same fingerprint")
	}
	c := Finding{Category: CategorySecret, RuleFamily: "secret.aws-access-key", Location: Location{Path: "a.js", StartLine: 1}, Evidence: "x = ****"}
	d := c
	d.Location.StartLine = 50
	if c.ComputeFingerprint() != d.ComputeFingerprint() {
		t.Fatal("moving code must not change the fingerprint")
	}
}

func TestSeverityParsing(t *testing.T) {
	for in, want := range map[string]Severity{"CRITICAL": SeverityCritical, "moderate": SeverityMedium, "ERROR": SeverityHigh, "note": SeverityLow, "???": SeverityUnknown} {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q)=%q want %q", in, got, want)
		}
	}
	if SeverityFromScore(9.8) != SeverityCritical || SeverityFromScore(7.0) != SeverityHigh || SeverityFromScore(5.3) != SeverityMedium || SeverityFromScore(0.1) != SeverityLow {
		t.Fatal("SeverityFromScore thresholds")
	}
}

func TestValidate(t *testing.T) {
	f := Finding{Title: "x", Kind: KindPotentialRisk, Tools: []string{"t"}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	f.Kind = "maybe"
	if f.Validate() == nil {
		t.Fatal("invalid kind accepted")
	}
}
