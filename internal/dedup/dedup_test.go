package dedup

import (
	"slices"
	"testing"

	"github.com/secureprojects/secureprojects/internal/finding"
)

func fp(f finding.Finding) finding.Finding {
	f.Normalize()
	f.Fingerprint = f.ComputeFingerprint()
	return f
}

func TestMergeSameCVEAcrossTools(t *testing.T) {
	pkg := func() *finding.Package { return &finding.Package{Name: "lodash", Version: "4.17.15", Ecosystem: "npm"} }
	in := []finding.Finding{
		fp(finding.Finding{Title: "a", Kind: finding.KindVulnerability, Category: finding.CategoryDependencyVuln, Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh,
			RuleID: "GHSA-p6mc-m468-83gw", CVE: []string{"CVE-2020-8203"}, Aliases: []string{"GHSA-p6mc-m468-83gw"}, Package: pkg(), Tools: []string{"native-osv"}}),
		fp(finding.Finding{Title: "b", Kind: finding.KindVulnerability, Category: finding.CategoryDependencyVuln, Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh,
			RuleID: "CVE-2020-8203", CVE: []string{"CVE-2020-8203"}, Package: pkg(), Tools: []string{"trivy"},
			CVSS: &finding.CVSS{Version: "3.1", Score: 7.4, Source: "nvd"}}),
		// osv-scanner reports only the GHSA id (no CVE) - still the same vuln.
		fp(finding.Finding{Title: "c", Kind: finding.KindVulnerability, Category: finding.CategoryDependencyVuln, Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh,
			RuleID: "GHSA-p6mc-m468-83gw", Aliases: []string{"GHSA-p6mc-m468-83gw"}, Package: pkg(), Tools: []string{"osv-scanner"}}),
		// different vuln on the same package: must stay separate
		fp(finding.Finding{Title: "d", Kind: finding.KindVulnerability, Category: finding.CategoryDependencyVuln, Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh,
			RuleID: "CVE-2021-23337", CVE: []string{"CVE-2021-23337"}, Package: pkg(), Tools: []string{"trivy"}}),
	}
	out := Merge(in)
	if len(out) != 2 {
		t.Fatalf("want 2 findings, got %d", len(out))
	}
	var merged finding.Finding
	for _, f := range out {
		if slices.Contains(f.CVE, "CVE-2020-8203") {
			merged = f
		}
	}
	if !slices.Equal(merged.Tools, []string{"native-osv", "osv-scanner", "trivy"}) {
		t.Fatalf("tools = %v", merged.Tools)
	}
	if merged.CVSS == nil || merged.CVSS.Score != 7.4 {
		t.Fatal("CVSS must be kept from the richest source")
	}
	if merged.Fingerprint != in[0].Fingerprint {
		t.Fatal("merged fingerprint must prefer the native finding (stable identity)")
	}
	if out[0].GroupID != out[1].GroupID {
		t.Fatal("vulns on the same package must share a group")
	}
}

func TestMergeLocationFindings(t *testing.T) {
	in := []finding.Finding{
		fp(finding.Finding{Title: "root", Kind: finding.KindPotentialRisk, Category: finding.CategoryContainer, Severity: finding.SeverityHigh, Confidence: finding.ConfidenceMedium,
			RuleID: "SP-DOCKER-ROOT-USER", RuleFamily: "dockerfile.root-user", Location: finding.Location{Path: "Dockerfile", StartLine: 5}, Tools: []string{"native-dockerfile"}}),
		fp(finding.Finding{Title: "DL3002", Kind: finding.KindPotentialRisk, Category: finding.CategoryContainer, Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh,
			RuleID: "DL3002", RuleFamily: "dockerfile.root-user", Location: finding.Location{Path: "Dockerfile", StartLine: 5}, Tools: []string{"hadolint"}}),
		// same tool, adjacent lines, shared CWE: two different issues
		fp(finding.Finding{Title: "yaml", Kind: finding.KindPotentialRisk, Category: finding.CategorySAST, RuleID: "SP-PY-YAML-LOAD", CWE: []string{"CWE-502"}, Location: finding.Location{Path: "app.py", StartLine: 18}, Tools: []string{"native-sast"}}),
		fp(finding.Finding{Title: "pickle", Kind: finding.KindPotentialRisk, Category: finding.CategorySAST, RuleID: "SP-PY-PICKLE", CWE: []string{"CWE-502"}, Location: finding.Location{Path: "app.py", StartLine: 19}, Tools: []string{"native-sast"}}),
		// bandit agrees with the pickle finding through the CWE
		fp(finding.Finding{Title: "B301", Kind: finding.KindPotentialRisk, Category: finding.CategorySAST, RuleID: "B301", CWE: []string{"CWE-502"}, Location: finding.Location{Path: "app.py", StartLine: 19}, Tools: []string{"bandit"}, Confidence: finding.ConfidenceHigh}),
		// secrets on the same line from two tools
		fp(finding.Finding{Title: "aws", Kind: finding.KindPotentialRisk, Category: finding.CategorySecret, RuleFamily: "secret.aws-access-key", Location: finding.Location{Path: "c.js", StartLine: 3}, Tools: []string{"native-secrets"}}),
		fp(finding.Finding{Title: "aws gl", Kind: finding.KindPotentialRisk, Category: finding.CategorySecret, RuleFamily: "secret.aws-access-key", Location: finding.Location{Path: "c.js", StartLine: 3}, Tools: []string{"gitleaks"}}),
	}
	out := Merge(in)
	if len(out) != 4 {
		for _, f := range out {
			t.Logf("%s %v", f.Title, f.Tools)
		}
		t.Fatalf("want 4 findings (root, yaml, pickle+bandit, aws), got %d", len(out))
	}
	for _, f := range out {
		if f.Location.Path == "Dockerfile" {
			if len(f.Tools) != 2 || f.Confidence != finding.ConfidenceHigh || !slices.Contains(f.Tags, "corroborated") {
				t.Errorf("corroborated finding: %+v", f)
			}
		}
	}
}

func TestSortStable(t *testing.T) {
	fs := []finding.Finding{{Fingerprint: "b", Priority: 10}, {Fingerprint: "a", Priority: 10}, {Fingerprint: "c", Priority: 50}}
	Sort(fs)
	if fs[0].Fingerprint != "c" || fs[1].Fingerprint != "a" {
		t.Fatalf("%v", fs)
	}
}
