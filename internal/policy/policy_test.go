package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
)

func TestIgnoreFileRequiresReason(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ignore.yaml")
	_ = os.WriteFile(p, []byte("ignores:\n  - rule: X\n"), 0o600)
	if _, err := LoadIgnoreFile(p); err == nil {
		t.Fatal("entry without reason accepted")
	}
	if r, err := LoadIgnoreFile(filepath.Join(dir, "missing.yaml")); err != nil || r != nil {
		t.Fatal("missing ignore file must be fine")
	}
}

func TestApplyIgnores(t *testing.T) {
	fs := []finding.Finding{
		{RuleID: "SP-DOCKER-NO-HEALTHCHECK", Location: finding.Location{Path: "deploy/Dockerfile"}, Triage: finding.Triage{Status: finding.TriageOpen}},
		{RuleID: "GHSA-x", CVE: []string{"CVE-2020-8203"}, Package: &finding.Package{Name: "lodash"}, Triage: finding.Triage{Status: finding.TriageOpen}},
		{RuleID: "Z", Fingerprint: "abc", Triage: finding.Triage{Status: finding.TriageOpen}},
	}
	rules := []IgnoreRule{
		{Rule: "SP-DOCKER-NO-HEALTHCHECK", Path: "deploy/**", Reason: "k8s probes", Status: "accepted"},
		{CVE: "CVE-2020-8203", Package: "lodash", Reason: "not reachable"},
		{Fingerprint: "abc", Reason: "old", Expires: "2020-01-01"},
	}
	expired := ApplyIgnores(fs, rules, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if expired != 1 {
		t.Fatalf("expired=%d", expired)
	}
	if fs[0].Triage.Status != finding.TriageAccepted || fs[1].Triage.Status != finding.TriageIgnored || fs[2].Triage.Status != finding.TriageOpen {
		t.Fatalf("%+v", fs)
	}
}

func TestGate(t *testing.T) {
	fs := []finding.Finding{
		{Kind: finding.KindPotentialRisk, Severity: finding.SeverityHigh, Confidence: finding.ConfidenceLow, Triage: finding.Triage{Status: finding.TriageOpen}},
		{Kind: finding.KindVulnerability, Severity: finding.SeverityMedium, Confidence: finding.ConfidenceHigh, Triage: finding.Triage{Status: finding.TriageOpen}},
		{Kind: finding.KindVulnerability, Severity: finding.SeverityCritical, Confidence: finding.ConfidenceHigh, Triage: finding.Triage{Status: finding.TriageIgnored}},
	}
	if n := len(Gate(fs, "high", finding.ConfidenceMedium)); n != 0 {
		t.Fatalf("low-confidence heuristics and suppressed findings must not gate, got %d", n)
	}
	if n := len(Gate(fs, "medium", finding.ConfidenceMedium)); n != 1 {
		t.Fatalf("medium gate: %d", n)
	}
	if n := len(Gate(fs, "low", "")); n != 2 {
		t.Fatalf("no confidence filter: %d", n)
	}
	if Gate(fs, "none", "") != nil {
		t.Fatal("none must never fail")
	}
}

func TestBaseline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "b.json")
	_ = os.WriteFile(p, []byte(`{"schemaVersion":"1.0.0","findings":[{"fingerprint":"old"}]}`), 0o600)
	set, err := LoadBaseline(p)
	if err != nil {
		t.Fatal(err)
	}
	fs := []finding.Finding{{Fingerprint: "old"}, {Fingerprint: "new"}}
	MarkNew(fs, set)
	if *fs[0].IsNew || !*fs[1].IsNew {
		t.Fatal("MarkNew")
	}
	if n := OnlyNew(fs); len(n) != 1 || n[0].Fingerprint != "new" {
		t.Fatal("OnlyNew")
	}
	_ = os.WriteFile(p, []byte(`{"runs":[]}`), 0o600)
	if _, err := LoadBaseline(p); err == nil {
		t.Fatal("non-SecureProjects file accepted as baseline")
	}
}

func TestKnownFalsePositives(t *testing.T) {
	fs := []finding.Finding{{Category: finding.CategorySecret, Tags: []string{"placeholder"}, Triage: finding.Triage{Status: finding.TriageOpen}}}
	MarkKnownFalsePositives(fs)
	if fs[0].Triage.Status != finding.TriageFalsePositive || fs[0].Triage.Justification == "" {
		t.Fatalf("%+v", fs[0].Triage)
	}
}
