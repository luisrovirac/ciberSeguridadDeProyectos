package scoring

import (
	"testing"

	"github.com/secureprojects/secureprojects/internal/finding"
)

func TestScoreOrdering(t *testing.T) {
	direct := true
	confirmed := finding.Finding{Kind: finding.KindVulnerability, Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh,
		CVSS: &finding.CVSS{Score: 9.8}, Package: &finding.Package{Direct: &direct, FixedVersions: []string{"1.0.1"}}}
	heuristic := finding.Finding{Kind: finding.KindPotentialRisk, Severity: finding.SeverityHigh, Confidence: finding.ConfidenceLow}
	inTests := finding.Finding{Kind: finding.KindPotentialRisk, Severity: finding.SeverityHigh, Confidence: finding.ConfidenceLow, Location: finding.Location{Path: "tests/x.py"}}
	for _, f := range []*finding.Finding{&confirmed, &heuristic, &inTests} {
		Score(f)
	}
	if confirmed.Priority != 100 {
		t.Errorf("capped at 100, got %v", confirmed.Priority)
	}
	if !(confirmed.Priority > heuristic.Priority && heuristic.Priority > inTests.Priority) {
		t.Errorf("ordering: %v %v %v", confirmed.Priority, heuristic.Priority, inTests.Priority)
	}
	if heuristic.Priority != 30 { // 7.5*10*0.5*0.8
		t.Errorf("heuristic priority = %v", heuristic.Priority)
	}
	unknown := finding.Finding{Kind: finding.KindVulnerability, Severity: finding.SeverityUnknown, Confidence: finding.ConfidenceHigh, CVSS: &finding.CVSS{Score: 5.3}}
	Score(&unknown)
	if unknown.Severity != finding.SeverityMedium {
		t.Errorf("severity should be derived from CVSS, got %s", unknown.Severity)
	}
	if Label(85) != "P1" || Label(10) != "P4" {
		t.Fatal("labels")
	}
}
