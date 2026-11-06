package native

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/detector"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/execx"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/fsutil"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/redact"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
)

// secretRule is a pattern-based secret detector. Several regexes are adapted
// from gitleaks' default configuration (MIT licensed, see docs/rules.md).
type secretRule struct {
	ID         string
	Title      string
	Re         *regexp.Regexp
	MinEntropy float64 // 0 disables the entropy check
	Severity   finding.Severity
	Confidence finding.Confidence
	Family     string
}

var secretRules = []secretRule{
	{"aws-access-key-id", "AWS access key ID", regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`), 3, finding.SeverityHigh, finding.ConfidenceHigh, "secret.aws-access-key"},
	{"github-pat", "GitHub personal access token", regexp.MustCompile(`\b(ghp_[0-9a-zA-Z]{36})\b`), 3, finding.SeverityHigh, finding.ConfidenceHigh, "secret.github-token"},
	{"github-fine-grained-pat", "GitHub fine-grained token", regexp.MustCompile(`\b(github_pat_\w{82})\b`), 3, finding.SeverityHigh, finding.ConfidenceHigh, "secret.github-token"},
	{"github-oauth-app-token", "GitHub OAuth/app token", regexp.MustCompile(`\b(gh[ousr]_[0-9a-zA-Z]{36})\b`), 3, finding.SeverityHigh, finding.ConfidenceHigh, "secret.github-token"},
	{"gitlab-pat", "GitLab personal access token", regexp.MustCompile(`\b(glpat-[\w-]{20})\b`), 3, finding.SeverityHigh, finding.ConfidenceHigh, "secret.gitlab-token"},
	{"private-key", "Private key", regexp.MustCompile(`(-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----)`), 0, finding.SeverityHigh, finding.ConfidenceHigh, "secret.private-key"},
	{"slack-token", "Slack token", regexp.MustCompile(`\b(xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z-]{10,})`), 3, finding.SeverityHigh, finding.ConfidenceHigh, "secret.slack-token"},
	{"slack-webhook", "Slack webhook URL", regexp.MustCompile(`(https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9+/]{43,56})`), 0, finding.SeverityMedium, finding.ConfidenceHigh, "secret.slack-webhook"},
	{"stripe-key", "Stripe API key", regexp.MustCompile(`\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})\b`), 2, finding.SeverityHigh, finding.ConfidenceHigh, "secret.stripe-key"},
	{"gcp-api-key", "Google API key", regexp.MustCompile(`\b(AIza[\w-]{35})(?:[` + "`" + `'"\s;]|$)`), 4, finding.SeverityHigh, finding.ConfidenceHigh, "secret.gcp-api-key"},
	{"openai-api-key", "OpenAI API key", regexp.MustCompile(`\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})`), 3, finding.SeverityHigh, finding.ConfidenceHigh, "secret.openai-key"},
	{"anthropic-api-key", "Anthropic API key", regexp.MustCompile(`\b(sk-ant-(?:api|admin)\d{2}-[\w-]{80,})`), 3, finding.SeverityHigh, finding.ConfidenceHigh, "secret.anthropic-key"},
	{"npm-token", "npm access token", regexp.MustCompile(`\b(npm_[a-zA-Z0-9]{36})\b`), 3, finding.SeverityHigh, finding.ConfidenceHigh, "secret.npm-token"},
	{"jwt", "JSON Web Token", regexp.MustCompile(`\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.(?:[a-zA-Z0-9/\\_-]{10,}={0,2})?)(?:[` + "`" + `'"\s;]|$)`), 3, finding.SeverityMedium, finding.ConfidenceMedium, "secret.jwt"},
	{"url-credentials", "Credentials embedded in URL", regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^\s:/@'"]{1,64}:([^\s:/@'"]{6,128})@[^\s'"]+`), 3, finding.SeverityHigh, finding.ConfidenceMedium, "secret.url-credentials"},
	// Generic keyword = value with an entropy gate. Heuristic, hence medium/low confidence.
	{"generic-secret", "Hard-coded secret (generic)", regexp.MustCompile(`(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[` + "`" + `'"\s=]{0,5}([\w.=+/-]{10,150})(?:[` + "`" + `'"\s;]|\\[nr]|$)`), 3.5, finding.SeverityMedium, finding.ConfidenceMedium, "secret.generic"},
}

// placeholderRe catches obvious non-secrets: examples, templates, variables.
var placeholderRe = regexp.MustCompile(`(?i)(example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxxx|<[^>]*>|\$\{|\{\{|%[sd]|process\.env|os\.getenv|os\.environ|getenv|\*\*\*\*|redacted|test[_-]?key|lorem|1234567890)`)

// skippedSecretFiles are noisy files where hashes look like secrets.
var skippedSecretFiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "go.sum": true,
	"poetry.lock": true, "pipfile.lock": true, "cargo.lock": true, "composer.lock": true,
	"gemfile.lock": true, "packages.lock.json": true, "uv.lock": true, "npm-shrinkwrap.json": true,
}

var skippedSecretExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".svg": true, ".pdf": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".zip": true, ".gz": true, ".jar": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".class": true, ".pyc": true, ".sum": true,
}

// Secrets is the native secret detector.
type Secrets struct{ base }

// NewSecrets creates the analyzer.
func NewSecrets() *Secrets { return &Secrets{base{"native-secrets"}} }

// Applicable always returns true: every project can leak secrets.
func (s *Secrets) Applicable(*detector.Profile, *config.Config) bool { return true }

// Scan implements scanners.Scanner.
func (s *Secrets) Scan(ctx context.Context, req *scanners.Request, _ execx.Resolution) ([]finding.Finding, error) {
	var out []finding.Finding
	err := eachFile(ctx, req, func(rel string) bool {
		b := base0(rel)
		return !skippedSecretFiles[b] && !skippedSecretExt[ext(rel)] && !strings.HasSuffix(b, ".min.js")
	}, func(rel string, data []byte) {
		out = append(out, ScanSecrets(rel, data)...)
	})
	return out, err
}

// ScanSecrets runs every secret rule over data. Exported for tests and the git history scanner.
func ScanSecrets(rel string, data []byte) []finding.Finding {
	var out []finding.Finding
	isTest := fsutil.IsTestPath(rel)
	isEnv := strings.HasPrefix(base0(rel), ".env")
	for i, line := range lines(data) {
		if len(line) > 4096 {
			line = line[:4096]
		}
		if strings.Contains(line, "secureprojects:ignore") || strings.Contains(line, "gitleaks:allow") {
			continue
		}
		matchedSpecific := false
		for _, r := range secretRules {
			if r.ID == "generic-secret" && matchedSpecific {
				continue
			}
			for _, m := range r.Re.FindAllStringSubmatch(line, -1) {
				secret := m[0]
				if len(m) > 1 && m[1] != "" {
					secret = m[1]
				}
				if r.MinEntropy > 0 && ShannonEntropy(secret) <= r.MinEntropy {
					continue
				}
				conf := r.Confidence
				tags := []string{"heuristic", "secret"}
				if placeholderRe.MatchString(secret) || (r.ID == "generic-secret" && placeholderRe.MatchString(m[0])) {
					if r.ID == "generic-secret" || r.ID == "url-credentials" {
						continue
					}
					conf = finding.ConfidenceLow
					tags = append(tags, "placeholder")
				}
				if r.ID == "generic-secret" && !looksLikeSecretValue(secret) {
					continue
				}
				if r.ID != "generic-secret" {
					matchedSpecific = true
				}
				sev := r.Severity
				if isTest {
					conf = lower(conf)
				}
				if isEnv && sev.Rank() < finding.SeverityHigh.Rank() {
					sev = finding.SeverityHigh
				}
				out = append(out, finding.Finding{
					Title:       r.Title + " in " + rel,
					Description: fmt.Sprintf("A value matching the %q pattern (entropy %.2f) was found. Secrets committed to source control must be considered compromised.", r.ID, ShannonEntropy(secret)),
					Kind:        finding.KindPotentialRisk,
					Category:    finding.CategorySecret,
					Severity:    sev,
					Confidence:  conf,
					RuleID:      "SP-SECRET-" + strings.ToUpper(r.ID),
					RuleFamily:  r.Family,
					Location:    finding.Location{Path: rel, StartLine: i + 1, EndLine: i + 1},
					CWE:         []string{"CWE-798"},
					Evidence:    snippet(redact.Value(line, secret)),
					Remediation: "Revoke and rotate the credential, remove it from the code and the Git history (git filter-repo / BFG), and load it from a secret manager or environment variable.",
					References:  []string{"https://cwe.mitre.org/data/definitions/798.html", "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"},
					Tags:        tags,
				})
			}
		}
	}
	return out
}

func looksLikeSecretValue(v string) bool {
	// Reject plain words, booleans, paths, and identifiers without digits.
	lv := strings.ToLower(v)
	switch lv {
	case "true", "false", "null", "none", "undefined":
		return false
	}
	hasDigit, hasLetter := false, false
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			hasLetter = true
		}
	}
	if !hasDigit || !hasLetter {
		return false
	}
	return !strings.Contains(v, "/") || strings.Count(v, "/") < 2
}

func lower(c finding.Confidence) finding.Confidence {
	switch c {
	case finding.ConfidenceHigh:
		return finding.ConfidenceMedium
	default:
		return finding.ConfidenceLow
	}
}

// ShannonEntropy returns the Shannon entropy (bits per symbol) of s,
// computed over bytes as gitleaks does.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
