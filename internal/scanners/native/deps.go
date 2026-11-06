package native

import (
	"bytes"
	"context"
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/secureprojects/secureprojects/internal/config"
	"github.com/secureprojects/secureprojects/internal/detector"
	"github.com/secureprojects/secureprojects/internal/execx"
	"github.com/secureprojects/secureprojects/internal/finding"
	"github.com/secureprojects/secureprojects/internal/scanners"
)

// DepsRisk flags unpinned or loosely pinned dependencies. Determining whether
// a dependency is outdated requires querying a registry (network), which is
// intentionally not done; see LIMITATIONS.md.
type DepsRisk struct{ base }

// NewDepsRisk creates the analyzer.
func NewDepsRisk() *DepsRisk { return &DepsRisk{base{"native-deps"}} }

// Applicable when dependency manifests exist.
func (d *DepsRisk) Applicable(p *detector.Profile, _ *config.Config) bool { return p.HasManifests() }

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// Scan implements scanners.Scanner.
func (d *DepsRisk) Scan(ctx context.Context, req *scanners.Request, _ execx.Resolution) ([]finding.Finding, error) {
	fileSet := map[string]bool{}
	for _, f := range req.Files {
		fileSet[f] = true
	}
	var out []finding.Finding
	err := eachFile(ctx, req, func(rel string) bool {
		b := base0(rel)
		return b == "package.json" || b == "go.mod" || (strings.HasPrefix(b, "requirements") && strings.HasSuffix(b, ".txt")) || b == "gemfile"
	}, func(rel string, data []byte) {
		dir := path.Dir(rel)
		has := func(n string) bool {
			if dir == "." {
				return fileSet[n]
			}
			return fileSet[dir+"/"+n]
		}
		switch base0(rel) {
		case "package.json":
			locked := has("package-lock.json") || has("yarn.lock") || has("pnpm-lock.yaml") || has("npm-shrinkwrap.json")
			out = append(out, AnalyzePackageJSON(rel, data, locked)...)
		case "go.mod":
			out = append(out, AnalyzeGoMod(rel, data)...)
		case "gemfile":
			out = append(out, AnalyzeGemfile(rel, data, has("Gemfile.lock") || has("gemfile.lock"))...)
		default:
			out = append(out, AnalyzeRequirements(rel, data)...)
		}
	})
	return out, err
}

func depFinding(rel string, line int, id, title, desc, rem string, sev finding.Severity, eco, name, ver string) finding.Finding {
	return finding.Finding{
		Title: title, Description: desc, Kind: finding.KindPotentialRisk, Category: finding.CategoryDependencyRisk,
		Severity: sev, Confidence: finding.ConfidenceHigh, RuleID: id, RuleFamily: "deps.unpinned",
		Location: finding.Location{Path: rel, StartLine: line, EndLine: line},
		Package:  &finding.Package{Name: name, Version: ver, Ecosystem: eco},
		CWE:      []string{"CWE-1357"}, Evidence: snippet(name + " " + ver), Remediation: rem,
		Tags: []string{"heuristic", "supply-chain"},
	}
}

var npmLooseRe = regexp.MustCompile(`^\s*(\*|x|latest|next|>=?|<=?|\|\||[0-9]+\.x|[0-9]+$)|\s-\s|\|\|`)

// AnalyzePackageJSON flags wildcard, latest, git/URL and open ranges.
// Caret/tilde ranges are only reported (info) when no lockfile exists.
func AnalyzePackageJSON(rel string, data []byte, locked bool) []finding.Finding {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	ls := lines(data)
	lineOf := func(name string) int {
		needle := `"` + name + `"`
		for i, l := range ls {
			if strings.Contains(l, needle) {
				return i + 1
			}
		}
		return 0
	}
	var out []finding.Finding
	check := func(deps map[string]string, dev bool) {
		for name, spec := range deps {
			sev := finding.SeverityLow
			if dev {
				sev = finding.SeverityInfo
			}
			s := strings.TrimSpace(spec)
			switch {
			case strings.HasPrefix(s, "git") || strings.HasPrefix(s, "http") || strings.Contains(s, "github:") || (strings.Contains(s, "/") && !strings.HasPrefix(s, "npm:") && !strings.HasPrefix(s, "file:") && !strings.HasPrefix(s, "workspace:")):
				out = append(out, depFinding(rel, lineOf(name), "SP-DEPS-NPM-URL", "Dependency fetched from git/URL: "+name,
					"Dependencies from git or URLs bypass the registry and are not covered by vulnerability databases; a moving branch can change code silently.",
					"Depend on a published registry version, or pin the git dependency to a commit SHA.", sev, "npm", name, spec))
			case npmLooseRe.MatchString(s) || s == "":
				out = append(out, depFinding(rel, lineOf(name), "SP-DEPS-NPM-WILDCARD", "Unbounded version range for "+name,
					"The version spec accepts any (or any future major) version, so builds can pull untested or malicious releases.",
					"Pin an explicit version range (e.g. ^1.2.3) and commit a lockfile.", sev, "npm", name, spec))
			case !locked && (strings.HasPrefix(s, "^") || strings.HasPrefix(s, "~")):
				out = append(out, depFinding(rel, lineOf(name), "SP-DEPS-NPM-NO-LOCKFILE", "Floating range without lockfile: "+name,
					"Without a lockfile, each install may resolve a different version.",
					"Commit package-lock.json / yarn.lock / pnpm-lock.yaml and use 'npm ci'.", finding.SeverityInfo, "npm", name, spec))
			}
		}
	}
	check(pkg.Dependencies, false)
	check(pkg.DevDependencies, true)
	return out
}

var reqLineRe = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$`)

// AnalyzeRequirements flags requirements without an exact '==' pin.
func AnalyzeRequirements(rel string, data []byte) []finding.Finding {
	var out []finding.Finding
	for i, l := range lines(data) {
		t := strings.TrimSpace(l)
		if c := strings.Index(t, " #"); c >= 0 {
			t = strings.TrimSpace(t[:c])
		}
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") {
			continue
		}
		if strings.Contains(t, "://") || strings.HasPrefix(t, "git+") {
			out = append(out, depFinding(rel, i+1, "SP-DEPS-PY-URL", "Requirement installed from URL",
				"URL/VCS requirements bypass PyPI and vulnerability databases.",
				"Use a released PyPI version with '==' and hashes (--require-hashes).", finding.SeverityLow, "PyPI", t, ""))
			continue
		}
		m := reqLineRe.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		spec := strings.TrimSpace(strings.Split(m[3], ";")[0])
		if strings.HasPrefix(spec, "==") || strings.HasPrefix(spec, "===") {
			continue
		}
		title := "Unpinned Python requirement: " + m[1]
		if spec != "" {
			title = "Loosely pinned Python requirement: " + m[1] + " " + spec
		}
		out = append(out, depFinding(rel, i+1, "SP-DEPS-PY-UNPINNED", title,
			"Without an exact pin, installs resolve the newest matching release, which may be vulnerable, breaking or malicious.",
			"Pin with '==' (e.g. generated by pip-compile) and consider --require-hashes.", finding.SeverityLow, "PyPI", m[1], spec))
	}
	return out
}

var goReplaceLocalRe = regexp.MustCompile(`^\s*(?:replace\s+)?(\S+)(?:\s+\S+)?\s*=>\s*(\.{1,2}/\S*|/\S+)`)

// AnalyzeGoMod flags local replace directives (they hide the real dependency source).
func AnalyzeGoMod(rel string, data []byte) []finding.Finding {
	var out []finding.Finding
	inReplace := false
	for i, l := range lines(data) {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "replace (") {
			inReplace = true
			continue
		}
		if inReplace && t == ")" {
			inReplace = false
			continue
		}
		if !inReplace && !strings.HasPrefix(t, "replace ") {
			continue
		}
		if m := goReplaceLocalRe.FindStringSubmatch(t); m != nil {
			out = append(out, depFinding(rel, i+1, "SP-DEPS-GO-LOCAL-REPLACE", "go.mod replaces "+m[1]+" with a local path",
				"A local replace directive means the built code differs from the published module and is not covered by vulnerability databases.",
				"Remove local replace directives before releasing, or vendor the fork under a versioned module path.", finding.SeverityInfo, "Go", m[1], m[2]))
		}
	}
	return out
}

var gemLineRe = regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"]\s*(,\s*['"]([^'"]+)['"])?`)

// AnalyzeGemfile flags gems without a version constraint when there is no Gemfile.lock.
func AnalyzeGemfile(rel string, data []byte, locked bool) []finding.Finding {
	if locked {
		return nil
	}
	var out []finding.Finding
	for i, l := range lines(data) {
		m := gemLineRe.FindStringSubmatch(l)
		if m == nil || m[3] != "" {
			continue
		}
		out = append(out, depFinding(rel, i+1, "SP-DEPS-GEM-UNPINNED", "Gem without version constraint: "+m[1],
			"Without a constraint or a Gemfile.lock any version may be installed.",
			"Add a version constraint and commit Gemfile.lock.", finding.SeverityLow, "RubyGems", m[1], ""))
	}
	return out
}
