// Package lockfiles extracts exact (name, version) pairs from dependency
// lockfiles and manifests. Only exact versions are returned: ranges cannot be
// matched against vulnerability data without resolution.
package lockfiles

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Package is a resolved dependency.
type Package struct {
	Name      string
	Version   string
	Ecosystem string // OSV ecosystem name
	File      string // relative path of the lockfile
	Line      int
	Direct    *bool
	Dev       bool
}

// Parser parses one lockfile format.
type Parser func(rel string, data []byte) []Package

// ParserFor returns a parser for the file name, or nil.
func ParserFor(rel string) Parser {
	b := strings.ToLower(path.Base(rel))
	switch {
	case b == "go.mod":
		return ParseGoMod
	case b == "package-lock.json" || b == "npm-shrinkwrap.json":
		return ParsePackageLock
	case b == "yarn.lock":
		return ParseYarnLock
	case b == "pnpm-lock.yaml":
		return ParsePnpmLock
	case strings.HasPrefix(b, "requirements") && strings.HasSuffix(b, ".txt"):
		return ParseRequirements
	case b == "poetry.lock" || b == "uv.lock":
		return tomlPackages("PyPI")
	case b == "pipfile.lock":
		return ParsePipfileLock
	case b == "cargo.lock":
		return tomlPackages("crates.io")
	case b == "gemfile.lock":
		return ParseGemfileLock
	case b == "composer.lock":
		return ParseComposerLock
	case b == "pom.xml":
		return ParsePom
	case b == "gradle.lockfile":
		return ParseGradleLock
	case b == "packages.lock.json":
		return ParseNuGetLock
	case strings.HasSuffix(b, ".csproj") || strings.HasSuffix(b, ".fsproj") || strings.HasSuffix(b, ".vbproj"):
		return ParseCsproj
	}
	return nil
}

func lines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func bptr(b bool) *bool { return &b }

// lineIndex finds the first line containing needle (1-based, 0 if none).
func lineIndex(ls []string, needle string) int {
	for i, l := range ls {
		if strings.Contains(l, needle) {
			return i + 1
		}
	}
	return 0
}

func sortPkgs(p []Package) []Package {
	sort.SliceStable(p, func(i, j int) bool {
		if p[i].Name != p[j].Name {
			return p[i].Name < p[j].Name
		}
		return p[i].Version < p[j].Version
	})
	return p
}

// ---------- Go ----------

var goReqRe = regexp.MustCompile(`^\s*(?:require\s+)?([^\s()]+)\s+(v[^\s]+)(\s*//\s*indirect)?`)

// ParseGoMod reads require directives (Go >= 1.17 lists the full build list).
func ParseGoMod(rel string, data []byte) []Package {
	var out []Package
	inReq := false
	for i, l := range lines(data) {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "require ("):
			inReq = true
			continue
		case inReq && t == ")":
			inReq = false
			continue
		case !inReq && !strings.HasPrefix(t, "require "):
			continue
		}
		if m := goReqRe.FindStringSubmatch(t); m != nil {
			out = append(out, Package{Name: m[1], Version: strings.TrimPrefix(m[2], "v"), Ecosystem: "Go", File: rel, Line: i + 1, Direct: bptr(m[3] == "")})
		}
	}
	return sortPkgs(out)
}

// ---------- npm ----------

// ParsePackageLock supports lockfileVersion 1, 2 and 3.
func ParsePackageLock(rel string, data []byte) []Package {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
			Link    bool   `json:"link"`
			Name    string `json:"name"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	ls := lines(data)
	var out []Package
	if len(lock.Packages) > 0 {
		direct := map[string]bool{}
		var rootDeps struct {
			Packages map[string]struct {
				Dependencies    map[string]string `json:"dependencies"`
				DevDependencies map[string]string `json:"devDependencies"`
			} `json:"packages"`
		}
		_ = json.Unmarshal(data, &rootDeps)
		for n := range rootDeps.Packages[""].Dependencies {
			direct[n] = true
		}
		for n := range rootDeps.Packages[""].DevDependencies {
			direct[n] = true
		}
		for key, p := range lock.Packages {
			if key == "" || p.Link || p.Version == "" {
				continue
			}
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 {
				continue
			}
			name := key[i+len("node_modules/"):]
			if p.Name != "" {
				name = p.Name
			}
			isDirect := direct[name] && strings.Count(key, "node_modules/") == 1
			out = append(out, Package{Name: name, Version: p.Version, Ecosystem: "npm", File: rel, Line: lineIndex(ls, `"`+key+`"`), Direct: bptr(isDirect), Dev: p.Dev})
		}
		return sortPkgs(dedupe(out))
	}
	// lockfileVersion 1: nested "dependencies"
	var walk func(deps map[string]json.RawMessage, depth int)
	walk = func(deps map[string]json.RawMessage, depth int) {
		for name, raw := range deps {
			var d struct {
				Version      string                     `json:"version"`
				Dev          bool                       `json:"dev"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &d) != nil {
				continue
			}
			if d.Version != "" && !strings.Contains(d.Version, ":") {
				out = append(out, Package{Name: name, Version: d.Version, Ecosystem: "npm", File: rel, Line: lineIndex(ls, `"`+name+`"`), Direct: bptr(depth == 0), Dev: d.Dev})
			}
			walk(d.Dependencies, depth+1)
		}
	}
	walk(lock.Dependencies, 0)
	return sortPkgs(dedupe(out))
}

var yarnHeaderRe = regexp.MustCompile(`^"?(@?[^@"\s]+)@`)
var yarnVersionRe = regexp.MustCompile(`^\s+version:?\s+"?([^"\s]+)"?`)

// ParseYarnLock supports yarn classic (v1) and berry lockfiles.
func ParseYarnLock(rel string, data []byte) []Package {
	var out []Package
	name, line := "", 0
	for i, l := range lines(data) {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if !strings.HasPrefix(l, " ") {
			name, line = "", 0
			if m := yarnHeaderRe.FindStringSubmatch(l); m != nil && m[1] != "__metadata" {
				name, line = m[1], i+1
			}
			continue
		}
		if name != "" {
			if m := yarnVersionRe.FindStringSubmatch(l); m != nil {
				out = append(out, Package{Name: name, Version: m[1], Ecosystem: "npm", File: rel, Line: line})
				name = ""
			}
		}
	}
	return sortPkgs(dedupe(out))
}

var pnpmKeyRe = regexp.MustCompile(`^\s{2}['"]?/?(@?[^@\s'"/]+(?:/[^@\s'"/]+)?)[@/]([0-9][^\s('":]*)`)

// ParsePnpmLock reads package keys of pnpm lockfiles (v5-v9).
func ParsePnpmLock(rel string, data []byte) []Package {
	var out []Package
	inPackages := false
	for i, l := range lines(data) {
		if !strings.HasPrefix(l, " ") && strings.HasSuffix(strings.TrimSpace(l), ":") {
			inPackages = strings.TrimSpace(l) == "packages:" || strings.TrimSpace(l) == "snapshots:"
			continue
		}
		if !inPackages {
			continue
		}
		if m := pnpmKeyRe.FindStringSubmatch(l); m != nil {
			out = append(out, Package{Name: m[1], Version: m[2], Ecosystem: "npm", File: rel, Line: i + 1})
		}
	}
	return sortPkgs(dedupe(out))
}

// ---------- Python ----------

var reqPinRe = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)`)

// ParseRequirements returns only exactly pinned (==) requirements.
func ParseRequirements(rel string, data []byte) []Package {
	var out []Package
	for i, l := range lines(data) {
		if m := reqPinRe.FindStringSubmatch(l); m != nil && !strings.Contains(m[2], "*") {
			out = append(out, Package{Name: NormalizePyPI(m[1]), Version: m[2], Ecosystem: "PyPI", File: rel, Line: i + 1, Direct: bptr(true)})
		}
	}
	return sortPkgs(out)
}

var pypiSepRe = regexp.MustCompile(`[-_.]+`)

// NormalizePyPI applies PEP 503 name normalization.
func NormalizePyPI(n string) string {
	return pypiSepRe.ReplaceAllString(strings.ToLower(n), "-")
}

// ParsePipfileLock reads Pipfile.lock JSON.
func ParsePipfileLock(rel string, data []byte) []Package {
	var lock map[string]json.RawMessage
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	ls := lines(data)
	var out []Package
	for _, section := range []string{"default", "develop"} {
		var deps map[string]struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(lock[section], &deps) != nil {
			continue
		}
		for name, d := range deps {
			v := strings.TrimPrefix(d.Version, "==")
			if v == "" || v == d.Version {
				continue
			}
			out = append(out, Package{Name: NormalizePyPI(name), Version: v, Ecosystem: "PyPI", File: rel, Line: lineIndex(ls, `"`+name+`"`), Dev: section == "develop"})
		}
	}
	return sortPkgs(out)
}

// tomlPackages parses [[package]] tables with name/version keys
// (poetry.lock, uv.lock, Cargo.lock) without a full TOML parser.
func tomlPackages(eco string) Parser {
	return func(rel string, data []byte) []Package {
		var out []Package
		var name, ver string
		start := 0
		flush := func() {
			if name != "" && ver != "" {
				n := name
				if eco == "PyPI" {
					n = NormalizePyPI(n)
				}
				out = append(out, Package{Name: n, Version: ver, Ecosystem: eco, File: rel, Line: start})
			}
			name, ver = "", ""
		}
		for i, l := range lines(data) {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "[") {
				flush()
				if t == "[[package]]" {
					start = i + 1
				} else {
					start = 0
				}
				continue
			}
			if start == 0 {
				continue
			}
			if k, v, ok := strings.Cut(t, "="); ok {
				k = strings.TrimSpace(k)
				v = strings.Trim(strings.TrimSpace(v), `"'`)
				switch k {
				case "name":
					name = v
				case "version":
					ver = v
				}
			}
		}
		flush()
		return sortPkgs(out)
	}
}

// ---------- Ruby ----------

var gemSpecRe = regexp.MustCompile(`^ {4}([A-Za-z0-9._-]+) \(([^)\s]+)\)$`)

// ParseGemfileLock reads the specs section of Gemfile.lock.
func ParseGemfileLock(rel string, data []byte) []Package {
	var out []Package
	for i, l := range lines(data) {
		if m := gemSpecRe.FindStringSubmatch(l); m != nil {
			v := m[2]
			if j := strings.Index(v, "-"); j > 0 && strings.ContainsAny(v[j:], "abcdefghijklmnopqrstuvwxyz") && (strings.Contains(v[j:], "linux") || strings.Contains(v[j:], "darwin") || strings.Contains(v[j:], "mingw") || strings.Contains(v[j:], "java")) {
				v = v[:j] // strip platform suffix
			}
			out = append(out, Package{Name: m[1], Version: v, Ecosystem: "RubyGems", File: rel, Line: i + 1})
		}
	}
	return sortPkgs(dedupe(out))
}

// ---------- PHP ----------

// ParseComposerLock reads composer.lock packages and packages-dev.
func ParseComposerLock(rel string, data []byte) []Package {
	var lock struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	ls := lines(data)
	var out []Package
	add := func(name, v string, dev bool) {
		v = strings.TrimPrefix(v, "v")
		if name == "" || v == "" || strings.HasPrefix(v, "dev-") {
			return
		}
		out = append(out, Package{Name: name, Version: v, Ecosystem: "Packagist", File: rel, Line: lineIndex(ls, `"`+name+`"`), Dev: dev})
	}
	for _, p := range lock.Packages {
		add(p.Name, p.Version, false)
	}
	for _, p := range lock.PackagesDev {
		add(p.Name, p.Version, true)
	}
	return sortPkgs(out)
}

// ---------- Java ----------

// ParsePom reads dependencies with literal versions from pom.xml.
// Property placeholders (${...}) are resolved only from the same file's <properties>.
func ParsePom(rel string, data []byte) []Package {
	type dep struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
		Scope      string `xml:"scope"`
	}
	var pom struct {
		Properties struct {
			Entries []struct {
				XMLName xml.Name
				Value   string `xml:",chardata"`
			} `xml:",any"`
		} `xml:"properties"`
		Deps    []dep `xml:"dependencies>dependency"`
		Managed []dep `xml:"dependencyManagement>dependencies>dependency"`
	}
	if xml.Unmarshal(data, &pom) != nil {
		return nil
	}
	props := map[string]string{}
	for _, e := range pom.Properties.Entries {
		props[e.XMLName.Local] = strings.TrimSpace(e.Value)
	}
	ls := lines(data)
	var out []Package
	for _, d := range append(pom.Deps, pom.Managed...) {
		v := strings.TrimSpace(d.Version)
		if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
			v = props[v[2:len(v)-1]]
		}
		if v == "" || strings.ContainsAny(v, "[]()${},") {
			continue
		}
		out = append(out, Package{Name: d.GroupID + ":" + d.ArtifactID, Version: v, Ecosystem: "Maven", File: rel,
			Line: lineIndex(ls, "<artifactId>"+d.ArtifactID+"</artifactId>"), Direct: bptr(true), Dev: d.Scope == "test"})
	}
	return sortPkgs(dedupe(out))
}

// ParseGradleLock reads gradle.lockfile entries "group:artifact:version=configs".
func ParseGradleLock(rel string, data []byte) []Package {
	var out []Package
	for i, l := range lines(data) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "empty=") {
			continue
		}
		coord, _, _ := strings.Cut(l, "=")
		parts := strings.Split(coord, ":")
		if len(parts) != 3 {
			continue
		}
		out = append(out, Package{Name: parts[0] + ":" + parts[1], Version: parts[2], Ecosystem: "Maven", File: rel, Line: i + 1})
	}
	return sortPkgs(out)
}

// ---------- .NET ----------

// ParseNuGetLock reads packages.lock.json.
func ParseNuGetLock(rel string, data []byte) []Package {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	ls := lines(data)
	var out []Package
	for _, deps := range lock.Dependencies {
		for name, d := range deps {
			if d.Resolved == "" || d.Type == "Project" {
				continue
			}
			out = append(out, Package{Name: name, Version: d.Resolved, Ecosystem: "NuGet", File: rel, Line: lineIndex(ls, `"`+name+`"`), Direct: bptr(d.Type == "Direct")})
		}
	}
	return sortPkgs(dedupe(out))
}

var pkgRefRe = regexp.MustCompile(`(?i)<PackageReference\s+Include\s*=\s*"([^"]+)"\s+Version\s*=\s*"([^"\[\]()*,]+)"`)

// ParseCsproj reads PackageReference elements with literal versions.
func ParseCsproj(rel string, data []byte) []Package {
	var out []Package
	for i, l := range lines(data) {
		if m := pkgRefRe.FindStringSubmatch(l); m != nil {
			out = append(out, Package{Name: m[1], Version: m[2], Ecosystem: "NuGet", File: rel, Line: i + 1, Direct: bptr(true)})
		}
	}
	return sortPkgs(out)
}

func dedupe(in []Package) []Package {
	seen := map[string]bool{}
	out := in[:0]
	for _, p := range in {
		k := p.Name + "@" + p.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out
}
