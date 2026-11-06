// Package detector inspects a project tree and reports which languages,
// ecosystems, container and IaC technologies are present.
package detector

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/secureprojects/secureprojects/internal/fsutil"
)

// Profile summarizes the technologies detected in a project.
type Profile struct {
	Root       string              `json:"-"`
	Languages  []string            `json:"languages"`
	Ecosystems []string            `json:"ecosystems"`
	Manifests  map[string][]string `json:"manifests"` // ecosystem -> relative manifest paths
	Dockerfile []string            `json:"dockerfiles,omitempty"`
	Compose    []string            `json:"compose,omitempty"`
	Terraform  []string            `json:"terraform,omitempty"`
	K8s        []string            `json:"kubernetes,omitempty"`
	Helm       []string            `json:"helm,omitempty"`
	CloudForm  []string            `json:"cloudformation,omitempty"`
	HasGit     bool                `json:"hasGit"`
	FileCount  int                 `json:"fileCount"`
	Truncated  bool                `json:"truncated,omitempty"`
}

// Has reports whether a language or ecosystem was detected.
func (p *Profile) Has(name string) bool {
	for _, l := range p.Languages {
		if strings.EqualFold(l, name) {
			return true
		}
	}
	for _, e := range p.Ecosystems {
		if strings.EqualFold(e, name) {
			return true
		}
	}
	return false
}

// HasIaC reports whether any IaC technology is present.
func (p *Profile) HasIaC() bool {
	return len(p.Terraform)+len(p.K8s)+len(p.Helm)+len(p.CloudForm)+len(p.Compose) > 0
}

// HasContainers reports whether Dockerfiles or compose files are present.
func (p *Profile) HasContainers() bool { return len(p.Dockerfile)+len(p.Compose) > 0 }

// HasManifests reports whether any dependency manifest was found.
func (p *Profile) HasManifests() bool { return len(p.Manifests) > 0 }

var extLang = map[string]string{
	".go": "Go", ".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
	".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin",
	".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".vb": "VB.NET", ".rs": "Rust", ".c": "C", ".cpp": "C++",
	".scala": "Scala", ".swift": "Swift", ".sh": "Shell", ".tf": "HCL",
}

// manifest file name -> ecosystem (OSV naming).
var manifestEco = map[string]string{
	"go.mod": "Go", "go.sum": "Go",
	"package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm", "npm-shrinkwrap.json": "npm",
	"requirements.txt": "PyPI", "pyproject.toml": "PyPI", "poetry.lock": "PyPI", "pipfile": "PyPI", "pipfile.lock": "PyPI", "setup.py": "PyPI", "uv.lock": "PyPI",
	"pom.xml": "Maven", "build.gradle": "Maven", "build.gradle.kts": "Maven", "gradle.lockfile": "Maven",
	"gemfile": "RubyGems", "gemfile.lock": "RubyGems",
	"composer.json": "Packagist", "composer.lock": "Packagist",
	"cargo.toml": "crates.io", "cargo.lock": "crates.io",
	"packages.lock.json": "NuGet", "packages.config": "NuGet",
}

// Detect walks root (respecting excludes and limits) and builds a Profile.
func Detect(root string, excludes []string, maxFiles int) (*Profile, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, errors.New("scan target must be a directory")
	}
	p := &Profile{Root: abs, Manifests: map[string][]string{}}
	if fi, err := os.Stat(filepath.Join(abs, ".git")); err == nil && fi != nil {
		p.HasGit = true
	}
	langs := map[string]bool{}
	ecos := map[string]bool{}

	err = fsutil.Walk(abs, excludes, maxFiles, func(rel string, d fs.DirEntry) error {
		p.FileCount++
		name := strings.ToLower(d.Name())
		ext := strings.ToLower(path.Ext(name))
		if l, ok := extLang[ext]; ok {
			langs[l] = true
		}
		if strings.HasSuffix(name, ".csproj") || strings.HasSuffix(name, ".fsproj") || strings.HasSuffix(name, ".vbproj") {
			ecos["NuGet"] = true
			langs[".NET"] = true
			p.Manifests["NuGet"] = append(p.Manifests["NuGet"], rel)
		}
		if eco, ok := manifestEco[name]; ok {
			ecos[eco] = true
			p.Manifests[eco] = append(p.Manifests[eco], rel)
		}
		switch {
		case name == "dockerfile" || strings.HasPrefix(name, "dockerfile.") || strings.HasSuffix(name, ".dockerfile") || name == "containerfile":
			p.Dockerfile = append(p.Dockerfile, rel)
		case strings.HasPrefix(name, "docker-compose") || name == "compose.yml" || name == "compose.yaml":
			p.Compose = append(p.Compose, rel)
		case ext == ".tf" || strings.HasSuffix(name, ".tf.json"):
			p.Terraform = append(p.Terraform, rel)
		case name == "chart.yaml":
			p.Helm = append(p.Helm, rel)
		case ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".template":
			classifyStructured(p, filepath.Join(abs, filepath.FromSlash(rel)), rel)
		}
		return nil
	})
	if errors.Is(err, fsutil.ErrTooManyFiles) {
		p.Truncated = true
	} else if err != nil {
		return nil, err
	}
	p.Languages = keys(langs)
	p.Ecosystems = keys(ecos)
	return p, nil
}

func classifyStructured(p *Profile, abs, rel string) {
	if strings.Contains(rel, "/templates/") {
		// probable Helm template; Chart.yaml detection covers the chart itself
		return
	}
	head := readHead(abs, 8192)
	if head == nil {
		return
	}
	switch {
	case bytes.Contains(head, []byte("AWSTemplateFormatVersion")) ||
		(bytes.Contains(head, []byte("Resources")) && bytes.Contains(head, []byte("AWS::"))):
		p.CloudForm = append(p.CloudForm, rel)
	case bytes.Contains(head, []byte("apiVersion")) && bytes.Contains(head, []byte("kind")):
		p.K8s = append(p.K8s, rel)
	}
}

func readHead(p string, n int) []byte {
	f, err := os.Open(p) //nolint:gosec // path comes from a controlled walk
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, n)
	m, _ := f.Read(buf)
	return buf[:m]
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
