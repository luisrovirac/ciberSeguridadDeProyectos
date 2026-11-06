package report

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/url"
	"strings"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scoring"
)

//go:embed templates/report.html.tmpl
var templatesFS embed.FS

var (
	htmlTmpl   *template.Template
	scriptHash string
)

func init() {
	raw, err := templatesFS.ReadFile("templates/report.html.tmpl")
	if err != nil {
		panic(err)
	}
	// The CSP allows exactly the inline script embedded in the template.
	s := string(raw)
	start := strings.Index(s, "<script>")
	end := strings.Index(s, "</script>")
	if start < 0 || end < 0 {
		panic("report template: inline script not found")
	}
	sum := sha256.Sum256([]byte(s[start+len("<script>") : end]))
	scriptHash = "sha256-" + base64.StdEncoding.EncodeToString(sum[:])

	htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
		"join":  strings.Join,
		"label": scoring.Label,
		"deref": func(b *bool) bool { return b != nil && *b },
		"loc": func(f finding.Finding) string {
			switch {
			case f.Location.Path != "" && f.Location.StartLine > 0:
				return fmt.Sprintf("%s:%d", f.Location.Path, f.Location.StartLine)
			case f.Location.Path != "":
				return f.Location.Path
			}
			return f.Location.Resource
		},
		"searchText": func(f finding.Finding) string {
			parts := []string{f.Title, f.Location.Path, f.Location.Resource, f.RuleID, f.RuleFamily, strings.Join(f.CVE, " "), strings.Join(f.Aliases, " "), strings.Join(f.CWE, " ")}
			if f.Package != nil {
				parts = append(parts, f.Package.Name, f.Package.Version)
			}
			return strings.ToLower(strings.Join(parts, " "))
		},
		// safeURL only lets http(s) links through; html/template escapes the rest.
		"safeURL": func(s string) bool {
			u, err := url.Parse(s)
			return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
		},
	}).Parse(s))
}

type bar struct {
	Key   string
	Count int
	Width int
}

func bars(m map[string]int, n int) []bar {
	kvs := topN(m, n)
	maxV := 1
	for _, kv := range kvs {
		maxV = max(maxV, kv.Count)
	}
	out := make([]bar, len(kvs))
	for i, kv := range kvs {
		out[i] = bar{kv.Key, kv.Count, 2 + kv.Count*160/maxV}
	}
	return out
}

// RenderHTML renders the self-contained HTML report.
func RenderHTML(r *Report) ([]byte, error) {
	data := struct {
		R          *Report
		ScriptHash string
		Sevs       []string
		Cats       []bar
		Tools      []bar
		Files      []bar
	}{
		R: r, ScriptHash: scriptHash,
		Sevs:  []string{"critical", "high", "medium", "low", "info"},
		Cats:  bars(r.Summary.ByCategory, 0),
		Tools: bars(r.Summary.ByTool, 0),
		Files: bars(r.Summary.ByFile, 10),
	}
	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteHTML writes the HTML report.
func WriteHTML(r *Report, path string) error {
	b, err := RenderHTML(r)
	if err != nil {
		return err
	}
	return writeFile(path, b)
}
