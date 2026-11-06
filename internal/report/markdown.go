package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scoring"
)

// WriteMarkdown writes the report as a human-readable Markdown document.
func WriteMarkdown(r *Report, path string) error {
	var b bytes.Buffer
	RenderMarkdown(&b, r)
	return writeFile(path, b.Bytes())
}

// RenderMarkdown renders the report as Markdown (in Spanish, like the docs).
func RenderMarkdown(w io.Writer, r *Report) {
	p := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }
	s := r.Summary

	p("# Informe de seguridad — SecureProjects %s\n\n", r.Tool.Version)
	p("| | |\n|---|---|\n")
	p("| **Objetivo** | `%s` |\n", cell(r.Scan.Target))
	if r.Scan.Repository != "" && r.Scan.Repository != r.Scan.Target {
		p("| **Repositorio** | %s |\n", cell(r.Scan.Repository))
	}
	if r.Scan.Commit != "" {
		p("| **Commit** | `%s` |\n", shortSHA(r.Scan.Commit))
	}
	if r.Scan.Branch != "" {
		p("| **Rama** | %s |\n", cell(r.Scan.Branch))
	}
	if !r.Scan.StartedAt.IsZero() {
		p("| **Fecha** | %s |\n", r.Scan.StartedAt.Local().Format("2006-01-02 15:04:05"))
	}
	p("| **Duración** | %s |\n", (time.Duration(r.Scan.DurationMs) * time.Millisecond).Round(100*time.Millisecond))
	p("| **Modo** | %s |\n\n", cell(modeLabel(r)))

	// Summary
	p("## Resumen\n\n")
	p("- Hallazgos abiertos: **%d** (suprimidos: %d", s.Open, s.Suppressed)
	if s.New != nil {
		p(", nuevos respecto a la línea base: %d", *s.New)
	}
	p(")\n")
	p("- Vulnerabilidades confirmadas: **%d** · Riesgos potenciales (heurísticos): **%d**\n",
		s.ByKind[string(finding.KindVulnerability)], s.ByKind[string(finding.KindPotentialRisk)])
	switch g := s.Gate; {
	case g.FailOn == "none":
		p("- Puerta de CI: desactivada (`--fail-on none`)\n")
	case g.Failed:
		p("- Puerta de CI: **FALLA** — %d hallazgo(s) abiertos de severidad `%s` o superior\n", g.FailingCount, g.FailOn)
	default:
		p("- Puerta de CI: superada (ningún hallazgo abierto de severidad `%s` o superior)\n", g.FailOn)
	}
	p("\n| Severidad | Abiertos |\n|---|---:|\n")
	for _, sev := range finding.AllSeverities {
		p("| %s | %d |\n", sev, s.BySeverity[string(sev)])
	}
	p("\n")
	if len(s.ByCategory) > 0 {
		p("**Por categoría:** ")
		var cats []string
		for _, kv := range topN(s.ByCategory, 0) {
			cats = append(cats, fmt.Sprintf("%s (%d)", kv.Key, kv.Count))
		}
		p("%s\n\n", strings.Join(cats, ", "))
	}
	if files := TopFiles(s.ByFile, 10); len(files) > 0 {
		p("**Archivos con más hallazgos:**\n\n")
		for _, kv := range files {
			p("- `%s` (%d)\n", cell(kv.Key), kv.Count)
		}
		p("\n")
	}

	if len(r.Scan.Warnings) > 0 {
		p("## Avisos\n\n")
		for _, wmsg := range r.Scan.Warnings {
			p("> ⚠️ %s\n>\n", oneLine(wmsg))
		}
		p("\n")
	}

	// Scanners
	p("## Analizadores\n\n| Analizador | Estado | Modo | Hallazgos | Detalle |\n|---|---|---|---:|---|\n")
	for _, st := range r.Scan.Scanners {
		if st.Status == "not-applicable" || st.Status == "disabled" {
			continue
		}
		msg := st.Message
		if st.InstallHint != "" && st.Status == "skipped" {
			msg = strings.TrimSpace(msg + " — " + st.InstallHint)
		}
		p("| %s | %s | %s | %d | %s |\n", st.Name, st.Status, st.Mode, st.Findings, cell(msg))
	}
	p("\n")

	// Findings
	var open, suppressed []finding.Finding
	for _, f := range r.Findings {
		if f.Triage.Status.Suppressed() {
			suppressed = append(suppressed, f)
		} else {
			open = append(open, f)
		}
	}
	p("## Hallazgos (mayor prioridad primero)\n\n")
	if len(open) == 0 {
		p("No hay hallazgos abiertos.\n\n")
	} else {
		p("| # | Prioridad | Severidad | Tipo | Ubicación | Título |\n|---:|---|---|---|---|---|\n")
		for i, f := range open {
			p("| [%d](#h%d) | %s %.0f | %s | %s | `%s` | %s |\n", i+1, i+1, scoring.Label(f.Priority), f.Priority,
				f.Severity, kindLabel(f), cell(location(f)), cell(f.Title))
		}
		p("\n")
		for i, f := range open {
			writeFindingMD(w, i+1, f)
		}
	}

	if len(suppressed) > 0 {
		p("## Hallazgos suprimidos (%d)\n\n| Severidad | Ubicación | Título | Estado | Justificación |\n|---|---|---|---|---|\n", len(suppressed))
		for _, f := range suppressed {
			p("| %s | `%s` | %s | %s | %s |\n", f.Severity, cell(location(f)), cell(f.Title), f.Triage.Status, cell(f.Triage.Justification))
		}
		p("\n")
	}

	p("---\n\n_%s_\n", r.Disclaimer)
}

func writeFindingMD(w io.Writer, n int, f finding.Finding) {
	p := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }
	p("<a id=\"h%d\"></a>\n### %d. [%s] %s\n\n", n, n, strings.ToUpper(string(f.Severity)), oneLine(f.Title))
	p("- **Tipo:** %s · **Confianza:** %s · **Prioridad:** %s %.0f\n", kindLabel(f), f.Confidence, scoring.Label(f.Priority), f.Priority)
	p("- **Categoría:** %s\n", f.Category)
	if loc := location(f); loc != "" {
		p("- **Ubicación:** `%s`\n", loc)
	}
	if pk := f.Package; pk != nil {
		line := pk.Name
		if pk.Version != "" {
			line += "@" + pk.Version
		}
		if pk.Ecosystem != "" {
			line += " (" + pk.Ecosystem + ")"
		}
		p("- **Paquete:** `%s`", line)
		if len(pk.FixedVersions) > 0 {
			p(" — corregido en: %s", strings.Join(pk.FixedVersions, ", "))
		}
		p("\n")
	}
	if len(f.CVE) > 0 {
		p("- **CVE:** %s\n", strings.Join(f.CVE, ", "))
	}
	if f.CVSS != nil && f.CVSS.Score > 0 {
		p("- **CVSS:** %.1f %s\n", f.CVSS.Score, f.CVSS.Vector)
	}
	if len(f.CWE) > 0 {
		p("- **CWE:** %s\n", strings.Join(f.CWE, ", "))
	}
	p("- **Herramientas:** %s", strings.Join(f.Tools, ", "))
	if f.RuleID != "" {
		p(" · **Regla:** `%s`", f.RuleID)
	}
	p("\n\n")
	if f.Description != "" {
		p("%s\n\n", strings.TrimSpace(f.Description))
	}
	if f.Evidence != "" {
		fence := codeFence(f.Evidence)
		p("**Evidencia** (datos sensibles ocultados):\n\n%s\n%s\n%s\n\n", fence, strings.TrimRight(f.Evidence, "\n"), fence)
	}
	if f.Remediation != "" {
		p("**Cómo corregirlo:** %s\n\n", strings.TrimSpace(f.Remediation))
	}
	if f.AIExplanation != "" {
		p("**Explicación del LLM (no autoritativa):** %s\n\n", strings.TrimSpace(f.AIExplanation))
	}
	if len(f.References) > 0 {
		p("**Referencias:**\n\n")
		for _, ref := range f.References {
			p("- %s\n", ref)
		}
		p("\n")
	}
}

func kindLabel(f finding.Finding) string {
	if f.Kind == finding.KindPotentialRisk {
		return "riesgo potencial"
	}
	return "vulnerabilidad confirmada"
}

// cell makes a value safe inside a Markdown table cell.
func cell(s string) string {
	return strings.ReplaceAll(oneLine(s), "|", `\|`)
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// codeFence returns a backtick fence longer than any backtick run in s.
func codeFence(s string) string {
	longest, run := 0, 0
	for _, c := range s {
		if c == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return strings.Repeat("`", max(3, longest+1))
}
