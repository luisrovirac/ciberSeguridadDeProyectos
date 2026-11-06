package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scoring"
)

// ColorEnabled decides whether ANSI colors should be used on w.
func ColorEnabled(w io.Writer, disabled bool) bool {
	if disabled || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return enableVT(f)
}

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	cyan   = "\x1b[36m"
	green  = "\x1b[32m"
	mag    = "\x1b[35m"
)

func sevColor(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return bold + mag
	case finding.SeverityHigh:
		return red
	case finding.SeverityMedium:
		return yellow
	case finding.SeverityLow:
		return blue
	default:
		return dim
	}
}

// WriteTable prints an executive summary and the findings table.
// maxRows <= 0 prints every finding.
func WriteTable(w io.Writer, r *Report, color bool, maxRows int) {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + reset
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, c(bold, "SecureProjects "+r.Tool.Version+" — security scan report"))
	fmt.Fprintf(w, "Target: %s", r.Scan.Target)
	if r.Scan.Commit != "" {
		fmt.Fprintf(w, "  (commit %s)", shortSHA(r.Scan.Commit))
	}
	fmt.Fprintf(w, "\nMode: %s%s   Duration: %.1fs\n", modeLabel(r), "", float64(r.Scan.DurationMs)/1000)
	fmt.Fprintln(w)

	// Scanner status
	fmt.Fprintln(w, c(bold, "Scanners"))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, s := range r.Scan.Scanners {
		if s.Status == "not-applicable" || s.Status == "disabled" {
			continue
		}
		st := s.Status
		switch s.Status {
		case "ok", "cached":
			st = c(green, st)
		case "skipped":
			st = c(yellow, st)
		case "error":
			st = c(red, st)
		}
		msg := s.Message
		if s.InstallHint != "" && s.Status == "skipped" {
			msg = strings.TrimSpace(msg + " — " + s.InstallHint)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%d findings\t%s\n", s.Name, st, s.Mode, s.Findings, truncate(msg, 140))
	}
	_ = tw.Flush()
	fmt.Fprintln(w)

	// Executive summary
	s := r.Summary
	fmt.Fprintln(w, c(bold, "Summary"))
	fmt.Fprintf(w, "  Open findings: %d  (suppressed: %d", s.Open, s.Suppressed)
	if s.New != nil {
		fmt.Fprintf(w, ", new vs baseline: %d", *s.New)
	}
	fmt.Fprintln(w, ")")
	var parts []string
	for _, sev := range finding.AllSeverities {
		if n := s.BySeverity[string(sev)]; n > 0 {
			parts = append(parts, c(sevColor(sev), fmt.Sprintf("%s: %d", sev, n)))
		}
	}
	if len(parts) == 0 {
		parts = []string{c(green, "no open findings")}
	}
	fmt.Fprintln(w, "  "+strings.Join(parts, "  "))
	fmt.Fprintf(w, "  Confirmed vulnerabilities: %d   Potential risks (heuristic): %d\n", s.ByKind[string(finding.KindVulnerability)], s.ByKind[string(finding.KindPotentialRisk)])
	if len(s.ByCategory) > 0 {
		var cats []string
		for _, kv := range topN(s.ByCategory, 0) {
			cats = append(cats, fmt.Sprintf("%s: %d", kv.Key, kv.Count))
		}
		fmt.Fprintln(w, "  By category: "+strings.Join(cats, ", "))
	}
	if files := TopFiles(s.ByFile, 5); len(files) > 0 {
		var fl []string
		for _, kv := range files {
			fl = append(fl, fmt.Sprintf("%s (%d)", kv.Key, kv.Count))
		}
		fmt.Fprintln(w, "  Top files: "+strings.Join(fl, ", "))
	}
	fmt.Fprintln(w)

	// Findings
	var open []finding.Finding
	for _, f := range r.Findings {
		if !f.Triage.Status.Suppressed() {
			open = append(open, f)
		}
	}
	if len(open) > 0 {
		fmt.Fprintln(w, c(bold, "Findings (highest priority first)"))
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  PRIO\tSEVERITY\tKIND\tCONF\tLOCATION\tTITLE\tTOOLS")
		for i, f := range open {
			if maxRows > 0 && i >= maxRows {
				fmt.Fprintf(tw, "  …\t\t\t\t\t%d more findings in the JSON/HTML report\t\n", len(open)-maxRows)
				break
			}
			kind := "CONFIRMED"
			if f.Kind == finding.KindPotentialRisk {
				kind = "potential"
			}
			fmt.Fprintf(tw, "  %s %.0f\t%s\t%s\t%s\t%s\t%s\t%s\n",
				scoring.Label(f.Priority), f.Priority, c(sevColor(f.Severity), string(f.Severity)), kind, f.Confidence,
				truncate(location(f), 50), truncate(f.Title, 80), strings.Join(f.Tools, ","))
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}
	for _, wmsg := range r.Scan.Warnings {
		fmt.Fprintln(w, c(yellow, "warning: ")+wmsg)
	}
	g := s.Gate
	switch {
	case g.FailOn == "none":
		fmt.Fprintln(w, "CI gate: disabled (--fail-on none)")
	case g.Failed:
		fmt.Fprintln(w, c(red+bold, fmt.Sprintf("CI gate: FAILED — %d open finding(s) at or above '%s'", g.FailingCount, g.FailOn)))
	default:
		fmt.Fprintln(w, c(green, fmt.Sprintf("CI gate: passed (no open findings at or above '%s')", g.FailOn)))
	}
	fmt.Fprintln(w, c(dim, "'potential' = heuristic/policy finding, not a confirmed vulnerability. Scan only projects you are authorized to test."))
}

func location(f finding.Finding) string {
	switch {
	case f.Location.Path != "" && f.Location.StartLine > 0:
		return fmt.Sprintf("%s:%d", f.Location.Path, f.Location.StartLine)
	case f.Location.Path != "":
		return f.Location.Path
	default:
		return f.Location.Resource
	}
}

func modeLabel(r *Report) string {
	var m []string
	if r.Scan.Offline {
		m = append(m, "offline")
	} else {
		m = append(m, "online (tool DB updates allowed)")
	}
	if r.Scan.ActiveScan {
		m = append(m, "ACTIVE DAST")
	} else {
		m = append(m, "passive/safe")
	}
	return strings.Join(m, ", ")
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
