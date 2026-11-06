package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/secureprojects/secureprojects/internal/config"
	"github.com/secureprojects/secureprojects/internal/dedup"
	"github.com/secureprojects/secureprojects/internal/execx"
	"github.com/secureprojects/secureprojects/internal/finding"
	"github.com/secureprojects/secureprojects/internal/policy"
	"github.com/secureprojects/secureprojects/internal/report"
	"github.com/secureprojects/secureprojects/internal/scanners/registry"
	"github.com/secureprojects/secureprojects/internal/version"
	"github.com/secureprojects/secureprojects/internal/vulndb"
)

func parseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be > 0")
	}
	return d, nil
}

// ---------- version ----------

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "SecureProjects %s", version.Version)
			if version.Commit != "" {
				fmt.Fprintf(cmd.OutOrStdout(), " (commit %s)", version.Commit)
			}
			if version.Date != "" {
				fmt.Fprintf(cmd.OutOrStdout(), " built %s", version.Date)
			}
			fmt.Fprintf(cmd.OutOrStdout(), " %s/%s %s\nJSON report schema %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version(), report.SchemaVersion)
		},
	}
}

// ---------- tools check ----------

func newToolsCmd(g *globalFlags) *cobra.Command {
	tools := &cobra.Command{Use: "tools", Short: "Manage external tool integrations"}
	var cfgFile, runner string
	var asJSON bool
	check := &cobra.Command{
		Use:   "check",
		Short: "Check which external tools are available (local binary or docker image)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return &exitError{ExitConfig, err}
			}
			if runner != "" {
				cfg.Scanners.Runner = runner
			}
			if err := cfg.Validate(); err != nil {
				return &exitError{ExitConfig, err}
			}
			r := execx.NewRunner(&cfg, g.logger(os.Stderr))
			type row struct {
				Tool        string `json:"tool"`
				Status      string `json:"status"`
				Mode        string `json:"mode"`
				Version     string `json:"version,omitempty"`
				Image       string `json:"image,omitempty"`
				Detail      string `json:"detail,omitempty"`
				InstallHint string `json:"installHint,omitempty"`
			}
			var rows []row
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			for _, s := range registry.External() {
				t := s.Tool()
				res := r.Resolve(ctx, *t)
				rw := row{Tool: t.Name, Mode: string(res.Mode), Version: res.Version, Image: res.Image, Detail: res.Reason}
				if res.Available() {
					rw.Status = "available"
				} else {
					rw.Status = "missing"
					rw.InstallHint = t.InstallHint
				}
				rows = append(rows, rw)
			}
			dbDir := cfg.VulnDB.Dir
			if dbDir == "" {
				dbDir = vulndb.DefaultDir()
			}
			info := vulndb.Info(dbDir, cfg.VulnDB.Ecosystems)
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"tools": rows, "osvDatabase": map[string]any{"dir": dbDir, "ecosystems": info}})
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TOOL\tSTATUS\tMODE\tVERSION/IMAGE\tDETAIL")
			for _, rw := range rows {
				v := rw.Version
				if v == "" {
					v = rw.Image
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", rw.Tool, rw.Status, rw.Mode, v, rw.Detail)
			}
			_ = w.Flush()
			fmt.Fprintln(cmd.OutOrStdout())
			for _, rw := range rows {
				if rw.Status == "missing" {
					fmt.Fprintf(cmd.OutOrStdout(), "- %s: %s\n", rw.Tool, rw.InstallHint)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\nNative analyzers (secrets, Dockerfile, IaC, SAST heuristics, dependency pinning) are always available.\n")
			if len(info) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Native OSV database: NOT downloaded (%s). Run 'secureprojects db update' to enable offline dependency CVE matching.\n", dbDir)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Native OSV database (%s):\n", dbDir)
				for _, e := range vulndb.SortedEcosystems(info) {
					fmt.Fprintf(cmd.OutOrStdout(), "  %-10s updated %s\n", e, info[e].Format(time.RFC3339))
				}
			}
			return nil
		},
	}
	check.Flags().StringVarP(&cfgFile, "config", "c", "", "YAML configuration file")
	check.Flags().StringVar(&runner, "runner", "", "auto|local|docker")
	check.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	tools.AddCommand(check)
	return tools
}

// ---------- db ----------

func newDBCmd(g *globalFlags) *cobra.Command {
	db := &cobra.Command{Use: "db", Short: "Manage the local OSV vulnerability database (used offline)"}
	var dir string
	var ecos []string
	update := &cobra.Command{
		Use:   "update",
		Short: "Download the public OSV database for the configured ecosystems (explicit network access)",
		Long: `Downloads public OSV exports (https://osv-vulnerabilities.storage.googleapis.com)
and builds compact local indexes. Only HTTP GET requests for public files are made;
nothing about your projects is transmitted.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := config.Default()
			if dir == "" {
				dir = vulndb.DefaultDir()
			}
			if len(ecos) == 0 {
				ecos = cfg.VulnDB.Ecosystems
			}
			log := g.logger(os.Stderr)
			if g.logLevel == "warn" && !g.quiet {
				log = (&globalFlags{logLevel: "info", logFormat: g.logFormat}).logger(os.Stderr)
			}
			if err := vulndb.Update(cmd.Context(), dir, ecos, log); err != nil {
				return &exitError{ExitError, err}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "OSV database updated in", dir)
			return nil
		},
	}
	update.Flags().StringVar(&dir, "dir", "", "database directory (default: user cache dir)")
	update.Flags().StringSliceVar(&ecos, "ecosystems", nil, "ecosystems to download (default: Go,npm,PyPI,Maven,RubyGems,Packagist,crates.io,NuGet)")
	status := &cobra.Command{
		Use:   "status",
		Short: "Show local OSV database status",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			if dir == "" {
				dir = vulndb.DefaultDir()
			}
			info := vulndb.Info(dir, config.Default().VulnDB.Ecosystems)
			if len(info) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No local OSV database in", dir, "- run 'secureprojects db update'.")
				return
			}
			for _, e := range vulndb.SortedEcosystems(info) {
				fmt.Fprintf(cmd.OutOrStdout(), "%-10s %s (age %s)\n", e, info[e].Format(time.RFC3339), time.Since(info[e]).Round(time.Hour))
			}
		},
	}
	status.Flags().StringVar(&dir, "dir", "", "database directory")
	var importEco string
	imp := &cobra.Command{
		Use:   "import <all.zip|directory>",
		Short: "Build a local OSV index from an OSV export zip or a directory of OSV JSON files (air-gapped mirrors)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if importEco == "" {
				return &exitError{ExitConfig, fmt.Errorf("--ecosystem is required (e.g. npm, PyPI, Go)")}
			}
			if dir == "" {
				dir = vulndb.DefaultDir()
			}
			st, err := os.Stat(args[0])
			if err != nil {
				return &exitError{ExitConfig, err}
			}
			var ix *vulndb.Index
			if st.IsDir() {
				ix, err = vulndb.BuildFromDir(args[0], importEco)
			} else {
				ix, err = vulndb.BuildFromZip(args[0], importEco)
			}
			if err == nil {
				err = ix.Save(dir)
			}
			if err != nil {
				return &exitError{ExitError, err}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Imported %d %s records into %s\n", len(ix.Vulns), importEco, dir)
			return nil
		},
	}
	imp.Flags().StringVar(&dir, "dir", "", "database directory")
	imp.Flags().StringVar(&importEco, "ecosystem", "", "OSV ecosystem name of the records")
	db.AddCommand(update, status, imp)
	return db
}

// ---------- report merge ----------

func newReportCmd(g *globalFlags) *cobra.Command {
	rep := &cobra.Command{Use: "report", Short: "Work with SecureProjects reports"}
	var formats []string
	var output, failOn string
	merge := &cobra.Command{
		Use:   "merge <report.json>...",
		Short: "Merge several SecureProjects JSON reports into one (deduplicated)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.Default()
			cfg.Formats = formats
			cfg.FailOn = failOn
			if output != "" {
				cfg.Output = output
			}
			if g.noColor {
				cfg.NoColor = true
			}
			if err := cfg.Validate(); err != nil {
				return &exitError{ExitConfig, err}
			}
			merged, err := mergeReports(args, cfg.FailOn, cfg.FailOnPotentialMinConfidence)
			if err != nil {
				return &exitError{ExitConfig, err}
			}
			if _, err := writeMerged(merged, &cfg); err != nil {
				return &exitError{ExitError, err}
			}
			if merged.Summary.Gate.Failed {
				return &exitError{code: ExitFindings}
			}
			return nil
		},
	}
	merge.Flags().StringSliceVarP(&formats, "format", "f", []string{"json"}, "output formats: table,json,sarif,html")
	merge.Flags().StringVarP(&output, "output", "o", "", "output directory")
	merge.Flags().StringVar(&failOn, "fail-on", "high", "gate threshold for the merged report")
	rep.AddCommand(merge)
	return rep
}

func mergeReports(paths []string, failOn, minConf string) (*report.Report, error) {
	var all []finding.Finding
	var first *report.Report
	var targets []string
	merged := &report.Report{SchemaVersion: report.SchemaVersion, Disclaimer: report.Disclaimer,
		Tool: report.ToolInfo{Name: "SecureProjects", Version: version.Version, Commit: version.Commit, URL: version.URL}}
	for _, p := range paths {
		r, err := report.ReadJSON(p)
		if err != nil {
			return nil, err
		}
		if first == nil {
			first = r
			merged.Scan.StartedAt = r.Scan.StartedAt
		}
		if r.Scan.StartedAt.Before(merged.Scan.StartedAt) {
			merged.Scan.StartedAt = r.Scan.StartedAt
		}
		if r.Scan.FinishedAt.After(merged.Scan.FinishedAt) {
			merged.Scan.FinishedAt = r.Scan.FinishedAt
		}
		targets = append(targets, r.Scan.Target)
		merged.Scan.Scanners = append(merged.Scan.Scanners, r.Scan.Scanners...)
		merged.Scan.Warnings = append(merged.Scan.Warnings, r.Scan.Warnings...)
		merged.Scan.Offline = merged.Scan.Offline || r.Scan.Offline
		all = append(all, r.Findings...)
	}
	merged.Scan.TargetType = "merged"
	merged.Scan.Target = fmt.Sprint(targets)
	merged.Scan.Safe = true
	merged.Scan.DurationMs = merged.Scan.FinishedAt.Sub(merged.Scan.StartedAt).Milliseconds()
	fs := dedup.Merge(all)
	dedup.Sort(fs)
	merged.Findings = fs
	failing := policy.Gate(fs, failOn, finding.ParseConfidence(minConf))
	merged.Summary = report.Summarize(fs)
	merged.Summary.Gate = report.Gate{FailOn: failOn, Failed: len(failing) > 0, FailingCount: len(failing)}
	return merged, nil
}

func writeMerged(r *report.Report, cfg *config.Config) ([]string, error) {
	var out []string
	for _, f := range cfg.Formats {
		var p string
		var err error
		switch f {
		case "table":
			report.WriteTable(os.Stdout, r, report.ColorEnabled(os.Stdout, cfg.NoColor), 50)
			continue
		case "json":
			p = cfg.Output + "/secureprojects-merged.json"
			err = report.WriteJSON(r, p)
		case "sarif":
			p = cfg.Output + "/secureprojects-merged.sarif"
			err = report.WriteSARIF(r, p)
		case "html":
			p = cfg.Output + "/secureprojects-merged.html"
			err = report.WriteHTML(r, p)
		}
		if err != nil {
			return out, err
		}
		fmt.Fprintln(os.Stderr, "report written:", p)
		out = append(out, p)
	}
	return out, nil
}
