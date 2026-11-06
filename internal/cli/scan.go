package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/app"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/report"
)

type scanFlags struct {
	configFile  string
	repo        string
	formats     []string
	output      string
	failOn      string
	baseline    string
	diff        bool
	offline     bool
	online      bool
	safe        bool
	allowActive bool
	targetURL   string
	authorized  bool
	only        []string
	disable     []string
	runner      string
	noCache     bool
	noHistory   bool
	customRules string
	ignoreFile  string
	llmExplain  bool
	llmConsent  bool
	toolTimeout string
	scanTimeout string
	maxFileSize int64
}

const legalWarning = `
!!! ACTIVE SCANNING (DAST) REQUESTED !!!
SecureProjects will send HTTP requests to %s using OWASP ZAP (baseline: spider +
passive rules, no attack payloads). Scanning systems without explicit written
authorization from their owner may be ILLEGAL in your jurisdiction.
You are solely responsible for having permission to test this target.
`

func newScanCmd(g *globalFlags) *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a local project directory or a Git repository",
		Example: `  secureprojects scan .
  secureprojects scan ./service --format table,json,sarif,html --output reports --fail-on high
  secureprojects scan --repo https://github.com/org/repo --offline
  secureprojects scan . --baseline reports/secureprojects-report.json --diff
  secureprojects scan . --allow-active-scan --target-url https://staging.example.com --i-have-authorization`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, g, f, args)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.configFile, "config", "c", "", "YAML configuration file")
	fl.StringVar(&f.repo, "repo", "", "Git repository URL to clone temporarily and scan (https://, ssh://, git@host:path)")
	fl.StringSliceVarP(&f.formats, "format", "f", nil, "output formats: table,json,sarif,html,md (default table; md is written to the current directory unless --output is set)")
	fl.StringVarP(&f.output, "output", "o", "", "directory for report files (default ./secureprojects-report)")
	fl.StringVar(&f.failOn, "fail-on", "", "exit 1 if open findings reach this severity: critical|high|medium|low|info|none (default high)")
	fl.StringVar(&f.baseline, "baseline", "", "previous SecureProjects JSON report to compare against")
	fl.BoolVar(&f.diff, "diff", false, "only report findings that are new compared to --baseline")
	fl.BoolVar(&f.offline, "offline", true, "never use the network: no tool DB updates, no image pulls, docker --network none (default)")
	fl.BoolVar(&f.online, "online", false, "allow external tools to update their public vulnerability databases and docker to pull images (source code is never uploaded)")
	fl.BoolVar(&f.safe, "safe", true, "safe/passive mode (default); no intrusive tests")
	fl.BoolVar(&f.allowActive, "allow-active-scan", false, "enable DAST (OWASP ZAP baseline) against --target-url; requires authorization")
	fl.StringVar(&f.targetURL, "target-url", "", "URL of the application to test with DAST (only with --allow-active-scan)")
	fl.BoolVar(&f.authorized, "i-have-authorization", false, "confirm you are authorized to actively test --target-url (non-interactive)")
	fl.StringSliceVar(&f.only, "only", nil, "run only these scanners (comma separated)")
	fl.StringSliceVar(&f.disable, "disable", nil, "disable these scanners (comma separated)")
	fl.StringVar(&f.runner, "runner", "", "how to run external tools: auto|local|docker (default auto)")
	fl.BoolVar(&f.noCache, "no-cache", false, "do not read or write the result cache")
	fl.BoolVar(&f.noHistory, "no-git-history", false, "do not scan Git history for secrets")
	fl.StringVar(&f.customRules, "rules", "", "YAML file with custom regex rules")
	fl.StringVar(&f.ignoreFile, "ignore-file", "", "ignore file (default .secureprojects-ignore.yaml in the target)")
	fl.BoolVar(&f.llmExplain, "llm-explain", false, "add non-authoritative LLM explanations to top findings (sends finding metadata, never source files)")
	fl.BoolVar(&f.llmConsent, "llm-consent", false, "explicit consent to send finding metadata to the configured LLM provider")
	fl.StringVar(&f.toolTimeout, "tool-timeout", "", "timeout per external tool, e.g. 10m")
	fl.StringVar(&f.scanTimeout, "scan-timeout", "", "global scan timeout, e.g. 30m")
	fl.Int64Var(&f.maxFileSize, "max-file-size", 0, "skip files larger than this many bytes")
	return cmd
}

func runScan(cmd *cobra.Command, g *globalFlags, f *scanFlags, args []string) error {
	cfg, err := config.Load(f.configFile)
	if err != nil {
		return &exitError{ExitConfig, err}
	}
	if err := applyScanFlags(cmd, f, &cfg); err != nil {
		return &exitError{ExitConfig, err}
	}
	if g.noColor {
		cfg.NoColor = true
	}
	if err := cfg.Validate(); err != nil {
		return &exitError{ExitConfig, err}
	}
	target := "."
	if len(args) == 1 {
		target = args[0]
	}
	if f.repo != "" && len(args) == 1 {
		return &exitError{ExitConfig, errors.New("use either a path or --repo, not both")}
	}

	if cfg.Active.Allowed {
		fmt.Fprintf(os.Stderr, legalWarning, cfg.Active.TargetURL)
		if !cfg.Active.Authorized {
			if !confirmInteractive() {
				return &exitError{ExitConfig, errors.New("active scan not confirmed: pass --i-have-authorization or type 'yes' when prompted")}
			}
			cfg.Active.Authorized = true
		}
	}

	log := g.logger(os.Stderr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := app.Options{Target: target, RepoURL: f.repo, Log: log}
	if !g.quiet {
		opts.Progress = progressPrinter(os.Stderr)
	}
	rep, err := app.Scan(ctx, &cfg, opts)
	if err != nil {
		return &exitError{codeFor(err), err}
	}
	out := os.Stdout
	if g.quiet {
		// keep table out of quiet runs; file formats are still written
		var keep []string
		for _, ff := range cfg.Formats {
			if ff != "table" {
				keep = append(keep, ff)
			}
		}
		cfg.Formats = keep
	}
	written, err := app.WriteOutputs(rep, &cfg, out)
	if err != nil {
		return &exitError{ExitError, err}
	}
	// Offer the Markdown report when the user did not choose formats and
	// someone is at the keyboard (never blocks CI or piped runs).
	if !g.quiet && !cmd.Flags().Changed("format") && !slices.Contains(cfg.Formats, "md") && isTerminal(os.Stdin) && isTerminal(os.Stderr) {
		path := app.MarkdownPath(&cfg)
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if askYesNo(fmt.Sprintf("\n¿Generar el informe en Markdown en %s? [S/n]: ", path), true) {
			if err := report.WriteMarkdown(rep, path); err != nil {
				return &exitError{ExitError, fmt.Errorf("write md report: %w", err)}
			}
			written = append(written, path)
		}
	}
	if !g.quiet {
		for _, p := range written {
			fmt.Fprintln(os.Stderr, "report written:", p)
		}
	}
	if rep.Summary.Gate.Failed {
		return &exitError{code: ExitFindings}
	}
	return nil
}

// progressPrinter writes step messages to w, prefixed with the elapsed time.
// Progress goes to stderr so stdout keeps only the report table.
func progressPrinter(w io.Writer) func(string, ...any) {
	start := time.Now()
	var mu sync.Mutex
	return func(format string, args ...any) {
		el := time.Since(start)
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(w, "[%02d:%02d] %s\n", int(el.Minutes()), int(el.Seconds())%60, fmt.Sprintf(format, args...))
	}
}

func applyScanFlags(cmd *cobra.Command, f *scanFlags, cfg *config.Config) error {
	ch := cmd.Flags().Changed
	if ch("format") {
		cfg.Formats = f.formats
	}
	if ch("output") {
		cfg.Output = f.output
	}
	if ch("fail-on") {
		cfg.FailOn = f.failOn
	}
	if ch("baseline") {
		cfg.Baseline = f.baseline
	}
	if ch("diff") {
		cfg.DiffOnly = f.diff
	}
	if ch("offline") && ch("online") {
		return fmt.Errorf("%w: --offline and --online are mutually exclusive", config.ErrInvalid)
	}
	if ch("offline") {
		cfg.Offline = f.offline
	}
	if f.online {
		cfg.Offline = false
	}
	if ch("safe") {
		cfg.Safe = f.safe
	}
	if ch("allow-active-scan") {
		cfg.Active.Allowed = f.allowActive
	}
	if ch("target-url") {
		cfg.Active.TargetURL = f.targetURL
	}
	if ch("i-have-authorization") {
		cfg.Active.Authorized = f.authorized
	}
	// DAST needs the network to reach the target: it implies --online unless
	// the user explicitly asked for --offline (which Validate then rejects).
	if cfg.Active.Allowed && !ch("offline") {
		cfg.Offline = false
	}
	if cfg.Active.Allowed && ch("safe") && f.safe {
		return fmt.Errorf("%w: --safe and --allow-active-scan are mutually exclusive", config.ErrInvalid)
	}
	if ch("only") {
		cfg.Scanners.Only = f.only
	}
	if ch("disable") {
		cfg.Scanners.Disable = append(cfg.Scanners.Disable, f.disable...)
	}
	if ch("runner") {
		cfg.Scanners.Runner = f.runner
	}
	if f.noCache {
		cfg.Cache.Enabled = false
	}
	if f.noHistory {
		cfg.ScanGitHistory = false
	}
	if ch("rules") {
		cfg.CustomRules = f.customRules
	}
	if ch("ignore-file") {
		cfg.IgnoreFile = f.ignoreFile
	}
	if f.llmExplain {
		cfg.LLM.Enabled = true
	}
	if f.llmConsent {
		cfg.LLM.Consent = true
	}
	if ch("max-file-size") {
		cfg.Limits.MaxFileSizeBytes = f.maxFileSize
	}
	for name, dst := range map[string]*string{"tool-timeout": &f.toolTimeout, "scan-timeout": &f.scanTimeout} {
		if !ch(name) {
			continue
		}
		d, err := parseDuration(*dst)
		if err != nil {
			return fmt.Errorf("%w: --%s: %w", config.ErrInvalid, name, err)
		}
		if name == "tool-timeout" {
			cfg.Limits.ToolTimeout = d
		} else {
			cfg.Limits.ScanTimeout = d
		}
	}
	return nil
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// askYesNo prompts on stderr and reads one line from stdin. An empty answer
// returns def; it accepts s/si/sí/y/yes and n/no.
func askYesNo(prompt string, def bool) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return def
	case "s", "si", "sí", "y", "yes":
		return true
	default:
		return false
	}
}

func confirmInteractive() bool {
	st, err := os.Stdin.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	fmt.Fprint(os.Stderr, "Type 'yes' to confirm you are authorized to test this target: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "yes")
}
