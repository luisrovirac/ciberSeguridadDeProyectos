// Package cli implements the secureprojects command line interface.
package cli

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/secureprojects/secureprojects/internal/config"
	"github.com/secureprojects/secureprojects/internal/redact"
)

// Exit codes (documented in README).
const (
	ExitOK       = 0 // no findings above the threshold
	ExitFindings = 1 // findings above the --fail-on threshold
	ExitError    = 2 // runtime error
	ExitConfig   = 3 // invalid configuration / usage
)

// ExitError carries a process exit code.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

type globalFlags struct {
	logLevel  string
	logFormat string
	noColor   bool
	quiet     bool
}

// NewRootCmd builds the command tree.
func NewRootCmd() *cobra.Command {
	g := &globalFlags{}
	root := &cobra.Command{
		Use:   "secureprojects",
		Short: "SecureProjects — offline-first security scanner orchestrator",
		Long: `SecureProjects scans local projects and Git repositories for known vulnerabilities
(CVEs in dependencies, IaC and container misconfigurations) and potential risks
(secrets, insecure patterns, unpinned dependencies). It combines built-in analyzers
with external open source tools (Trivy, OSV-Scanner, Gitleaks, Semgrep, Hadolint,
kube-linter, Checkov, KICS, Bandit, ZAP) when they are available.

No telemetry. No source code is sent anywhere. Only scan projects you own or are
authorized to test.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&g.logLevel, "log-level", "warn", "log level: debug|info|warn|error")
	root.PersistentFlags().StringVar(&g.logFormat, "log-format", "text", "log format: text|json")
	root.PersistentFlags().BoolVar(&g.noColor, "no-color", false, "disable colored output (also honors NO_COLOR)")
	root.PersistentFlags().BoolVarP(&g.quiet, "quiet", "q", false, "only print errors")

	root.AddCommand(newScanCmd(g), newToolsCmd(g), newReportCmd(g), newDBCmd(g), newVersionCmd())
	return root
}

func (g *globalFlags) logger(w io.Writer) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(g.logLevel) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelWarn
	}
	if g.quiet {
		lvl = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler = slog.NewTextHandler(w, opts)
	if g.logFormat == "json" {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(redact.NewHandler(h))
}

// Execute runs the CLI with os.Args and returns the process exit code.
func Execute() int { return Run(os.Args[1:]) }

// Run executes the CLI with explicit arguments and returns the exit code.
func Run(args []string) int {
	cmd := NewRootCmd()
	cmd.SetArgs(args)
	err := cmd.Execute()
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			fmt.Fprintln(os.Stderr, "error:", redact.String(ee.err.Error()))
		}
		return ee.code
	}
	fmt.Fprintln(os.Stderr, "error:", redact.String(err.Error()))
	if config.IsInvalid(err) || isUsageError(err) {
		return ExitConfig
	}
	return ExitError
}

func isUsageError(err error) bool {
	s := err.Error()
	return strings.HasPrefix(s, "unknown flag") || strings.HasPrefix(s, "unknown command") ||
		strings.Contains(s, "invalid argument") || strings.Contains(s, "accepts ") ||
		strings.HasPrefix(s, "flag needs an argument") || strings.HasPrefix(s, "unknown shorthand")
}

func codeFor(err error) int {
	if config.IsInvalid(err) {
		return ExitConfig
	}
	return ExitError
}
