// Package scanners defines the Scanner interface implemented by every
// adapter (external tools) and native analyzer, plus the concurrent engine.
package scanners

import (
	"context"
	"log/slog"

	"github.com/secureprojects/secureprojects/internal/config"
	"github.com/secureprojects/secureprojects/internal/detector"
	"github.com/secureprojects/secureprojects/internal/execx"
	"github.com/secureprojects/secureprojects/internal/finding"
)

// Request carries everything a scanner needs. Scanners must treat it as read-only.
type Request struct {
	Root    string // absolute project root
	Profile *detector.Profile
	Config  *config.Config
	Exec    *execx.Runner
	Log     *slog.Logger
	// Files lists the relative (forward-slash) paths of files within limits
	// and not excluded; native analyzers should iterate it instead of walking.
	Files []string
	// WorkDir is a private temporary directory for tool outputs.
	WorkDir string
	// Commit is the scanned git commit, if known.
	Commit string
}

// Scanner is implemented by every adapter and native analyzer.
type Scanner interface {
	// Name is a stable identifier, used in config and reports.
	Name() string
	// Native reports whether this scanner is built-in (no external tool).
	Native() bool
	// Applicable decides whether the scanner is relevant for the project.
	Applicable(p *detector.Profile, cfg *config.Config) bool
	// Tool returns the external tool description, nil for native scanners.
	Tool() *execx.Tool
	// Scan runs the analysis. res is the resolved execution mode for external tools.
	Scan(ctx context.Context, req *Request, res execx.Resolution) ([]finding.Finding, error)
}

// CacheKeyer can be implemented to add scanner-specific inputs to the cache
// key (for example the vulnerability database timestamp). Returning
// ok=false disables caching for this run.
type CacheKeyer interface {
	CacheKey(req *Request) (key string, ok bool)
}

// SkipError signals that a scanner could not run for an expected reason
// (missing database, nothing to scan, ...). It is reported as "skipped".
type SkipError struct{ Reason string }

func (e *SkipError) Error() string { return e.Reason }

// Skip returns a SkipError.
func Skip(reason string) error { return &SkipError{Reason: reason} }

// Status values reported per scanner.
const (
	StatusOK            = "ok"
	StatusCached        = "cached"
	StatusSkipped       = "skipped"
	StatusError         = "error"
	StatusNotApplicable = "not-applicable"
	StatusDisabled      = "disabled"
)

// Status is the per-scanner execution report embedded in reports.
type Status struct {
	Name        string `json:"name"`
	Native      bool   `json:"native"`
	Status      string `json:"status"`
	Mode        string `json:"mode,omitempty"`
	Version     string `json:"version,omitempty"`
	Message     string `json:"message,omitempty"`
	InstallHint string `json:"installHint,omitempty"`
	Findings    int    `json:"findings"`
	DurationMs  int64  `json:"durationMs"`
}
