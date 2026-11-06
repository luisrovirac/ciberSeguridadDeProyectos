// Package app wires detection, scanning, normalization, policy and
// reporting into the end-to-end scan pipeline used by the CLI.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/cache"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/dedup"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/detector"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/execx"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/gitinfo"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/llm"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/policy"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/report"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/native"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/registry"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scoring"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/version"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/vulndb"
)

// Options are the per-invocation inputs that are not part of Config.
type Options struct {
	Target  string // local directory
	RepoURL string // optional remote repository to clone
	Log     *slog.Logger
	// Scanners overrides the registry (tests).
	Scanners []scanners.Scanner
	// Explainer overrides the LLM client (tests).
	Explainer llm.Explainer
	// Now overrides the clock (tests).
	Now func() time.Time
	// Progress receives human-readable step messages for the user (may be nil).
	Progress func(format string, args ...any)
}

// ErrConfig marks configuration/usage errors (exit code 3).
var ErrConfig = config.ErrInvalid

// Scan runs the full pipeline and returns the report.
func Scan(ctx context.Context, cfg *config.Config, opts Options) (*report.Report, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	log := opts.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	started := now().UTC()
	step := opts.Progress
	if step == nil {
		step = func(string, ...any) {}
	}

	target, targetType, repoDisplay := opts.Target, "local", ""
	if opts.RepoURL != "" {
		step("Clonando el repositorio %s...", gitinfo.StripCredentials(opts.RepoURL))
		log.Info("cloning repository into a temporary directory", "url", gitinfo.StripCredentials(opts.RepoURL))
		dir, cleanup, err := gitinfo.Clone(ctx, opts.RepoURL, cfg.ScanGitHistory, cfg.Limits.ToolTimeout)
		defer cleanup() // always remove the clone, even on errors
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: %w", ErrConfig, err)
		}
		target, targetType, repoDisplay = dir, "repository", gitinfo.StripCredentials(opts.RepoURL)
	}
	if target == "" {
		target = "."
	}
	root, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%w: scan target %q is not a readable directory", ErrConfig, target)
	}

	step("Iniciando el escaneo de %s", root)
	step("Detectando lenguajes, dependencias e infraestructura...")
	profile, err := detector.Detect(root, cfg.Exclude, cfg.Limits.MaxFiles)
	if err != nil {
		return nil, err
	}
	step("Detectado: %s", describeProfile(profile))
	git := gitinfo.Read(ctx, root)
	if repoDisplay == "" {
		repoDisplay = git.Remote
	}

	var custom []native.PatternRule
	if cfg.CustomRules != "" {
		custom, err = native.LoadCustomRules(resolve(root, cfg.CustomRules))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConfig, err)
		}
	}
	ignores, err := policy.LoadIgnoreFile(resolve(root, cfg.IgnoreFile))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	var baseline map[string]bool
	if cfg.Baseline != "" {
		if baseline, err = policy.LoadBaseline(cfg.Baseline); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConfig, err)
		}
	}

	work, err := os.MkdirTemp("", "secureprojects-work-*")
	if err != nil {
		return nil, err
	}
	defer gitinfo.RemoveAll(work) //nolint:errcheck // best effort

	req := &scanners.Request{
		Root: root, Profile: profile, Config: cfg, Exec: execx.NewRunner(cfg, log), Log: log,
		WorkDir: work, Commit: git.Commit,
	}
	step("Listando archivos a analizar...")
	if err := scanners.ListFiles(req); err != nil {
		return nil, err
	}
	step("%d archivos a analizar", len(req.Files))

	list := opts.Scanners
	if list == nil {
		dbDir := cfg.VulnDB.Dir
		if dbDir == "" {
			dbDir = vulndb.DefaultDir()
		}
		list = registry.All(dbDir, custom)
	}
	eng := &scanners.Engine{Scanners: list, Notify: opts.Progress}
	if cfg.Cache.Enabled && !cfg.Active.Allowed {
		if st, err := cache.New(cfg.Cache.Dir); err == nil {
			eng.Cache = st
		} else {
			log.Warn("cache disabled", "error", err)
		}
	}

	sctx, cancel := context.WithTimeout(ctx, cfg.Limits.ScanTimeout)
	defer cancel()
	raw, statuses := eng.Run(sctx, req)
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil, ctx.Err()
	}
	var warnings []string
	if sctx.Err() == context.DeadlineExceeded {
		warnings = append(warnings, fmt.Sprintf("global scan timeout (%s) reached; results are partial", cfg.Limits.ScanTimeout))
	}
	if profile.Truncated {
		warnings = append(warnings, fmt.Sprintf("file limit (%d) reached; native analyzers saw only part of the project", cfg.Limits.MaxFiles))
	}
	for _, s := range statuses {
		if s.Name == "native-osv" && s.Status == scanners.StatusSkipped && !anyOK(statuses, "osv-scanner", "trivy") {
			warnings = append(warnings, "dependency CVE scanning not available: run 'secureprojects db update' (one-time download of the public OSV database) or install osv-scanner/trivy. 0 dependency vulnerabilities does NOT mean none exist.")
		}
	}

	step("Analizadores terminados. Unificando y puntuando %d hallazgo(s)...", len(raw))
	fs := dedup.Merge(raw)
	policy.MarkKnownFalsePositives(fs)
	if expired := policy.ApplyIgnores(fs, ignores, now()); expired > 0 {
		warnings = append(warnings, fmt.Sprintf("%d ignore rule(s) expired and were not applied", expired))
	}
	scoring.ScoreAll(fs)
	dedup.Sort(fs)
	if baseline != nil {
		policy.MarkNew(fs, baseline)
		if cfg.DiffOnly {
			fs = policy.OnlyNew(fs)
		}
	}

	if cfg.LLM.Enabled && cfg.LLM.Consent {
		ex := opts.Explainer
		if ex == nil {
			ex = llm.NewAnthropic(cfg.LLM)
		}
		step("Pidiendo explicaciones al LLM...")
		n := llm.Enrich(ctx, cfg.LLM, ex, fs, log)
		log.Info("LLM explanations added (non-authoritative)", "count", n)
	}

	failing := policy.Gate(fs, cfg.FailOn, finding.ParseConfidence(cfg.FailOnPotentialMinConfidence))
	sum := report.Summarize(fs)
	sum.Gate = report.Gate{FailOn: cfg.FailOn, Failed: len(failing) > 0, FailingCount: len(failing)}

	finished := now().UTC()
	step("Escaneo completado en %s: %d hallazgo(s)", finished.Sub(started).Round(time.Second), len(fs))
	red := cfg.Redacted()
	displayTarget := target
	if targetType == "repository" {
		displayTarget = repoDisplay
	}
	return &report.Report{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.ToolInfo{Name: "SecureProjects", Version: version.Version, Commit: version.Commit, URL: version.URL},
		Scan: report.ScanInfo{
			StartedAt: started, FinishedAt: finished, DurationMs: finished.Sub(started).Milliseconds(),
			Target: displayTarget, TargetType: targetType, Repository: repoDisplay,
			Commit: git.Commit, Branch: git.Branch, Offline: cfg.Offline, Safe: cfg.Safe, ActiveScan: cfg.Active.Allowed,
			Profile: profile, Config: &red, Scanners: statuses, Warnings: warnings,
		},
		Summary:    sum,
		Findings:   fs,
		Disclaimer: report.Disclaimer,
	}, nil
}

// describeProfile summarizes what the detector found in one line.
func describeProfile(p *detector.Profile) string {
	var parts []string
	if len(p.Languages) > 0 {
		parts = append(parts, "lenguajes "+strings.Join(p.Languages, ", "))
	}
	if len(p.Ecosystems) > 0 {
		parts = append(parts, "ecosistemas "+strings.Join(p.Ecosystems, ", "))
	}
	for _, x := range []struct {
		name string
		n    int
	}{{"Dockerfile", len(p.Dockerfile)}, {"compose", len(p.Compose)}, {"Terraform", len(p.Terraform)},
		{"Kubernetes", len(p.K8s)}, {"Helm", len(p.Helm)}, {"CloudFormation", len(p.CloudForm)}} {
		if x.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", x.n, x.name))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d archivos, sin lenguajes reconocidos", p.FileCount)
	}
	return fmt.Sprintf("%d archivos; %s", p.FileCount, strings.Join(parts, "; "))
}

func anyOK(st []scanners.Status, names ...string) bool {
	for _, s := range st {
		for _, n := range names {
			if s.Name == n && (s.Status == scanners.StatusOK || s.Status == scanners.StatusCached) {
				return true
			}
		}
	}
	return false
}

// resolve makes a relative path relative to the scan root when it does not
// exist relative to the working directory.
func resolve(root, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return filepath.Join(root, p)
}

// MarkdownPath is where the Markdown report goes: the current directory
// when the output directory was left at its default, cfg.Output otherwise.
func MarkdownPath(cfg *config.Config) string {
	dir := cfg.Output
	if dir == config.Default().Output {
		dir = "."
	}
	return filepath.Join(dir, "secureprojects-report.md")
}

// WriteOutputs renders the requested formats. "table" goes to stdout,
// "md" to MarkdownPath, the rest to files in cfg.Output. Returns the
// written file paths.
func WriteOutputs(r *report.Report, cfg *config.Config, stdout *os.File) ([]string, error) {
	var written []string
	for _, f := range cfg.Formats {
		var err error
		var p string
		switch f {
		case "table":
			report.WriteTable(stdout, r, report.ColorEnabled(stdout, cfg.NoColor), 50)
			continue
		case "json":
			p = filepath.Join(cfg.Output, "secureprojects-report.json")
			err = report.WriteJSON(r, p)
		case "sarif":
			p = filepath.Join(cfg.Output, "secureprojects-report.sarif")
			err = report.WriteSARIF(r, p)
		case "html":
			p = filepath.Join(cfg.Output, "secureprojects-report.html")
			err = report.WriteHTML(r, p)
		case "md":
			p = MarkdownPath(cfg)
			err = report.WriteMarkdown(r, p)
		}
		if err != nil {
			return written, fmt.Errorf("write %s report: %w", f, err)
		}
		written = append(written, p)
	}
	return written, nil
}
