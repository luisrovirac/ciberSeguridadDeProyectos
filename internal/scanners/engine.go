package scanners

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/cache"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/execx"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/fsutil"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/redact"
)

// Engine runs the relevant scanners concurrently with bounded parallelism.
type Engine struct {
	Scanners []Scanner
	Cache    *cache.Store // may be nil
	// Notify receives human-readable progress messages (may be nil).
	Notify func(format string, args ...any)
	// Heartbeat is how often Notify lists the scanners still running
	// (default 15s; negative disables it).
	Heartbeat time.Duration
}

func (e *Engine) notify(format string, args ...any) {
	if e.Notify != nil {
		e.Notify(format, args...)
	}
}

// ListFiles builds Request.Files honoring excludes and limits.
func ListFiles(req *Request) error {
	var files []string
	err := fsutil.Walk(req.Root, req.Config.Exclude, req.Config.Limits.MaxFiles, func(rel string, d fs.DirEntry) error {
		if info, err := d.Info(); err == nil && info.Size() > req.Config.Limits.MaxFileSizeBytes {
			return nil
		}
		files = append(files, rel)
		return nil
	})
	if err != nil && !errors.Is(err, fsutil.ErrTooManyFiles) {
		return err
	}
	if errors.Is(err, fsutil.ErrTooManyFiles) {
		req.Log.Warn("file limit reached; native analyzers will only see part of the project", "max_files", req.Config.Limits.MaxFiles)
	}
	sort.Strings(files)
	req.Files = files
	return nil
}

// Selected decides whether a scanner should run, and why not otherwise.
func Selected(s Scanner, req *Request) (bool, string, string) {
	cfg := req.Config
	name := s.Name()
	if len(cfg.Scanners.Only) > 0 && !slices.Contains(cfg.Scanners.Only, name) {
		return false, StatusDisabled, "not in scanners.only"
	}
	if slices.Contains(cfg.Scanners.Disable, name) || !cfg.Scanners.For(name).IsEnabled(true) {
		return false, StatusDisabled, "disabled by configuration"
	}
	if !s.Applicable(req.Profile, cfg) {
		return false, StatusNotApplicable, "no relevant files detected"
	}
	return true, "", ""
}

// Run executes every selected scanner. Errors in one scanner never abort the
// others; they are reported in the returned statuses.
func (e *Engine) Run(ctx context.Context, req *Request) ([]finding.Finding, []Status) {
	var (
		mu       sync.Mutex
		all      []finding.Finding
		statuses = make([]Status, len(e.Scanners))
	)
	treeHash := ""
	if e.Cache != nil {
		e.notify("Calculando huella de %d archivos para la caché...", len(req.Files))
		treeHash = cache.TreeHash(req.Root, req.Files)
	}

	selected := make([]bool, len(e.Scanners))
	var names []string
	for i, s := range e.Scanners {
		st := Status{Name: s.Name(), Native: s.Native()}
		ok, status, msg := Selected(s, req)
		if !ok {
			st.Status, st.Message = status, msg
			statuses[i] = st
			continue
		}
		selected[i] = true
		names = append(names, s.Name())
	}
	e.notify("Ejecutando %d de %d analizadores: %s", len(names), len(e.Scanners), strings.Join(names, ", "))

	// Track running scanners so a periodic message shows what is still busy.
	running := map[string]time.Time{}
	var done atomic.Int32
	stopBeat := e.startHeartbeat(&mu, running, &done, len(names))
	defer stopBeat()

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(req.Config.Limits.Concurrency)
	for i, s := range e.Scanners {
		if !selected[i] {
			continue
		}
		st := Status{Name: s.Name(), Native: s.Native()}
		g.Go(func() error {
			start := time.Now()
			mu.Lock()
			running[s.Name()] = start
			mu.Unlock()
			e.notify("  -> %s: iniciando", s.Name())
			fs, st := e.runOne(gctx, s, req, st, treeHash)
			st.DurationMs = time.Since(start).Milliseconds()
			st.Findings = len(fs)
			mu.Lock()
			all = append(all, fs...)
			statuses[i] = st
			delete(running, s.Name())
			mu.Unlock()
			n := done.Add(1)
			e.notify("  [%d/%d] %s", n, len(names), describe(st))
			return nil // never fail the group: one broken tool must not stop the scan
		})
	}
	_ = g.Wait()
	return all, statuses
}

// startHeartbeat periodically reports which scanners are still running, so a
// long tool run is not mistaken for a hang. The returned func stops it.
func (e *Engine) startHeartbeat(mu *sync.Mutex, running map[string]time.Time, done *atomic.Int32, total int) func() {
	every := e.Heartbeat
	if every == 0 {
		every = 15 * time.Second
	}
	if e.Notify == nil || every < 0 {
		return func() {}
	}
	stop := make(chan struct{})
	t := time.NewTicker(every)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				mu.Lock()
				var busy []string
				for name, since := range running {
					busy = append(busy, fmt.Sprintf("%s (%s)", name, time.Since(since).Round(time.Second)))
				}
				mu.Unlock()
				if len(busy) == 0 {
					continue
				}
				sort.Strings(busy)
				e.notify("  ... %d/%d terminados; en curso: %s", done.Load(), total, strings.Join(busy, ", "))
			}
		}
	}()
	return func() { close(stop) }
}

// describe renders one finished scanner status as a short progress line.
func describe(st Status) string {
	d := (time.Duration(st.DurationMs) * time.Millisecond).Round(100 * time.Millisecond)
	switch st.Status {
	case StatusOK:
		return fmt.Sprintf("%s: ok, %d hallazgo(s) en %s", st.Name, st.Findings, d)
	case StatusCached:
		return fmt.Sprintf("%s: %d hallazgo(s) desde la caché", st.Name, st.Findings)
	case StatusSkipped:
		return fmt.Sprintf("%s: omitido (%s)", st.Name, st.Message)
	case StatusError:
		return fmt.Sprintf("%s: ERROR tras %s (%s)", st.Name, d, st.Message)
	default:
		return fmt.Sprintf("%s: %s", st.Name, st.Status)
	}
}

func (e *Engine) runOne(ctx context.Context, s Scanner, req *Request, st Status, treeHash string) (out []finding.Finding, _ Status) {
	defer func() {
		if r := recover(); r != nil {
			req.Log.Error("scanner panicked", "scanner", s.Name(), "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			st.Status, st.Message = StatusError, fmt.Sprintf("internal error: %v", r)
			out = nil
		}
	}()

	res := execx.Resolution{Mode: execx.ModeLocal}
	if t := s.Tool(); t != nil {
		res = req.Exec.Resolve(ctx, *t)
		st.Mode, st.Version = string(res.Mode), res.Version
		if res.Image != "" && res.Mode == execx.ModeDocker {
			st.Version = res.Image
		}
		if !res.Available() {
			st.Status = StatusSkipped
			st.Message = res.Reason
			st.InstallHint = t.InstallHint
			req.Log.Info("tool not available, skipping", "scanner", s.Name(), "reason", res.Reason)
			return nil, st
		}
	} else {
		st.Mode = "native"
	}

	key, cacheable := "", e.Cache != nil && treeHash != ""
	if cacheable {
		extra, ok := "", true
		if ck, isCK := s.(CacheKeyer); isCK {
			extra, ok = ck.CacheKey(req)
		}
		cacheable = ok
		key = cache.Key(s.Name(), st.Version, string(res.Mode), extra, treeHash, cache.ConfigHash(req.Config, s.Name()))
		if cacheable {
			if cached, hit := e.Cache.Get(key); hit {
				st.Status, st.Message = StatusCached, "results reused from cache"
				return cached, st
			}
		}
	}

	req.Log.Info("running scanner", "scanner", s.Name(), "mode", st.Mode)
	fs, err := s.Scan(ctx, req, res)
	for i := range fs {
		f := &fs[i]
		if len(f.Tools) == 0 {
			f.Tools = []string{s.Name()}
		}
		f.Evidence = redact.String(f.Evidence)
		f.Description = redact.String(f.Description)
		f.Title = redact.String(f.Title)
		f.Normalize()
		if f.Fingerprint == "" {
			f.Fingerprint = f.ComputeFingerprint()
		}
	}
	valid := fs[:0]
	for _, f := range fs {
		if verr := f.Validate(); verr != nil {
			req.Log.Warn("dropping invalid finding", "scanner", s.Name(), "error", verr)
			continue
		}
		valid = append(valid, f)
	}
	fs = valid
	var skip *SkipError
	if errors.As(err, &skip) {
		st.Status, st.Message = StatusSkipped, skip.Reason
		req.Log.Info("scanner skipped", "scanner", s.Name(), "reason", skip.Reason)
		return fs, st
	}
	if err != nil {
		st.Status = StatusError
		st.Message = redact.String(err.Error())
		req.Log.Warn("scanner failed", "scanner", s.Name(), "error", st.Message)
		return fs, st // keep partial results
	}
	st.Status = StatusOK
	if cacheable {
		if err := e.Cache.Put(key, fs); err != nil {
			req.Log.Debug("cache write failed", "error", err)
		}
	}
	return fs, st
}
