// Package execx runs external tools safely: no shell, separated arguments,
// timeouts, bounded output, minimal environment and optional docker isolation.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
)

// Mode says how a tool is executed.
type Mode string

const (
	ModeNone   Mode = "none"
	ModeLocal  Mode = "local"
	ModeDocker Mode = "docker"
)

// Container paths used when running inside docker.
const (
	ContainerSrc   = "/src"
	ContainerOut   = "/out"
	ContainerCache = "/cache"
)

// Tool describes an external program.
type Tool struct {
	Name        string   // scanner name, e.g. "trivy"
	Binary      string   // executable name, e.g. "trivy"
	Image       string   // docker image, e.g. "aquasec/trivy:0.58.1"
	Entrypoint  []string // optional docker entrypoint override (first element) + leading args
	VersionArgs []string // args that print the version, e.g. ["--version"]
	InstallHint string   // human instructions shown when missing
}

// Resolution is the outcome of looking up a tool.
type Resolution struct {
	Mode    Mode   `json:"mode"`
	Path    string `json:"path,omitempty"`
	Image   string `json:"image,omitempty"`
	Version string `json:"version,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// Available reports whether the tool can be executed.
func (r Resolution) Available() bool { return r.Mode == ModeLocal || r.Mode == ModeDocker }

// Spec describes one invocation. Args may contain the placeholders
// {{src}}, {{out}} and {{cache}}, which are replaced with the host path
// (local mode) or the container path (docker mode).
type Spec struct {
	Args   []string
	SrcDir string // project root (mounted read-only in docker)
	OutDir string // optional writable directory for tool reports
	// ContainerOut overrides where OutDir is mounted in docker (default /out).
	ContainerOut string
	CacheDir     string            // optional persistent cache directory
	Env          map[string]string // extra env vars (also passed into docker)
	AcceptExit   []int             // exit codes that are not errors (0 always accepted)
	Network      bool              // allow network inside docker (ignored for local)
	Timeout      time.Duration
}

// Result holds process output.
type Result struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Truncated bool
	Duration  time.Duration
}

// Runner executes tools according to configuration.
type Runner struct {
	cfg       *config.Config
	log       *slog.Logger
	dockerMu  sync.Once
	dockerOK  bool
	dockerErr string
}

// NewRunner creates a Runner.
func NewRunner(cfg *config.Config, log *slog.Logger) *Runner {
	return &Runner{cfg: cfg, log: log}
}

// passthroughEnv are the only variables inherited from the parent process.
// Everything else (cloud credentials, tokens, ...) is NOT passed to tools.
var passthroughEnv = []string{
	"PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR",
	"SYSTEMROOT", "SystemRoot", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "WINDIR", "PROGRAMDATA", "ProgramFiles",
	"XDG_CACHE_HOME", "XDG_CONFIG_HOME", "LANG", "LC_ALL",
	"DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "DOCKER_CONTEXT",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// privacyEnv is always set for every tool: disables telemetry and update checks.
var privacyEnv = map[string]string{
	"SEMGREP_SEND_METRICS":          "off",
	"SEMGREP_ENABLE_VERSION_CHECK":  "0",
	"TRIVY_DISABLE_TELEMETRY":       "true",
	"TRIVY_SKIP_VERSION_CHECK":      "true",
	"CKV_SKIP_PACKAGE_UPDATE_CHECK": "true",
	"BC_SKIP_MAPPING":               "TRUE",
	"DISABLE_CRASH_REPORT":          "0",
	"GRYPE_CHECK_FOR_APP_UPDATE":    "false",
	"NO_COLOR":                      "1",
	"DO_NOT_TRACK":                  "1",
}

// Resolve finds how to execute tool according to the configured runner mode.
func (r *Runner) Resolve(ctx context.Context, t Tool) Resolution {
	sc := r.cfg.Scanners.For(t.Name)
	mode := sc.Runner
	if mode == "" || mode == config.RunnerAuto {
		mode = r.cfg.Scanners.Runner
	}
	image := t.Image
	if sc.Image != "" {
		image = sc.Image
	}
	bin := t.Binary
	if sc.Path != "" {
		bin = sc.Path
	}

	if mode == config.RunnerLocal || mode == config.RunnerAuto || mode == "" {
		if p, err := exec.LookPath(bin); err == nil {
			res := Resolution{Mode: ModeLocal, Path: p}
			res.Version = r.version(ctx, p, t.VersionArgs)
			return res
		}
		if mode == config.RunnerLocal {
			return Resolution{Mode: ModeNone, Reason: fmt.Sprintf("%q not found in PATH", bin)}
		}
	}
	if image == "" {
		return Resolution{Mode: ModeNone, Reason: fmt.Sprintf("%q not found in PATH and no docker image configured", bin)}
	}
	if ok, why := r.dockerAvailable(ctx); !ok {
		return Resolution{Mode: ModeNone, Reason: fmt.Sprintf("%q not in PATH; docker unavailable (%s)", bin, why)}
	}
	present := r.imagePresent(ctx, image)
	if !present && r.cfg.Offline {
		return Resolution{Mode: ModeNone, Image: image, Reason: fmt.Sprintf("%q not in PATH; docker image %s not pulled and --offline forbids pulling", bin, image)}
	}
	res := Resolution{Mode: ModeDocker, Image: image}
	if !present {
		res.Reason = "image will be pulled on first use"
	}
	return res
}

func (r *Runner) version(ctx context.Context, bin string, args []string) string {
	if len(args) == 0 {
		args = []string{"--version"}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // bin resolved via LookPath, args are constants
	cmd.Env = buildEnv(nil)
	out, _ := cmd.CombinedOutput()
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if len(line) > 120 {
		line = line[:120]
	}
	return line
}

func (r *Runner) dockerAvailable(ctx context.Context) (bool, string) {
	r.dockerMu.Do(func() {
		p, err := exec.LookPath("docker")
		if err != nil {
			r.dockerErr = "docker not in PATH"
			return
		}
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, p, "version", "--format", "{{.Server.Version}}") //nolint:gosec // constant args
		cmd.Env = buildEnv(nil)
		out, err := cmd.Output()
		if err != nil || len(bytes.TrimSpace(out)) == 0 {
			r.dockerErr = "docker daemon not reachable"
			return
		}
		r.dockerOK = true
	})
	return r.dockerOK, r.dockerErr
}

func (r *Runner) imagePresent(ctx context.Context, image string) bool {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", image) //nolint:gosec // image from config
	cmd.Env = buildEnv(nil)
	return cmd.Run() == nil
}

// Run executes the tool according to res.
func (r *Runner) Run(ctx context.Context, t Tool, res Resolution, s Spec) (*Result, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = r.cfg.Limits.ToolTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if len(s.Env) > 0 {
		env := make(map[string]string, len(s.Env))
		for k, v := range s.Env {
			if res.Mode == ModeDocker {
				env[k] = substitute([]string{v}, ContainerSrc, s.containerOut(), ContainerCache)[0]
			} else {
				env[k] = substitute([]string{v}, s.SrcDir, s.OutDir, s.CacheDir)[0]
			}
		}
		s.Env = env
	}

	var name string
	var args []string
	switch res.Mode {
	case ModeLocal:
		name = res.Path
		args = substitute(s.Args, s.SrcDir, s.OutDir, s.CacheDir)
	case ModeDocker:
		name = "docker"
		args = r.dockerArgs(t, res, s)
	default:
		return nil, fmt.Errorf("tool %s not available: %s", t.Name, res.Reason)
	}
	for _, a := range args {
		if strings.ContainsRune(a, 0) {
			return nil, errors.New("argument contains NUL byte")
		}
	}

	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // no shell; args are separated
	cmd.Env = buildEnv(s.Env)
	if res.Mode == ModeLocal && s.SrcDir != "" {
		cmd.Dir = s.SrcDir
	}
	limit := r.cfg.Limits.MaxToolOutputByte
	stdout := &limitedBuffer{max: limit}
	stderr := &limitedBuffer{max: 1 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 5 * time.Second

	r.log.Debug("running tool", "tool", t.Name, "mode", res.Mode, "cmd", name, "args", strings.Join(args, " "))
	start := time.Now()
	err := cmd.Run()
	out := &Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Truncated: stdout.truncated, Duration: time.Since(start)}
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s", t.Name, timeout)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			out.ExitCode = ee.ExitCode()
			for _, c := range s.AcceptExit {
				if c == out.ExitCode {
					return out, nil
				}
			}
			return out, fmt.Errorf("%s exited with code %d: %s", t.Name, out.ExitCode, tail(out.Stderr, 400))
		}
		return out, fmt.Errorf("%s failed: %w", t.Name, err)
	}
	if out.Truncated {
		return out, fmt.Errorf("%s output exceeded %d bytes", t.Name, limit)
	}
	return out, nil
}

func (r *Runner) dockerArgs(t Tool, res Resolution, s Spec) []string {
	args := []string{"run", "--rm", "--pull=missing", "--security-opt", "no-new-privileges", "--cap-drop", "ALL"}
	if r.cfg.Limits.DockerMemory != "" {
		args = append(args, "--memory", r.cfg.Limits.DockerMemory)
	}
	if !s.Network || r.cfg.Offline {
		args = append(args, "--network", "none")
	}
	if s.SrcDir != "" {
		args = append(args, "-v", dockerPath(s.SrcDir)+":"+ContainerSrc+":ro", "-w", ContainerSrc)
	}
	if s.OutDir != "" {
		args = append(args, "-v", dockerPath(s.OutDir)+":"+s.containerOut())
	}
	if s.CacheDir != "" {
		args = append(args, "-v", dockerPath(s.CacheDir)+":"+ContainerCache)
	}
	env := mergedToolEnv(s.Env)
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-e", k+"="+env[k])
	}
	if len(t.Entrypoint) > 0 {
		args = append(args, "--entrypoint", t.Entrypoint[0])
	}
	args = append(args, res.Image)
	if len(t.Entrypoint) > 1 {
		args = append(args, t.Entrypoint[1:]...)
	}
	return append(args, substitute(s.Args, ContainerSrc, s.containerOut(), ContainerCache)...)
}

func (s Spec) containerOut() string {
	if s.ContainerOut != "" {
		return s.ContainerOut
	}
	return ContainerOut
}

func dockerPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func substitute(args []string, src, out, cache string) []string {
	rep := strings.NewReplacer("{{src}}", src, "{{out}}", out, "{{cache}}", cache)
	res := make([]string, len(args))
	for i, a := range args {
		res[i] = rep.Replace(a)
	}
	return res
}

func mergedToolEnv(extra map[string]string) map[string]string {
	m := make(map[string]string, len(privacyEnv)+len(extra))
	for k, v := range privacyEnv {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func buildEnv(extra map[string]string) []string {
	var env []string
	seen := map[string]bool{}
	for _, k := range passthroughEnv {
		key := k
		if runtime.GOOS == "windows" {
			key = strings.ToUpper(k)
		}
		if seen[key] {
			continue
		}
		if v, ok := os.LookupEnv(k); ok {
			seen[key] = true
			env = append(env, k+"="+v)
		}
	}
	for k, v := range mergedToolEnv(extra) {
		env = append(env, k+"="+v)
	}
	return env
}

type limitedBuffer struct {
	buf       bytes.Buffer
	max       int64
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	remain := l.max - int64(l.buf.Len())
	if remain <= 0 {
		l.truncated = true
		return len(p), nil
	}
	if int64(len(p)) > remain {
		l.buf.Write(p[:remain])
		l.truncated = true
		return len(p), nil
	}
	return l.buf.Write(p)
}

func (l *limitedBuffer) Bytes() []byte { return l.buf.Bytes() }

func tail(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = "..." + s[len(s)-n:]
	}
	return s
}
