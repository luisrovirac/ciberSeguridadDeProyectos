// Package gitinfo reads repository metadata and performs safe temporary clones.
package gitinfo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Info describes the scanned repository.
type Info struct {
	Commit string
	Branch string
	Remote string // credentials stripped
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	full := append([]string{"-C", dir, "-c", "safe.directory=*"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...) //nolint:gosec // fixed git subcommands
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// Read returns commit/branch/remote. Missing git or non-repositories yield empty fields.
func Read(ctx context.Context, dir string) Info {
	var i Info
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return i
	}
	i.Commit, _ = git(ctx, dir, "rev-parse", "HEAD")
	if b, err := git(ctx, dir, "rev-parse", "--abbrev-ref", "HEAD"); err == nil && b != "HEAD" {
		i.Branch = b
	}
	if r, err := git(ctx, dir, "config", "--get", "remote.origin.url"); err == nil {
		i.Remote = StripCredentials(r)
	}
	if i.Commit == "" { // git binary missing: read HEAD by hand
		if b, err := os.ReadFile(filepath.Join(dir, ".git", "HEAD")); err == nil { //nolint:gosec // repo path
			head := strings.TrimSpace(string(b))
			if ref, ok := strings.CutPrefix(head, "ref: "); ok {
				i.Branch = strings.TrimPrefix(ref, "refs/heads/")
				if rb, err := os.ReadFile(filepath.Join(dir, ".git", filepath.FromSlash(ref))); err == nil { //nolint:gosec // repo path
					i.Commit = strings.TrimSpace(string(rb))
				}
			} else {
				i.Commit = head
			}
		}
	}
	return i
}

// StripCredentials removes user:password@ from URLs.
func StripCredentials(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return raw
	}
	u.User = nil
	return u.String()
}

var scpLikeRe = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._~/-]+$`)

// ValidateRepoURL accepts only https://, ssh:// and scp-like git@host:path URLs.
// It rejects option injection ("-..."), local paths, file:// and ext:: transports.
func ValidateRepoURL(raw string) error {
	if raw == "" || strings.HasPrefix(raw, "-") || strings.ContainsAny(raw, " \t\r\n\x00") {
		return errors.New("invalid repository URL")
	}
	if scpLikeRe.MatchString(raw) {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid repository URL: %w", err)
	}
	switch u.Scheme {
	case "https", "ssh":
		if u.Host == "" {
			return errors.New("repository URL has no host")
		}
		return nil
	case "http":
		return errors.New("plain http:// repositories are not allowed (use https://)")
	default:
		return fmt.Errorf("repository URL scheme %q is not allowed (use https://, ssh:// or git@host:path)", u.Scheme)
	}
}

// Clone performs a hardened clone into a new temporary directory.
// The caller must call the returned cleanup function (also on error paths).
func Clone(ctx context.Context, repoURL string, fullHistory bool, timeout time.Duration) (dir string, cleanup func(), err error) {
	if err := ValidateRepoURL(repoURL); err != nil {
		return "", func() {}, err
	}
	if _, err := exec.LookPath("git"); err != nil {
		return "", func() {}, errors.New("git is required for --repo but was not found in PATH")
	}
	tmp, err := os.MkdirTemp("", "secureprojects-clone-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup = func() { _ = RemoveAll(tmp) }
	dst := filepath.Join(tmp, "repo")
	args := []string{
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=never",
		"-c", "core.symlinks=false",
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "core.fsmonitor=false",
		"-c", "transfer.fsckObjects=true",
		"clone", "--no-recurse-submodules", "--quiet",
	}
	if !fullHistory {
		args = append(args, "--depth", "1")
	}
	args = append(args, "--", repoURL, dst)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", args...) //nolint:gosec // validated URL, "--" separator
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never", "GIT_LFS_SKIP_SMUDGE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("git clone failed: %w: %s", err, StripCredentials(strings.TrimSpace(string(out))))
	}
	return dst, cleanup, nil
}

// RemoveAll deletes a tree, clearing read-only bits first (Git object files
// are read-only on Windows, which makes os.RemoveAll fail).
func RemoveAll(dir string) error {
	if err := os.RemoveAll(dir); err == nil {
		return nil
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil {
			_ = os.Chmod(p, 0o700) //nolint:gosec // only to allow deleting read-only git objects
		}
		return nil
	})
	return os.RemoveAll(dir)
}
