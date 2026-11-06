// Package cache stores normalized scanner results keyed by a hash of the
// scanned files, the tool version and the relevant configuration.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
)

// Store is a directory of JSON result files.
type Store struct {
	dir string
	ttl time.Duration
}

// DefaultDir returns the per-user cache directory.
func DefaultDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "secureprojects")
}

// New opens (and creates) a cache store. Entries older than 24h are ignored
// so that vulnerability data never gets too stale.
func New(dir string) (*Store, error) {
	if dir == "" {
		dir = filepath.Join(DefaultDir(), "results")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, ttl: 24 * time.Hour}, nil
}

// Key derives a cache key from arbitrary parts.
func Key(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = io.WriteString(h, p)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ConfigHash hashes the configuration that can influence a scanner's output.
func ConfigHash(c *config.Config, scanner string) string {
	b, _ := json.Marshal(struct {
		S       config.ScannerConfig
		Offline bool
		Exclude []string
		Limits  int64
		Custom  string
		History bool
	}{c.Scanners.For(scanner), c.Offline, c.Exclude, c.Limits.MaxFileSizeBytes, c.CustomRules, c.ScanGitHistory})
	return Key(string(b), fileHash(c.CustomRules))
}

// TreeHash hashes the content of files (sorted relative paths). Empty on error.
func TreeHash(root string, files []string) string {
	h := sha256.New()
	for _, rel := range files {
		_, _ = io.WriteString(h, rel)
		_, _ = h.Write([]byte{0})
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel))) //nolint:gosec // controlled path
		if err != nil {
			return ""
		}
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return ""
		}
	}
	// Include git HEAD so history-based scanners are invalidated by new commits.
	if b, err := os.ReadFile(filepath.Join(root, ".git", "HEAD")); err == nil { //nolint:gosec // controlled path
		_, _ = h.Write(b)
		ref := strings.TrimSpace(strings.TrimPrefix(string(b), "ref:"))
		if rb, err := os.ReadFile(filepath.Join(root, ".git", filepath.FromSlash(ref))); err == nil { //nolint:gosec // controlled path
			_, _ = h.Write(rb)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func fileHash(p string) string {
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p) //nolint:gosec // user-configured path
	if err != nil {
		return ""
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Get returns cached findings.
func (s *Store) Get(key string) ([]finding.Finding, bool) {
	p := filepath.Join(s.dir, key+".json")
	st, err := os.Stat(p)
	if err != nil || time.Since(st.ModTime()) > s.ttl {
		return nil, false
	}
	b, err := os.ReadFile(p) //nolint:gosec // inside cache dir
	if err != nil {
		return nil, false
	}
	var fs []finding.Finding
	if err := json.Unmarshal(b, &fs); err != nil {
		return nil, false
	}
	return fs, true
}

// Put stores findings atomically. Findings are already redacted.
func (s *Store) Put(key string, fs []finding.Finding) error {
	if fs == nil {
		fs = []finding.Finding{}
	}
	b, err := json.Marshal(fs)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, "tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	dst := filepath.Join(s.dir, key+".json")
	if err := os.Rename(tmp.Name(), dst); err != nil {
		_ = os.Remove(tmp.Name())
		return errors.Join(err)
	}
	return nil
}
