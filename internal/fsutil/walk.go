// Package fsutil provides a bounded, symlink-safe directory walker with glob excludes.
package fsutil

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrTooManyFiles is returned when the walker hits the file-count limit.
var ErrTooManyFiles = errors.New("file limit reached")

// WalkFunc receives the forward-slash relative path of each regular file.
type WalkFunc func(rel string, d fs.DirEntry) error

// Walk visits regular files under root, skipping excluded globs and never
// following symlinks (so a scan can't escape the project root).
func Walk(root string, excludes []string, maxFiles int, fn WalkFunc) error {
	count := 0
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil //nolint:nilerr // unreadable entry: skip it, keep walking
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil //nolint:nilerr // path outside root (cannot happen with WalkDir): skip
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || Excluded(rel+"/", excludes) || Excluded(rel, excludes) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || Excluded(rel, excludes) {
			return nil
		}
		count++
		if maxFiles > 0 && count > maxFiles {
			return ErrTooManyFiles
		}
		return fn(rel, d)
	})
}

// Excluded reports whether rel matches any glob. Supports "**" segments.
func Excluded(rel string, globs []string) bool {
	for _, g := range globs {
		if MatchGlob(g, rel) {
			return true
		}
	}
	return false
}

// MatchGlob matches a slash-separated path against a glob with "**" support.
func MatchGlob(pattern, name string) bool {
	pattern = strings.TrimPrefix(filepath.ToSlash(pattern), "./")
	name = strings.TrimSuffix(name, "/")
	return matchParts(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchParts(pat, parts []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			if len(pat) == 1 {
				return true
			}
			for i := 0; i <= len(parts); i++ {
				if matchParts(pat[1:], parts[i:]) {
					return true
				}
			}
			return false
		}
		if len(parts) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], parts[0]); !ok {
			return false
		}
		pat, parts = pat[1:], parts[1:]
	}
	return len(parts) == 0
}

// ReadLimited reads a file if it is not larger than max bytes and does not
// look binary. ok=false means the file was skipped.
func ReadLimited(p string, max int64) (data []byte, ok bool) {
	f, err := os.Open(p) //nolint:gosec // controlled path
	if err != nil {
		return nil, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() > max {
		return nil, false
	}
	data, err = io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, false
	}
	if IsBinary(data) {
		return nil, false
	}
	return data, true
}

// IsBinary uses the NUL-byte heuristic on the first 8 KiB.
func IsBinary(b []byte) bool {
	if len(b) > 8192 {
		b = b[:8192]
	}
	return bytes.IndexByte(b, 0) >= 0
}

// IsTestPath reports whether a path looks like tests/fixtures/examples.
func IsTestPath(rel string) bool {
	l := "/" + strings.ToLower(rel)
	for _, s := range []string{"/test/", "/tests/", "/testdata/", "/__tests__/", "/spec/", "/fixtures/", "/fixture/", "/examples/", "/example/", "/mocks/", "/mock/"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	base := path.Base(l)
	return strings.HasSuffix(base, "_test.go") || strings.HasPrefix(base, "test_") ||
		strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
}
