// Package native contains SecureProjects' built-in analyzers. They work
// without any external tool. Except for the OSV dependency matcher, all of
// them are heuristics and report Kind=potential-risk.
package native

import (
	"bufio"
	"bytes"
	"context"
	"path"
	"path/filepath"
	"strings"

	"github.com/secureprojects/secureprojects/internal/execx"
	"github.com/secureprojects/secureprojects/internal/fsutil"
	"github.com/secureprojects/secureprojects/internal/scanners"
)

// base implements the boring parts of scanners.Scanner for native analyzers.
type base struct{ name string }

func (b base) Name() string      { return b.name }
func (b base) Native() bool      { return true }
func (b base) Tool() *execx.Tool { return nil }

// fileLines calls fn for each line of each file accepted by match.
// It stops early when ctx is cancelled.
func eachFile(ctx context.Context, req *scanners.Request, match func(rel string) bool, fn func(rel string, data []byte)) error {
	for _, rel := range req.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !match(rel) {
			continue
		}
		data, ok := fsutil.ReadLimited(filepath.Join(req.Root, filepath.FromSlash(rel)), req.Config.Limits.MaxFileSizeBytes)
		if !ok {
			continue
		}
		fn(rel, data)
	}
	return nil
}

// lines splits data into lines without the trailing newline.
func lines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func base0(rel string) string { return strings.ToLower(path.Base(rel)) }

func ext(rel string) string { return strings.ToLower(path.Ext(rel)) }

// snippet trims a line for use as evidence.
func snippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
