// Package toolcache provides per-tool persistent cache directories
// (vulnerability databases of external tools, etc.).
package toolcache

import (
	"os"
	"path/filepath"
)

// Dir returns (and creates) the cache directory for a tool.
func Dir(tool string) string {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	d := filepath.Join(base, "secureprojects", "tools", tool)
	_ = os.MkdirAll(d, 0o700)
	return d
}
