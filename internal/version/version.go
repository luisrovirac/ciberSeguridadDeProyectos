// Package version holds build information, set via -ldflags.
package version

// These are overridden at build time:
//
//	go build -ldflags "-X github.com/luisrovirac/ciberSeguridadDeProyectos/internal/version.Version=1.0.0 -X ...Commit=$(git rev-parse HEAD)"
var (
	Version = "0.1.0-dev"
	Commit  = ""
	Date    = ""
)

// URL is the project homepage reported in SARIF.
const URL = "https://github.com/luisrovirac/ciberSeguridadDeProyectos"
