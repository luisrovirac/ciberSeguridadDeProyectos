// Package registry lists every available scanner in a fixed order.
package registry

import (
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/bandit"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/gitleaks"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/hadolint"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/iac"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/kubelinter"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/native"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/osv"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/semgrep"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/trivy"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners/zap"
)

// All returns native analyzers first, then external adapters.
func All(osvDBDir string, customRules []native.PatternRule) []scanners.Scanner {
	return []scanners.Scanner{
		native.NewSecrets(),
		native.NewDockerfile(),
		native.NewIaC(),
		native.NewDangerous(),
		native.NewDepsRisk(),
		native.NewOSVMatcher(osvDBDir),
		native.NewCustom(customRules),
		trivy.New(),
		osv.New(),
		gitleaks.New(),
		semgrep.New(),
		hadolint.New(),
		kubelinter.New(),
		iac.NewCheckov(),
		iac.NewKICS(),
		bandit.New(),
		zap.New(),
	}
}

// External returns only the adapters for external tools.
func External() []scanners.Scanner {
	var out []scanners.Scanner
	for _, s := range All("", nil) {
		if !s.Native() {
			out = append(out, s)
		}
	}
	return out
}
