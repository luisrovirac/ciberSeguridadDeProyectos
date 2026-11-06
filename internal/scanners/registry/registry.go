// Package registry lists every available scanner in a fixed order.
package registry

import (
	"github.com/secureprojects/secureprojects/internal/scanners"
	"github.com/secureprojects/secureprojects/internal/scanners/bandit"
	"github.com/secureprojects/secureprojects/internal/scanners/gitleaks"
	"github.com/secureprojects/secureprojects/internal/scanners/hadolint"
	"github.com/secureprojects/secureprojects/internal/scanners/iac"
	"github.com/secureprojects/secureprojects/internal/scanners/kubelinter"
	"github.com/secureprojects/secureprojects/internal/scanners/native"
	"github.com/secureprojects/secureprojects/internal/scanners/osv"
	"github.com/secureprojects/secureprojects/internal/scanners/semgrep"
	"github.com/secureprojects/secureprojects/internal/scanners/trivy"
	"github.com/secureprojects/secureprojects/internal/scanners/zap"
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
