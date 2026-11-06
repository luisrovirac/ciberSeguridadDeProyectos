// Package trivy adapts Aqua Security Trivy (filesystem mode: vulnerabilities,
// misconfigurations and secrets).
package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/detector"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/execx"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/normalizer"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/toolcache"
)

// Scanner is the Trivy adapter.
type Scanner struct{}

// New creates the adapter.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (*Scanner) Name() string { return "trivy" }

// Native implements scanners.Scanner.
func (*Scanner) Native() bool { return false }

// Tool implements scanners.Scanner.
func (*Scanner) Tool() *execx.Tool {
	return &execx.Tool{
		Name: "trivy", Binary: "trivy", Image: "aquasec/trivy:0.76.2",
		VersionArgs: []string{"--version"},
		InstallHint: "Install Trivy: https://trivy.dev/latest/getting-started/installation/ (brew install trivy | choco install trivy | apt/yum repos), or let SecureProjects use the docker image aquasec/trivy.",
	}
}

// Applicable: Trivy covers dependencies, IaC, Dockerfiles and secrets.
func (*Scanner) Applicable(p *detector.Profile, _ *config.Config) bool {
	return p.HasManifests() || p.HasIaC() || p.HasContainers() || p.FileCount > 0
}

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request, res execx.Resolution) ([]finding.Finding, error) {
	cacheDir := toolcache.Dir("trivy")
	args := []string{"fs", "--format", "json", "--quiet", "--scanners", "vuln,misconfig,secret",
		"--offline-scan", "--skip-version-check", "--disable-telemetry", "--no-progress",
		"--cache-dir", "{{cache}}", "--timeout", req.Config.Limits.ToolTimeout.String()}
	if req.Config.Offline {
		args = append(args, "--skip-db-update", "--skip-java-db-update", "--skip-check-update")
	}
	for _, ex := range req.Config.Exclude {
		if d, ok := strings.CutSuffix(ex, "/**"); ok && !strings.ContainsAny(d, "*?[") {
			args = append(args, "--skip-dirs", d)
		}
	}
	args = append(args, req.Config.Scanners.For("trivy").Args...)
	args = append(args, "{{src}}")
	out, err := req.Exec.Run(ctx, *s.Tool(), res, execx.Spec{
		Args: args, SrcDir: req.Root, CacheDir: cacheDir, Network: !req.Config.Offline,
	})
	if err != nil {
		if req.Config.Offline && out != nil && strings.Contains(string(out.Stderr), "first run") {
			return nil, scanners.Skip("trivy has no vulnerability DB yet and --offline forbids downloading it; run once without --offline")
		}
		return nil, err
	}
	return Parse(out.Stdout, req.Root)
}

// Report mirrors the subset of Trivy's JSON report that we consume.
type Report struct {
	SchemaVersion int `json:"SchemaVersion"`
	Results       []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"VulnerabilityID"`
			VendorIDs        []string `json:"VendorIDs"`
			PkgName          string   `json:"PkgName"`
			PkgPath          string   `json:"PkgPath"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
			PkgIdentifier    struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
			PrimaryURL  string   `json:"PrimaryURL"`
			Title       string   `json:"Title"`
			Description string   `json:"Description"`
			Severity    string   `json:"Severity"`
			CweIDs      []string `json:"CweIDs"`
			References  []string `json:"References"`
			CVSS        map[string]struct {
				V2Vector  string  `json:"V2Vector"`
				V3Vector  string  `json:"V3Vector"`
				V2Score   float64 `json:"V2Score"`
				V3Score   float64 `json:"V3Score"`
				V40Vector string  `json:"V40Vector"`
				V40Score  float64 `json:"V40Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
		Misconfigurations []struct {
			Type          string   `json:"Type"`
			ID            string   `json:"ID"`
			AVDID         string   `json:"AVDID"`
			Title         string   `json:"Title"`
			Description   string   `json:"Description"`
			Message       string   `json:"Message"`
			Resolution    string   `json:"Resolution"`
			Severity      string   `json:"Severity"`
			PrimaryURL    string   `json:"PrimaryURL"`
			References    []string `json:"References"`
			Status        string   `json:"Status"`
			CauseMetadata struct {
				Resource  string `json:"Resource"`
				Provider  string `json:"Provider"`
				StartLine int    `json:"StartLine"`
				EndLine   int    `json:"EndLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
		Secrets []struct {
			RuleID    string `json:"RuleID"`
			Category  string `json:"Category"`
			Severity  string `json:"Severity"`
			Title     string `json:"Title"`
			StartLine int    `json:"StartLine"`
			EndLine   int    `json:"EndLine"`
			Match     string `json:"Match"`
		} `json:"Secrets"`
	} `json:"Results"`
}

// ecosystemFromType maps Trivy result types to OSV ecosystem names.
var ecosystemFromType = map[string]string{
	"gomod": "Go", "gobinary": "Go", "npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm", "bun": "npm",
	"pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "uv": "PyPI", "python-pkg": "PyPI",
	"pom": "Maven", "gradle": "Maven", "jar": "Maven", "sbt": "Maven",
	"bundler": "RubyGems", "gemspec": "RubyGems", "composer": "Packagist", "composer-vendor": "Packagist",
	"cargo": "crates.io", "rustbinary": "crates.io", "nuget": "NuGet", "dotnet-core": "NuGet", "packages-props": "NuGet",
}

// Parse converts Trivy JSON into findings.
func Parse(data []byte, root string) ([]finding.Finding, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse trivy output: %w", err)
	}
	var out []finding.Finding
	for _, res := range r.Results {
		target := normalizer.RelPath(root, res.Target)
		for _, v := range res.Vulnerabilities {
			f := finding.Finding{
				Kind: finding.KindVulnerability, Category: finding.CategoryDependencyVuln,
				Title:       fmt.Sprintf("%s in %s@%s", v.VulnerabilityID, v.PkgName, v.InstalledVersion),
				Description: v.Description, RuleID: v.VulnerabilityID,
				Severity: finding.ParseSeverity(v.Severity), Confidence: finding.ConfidenceHigh,
				Location: finding.Location{Path: target},
				Package: &finding.Package{Name: v.PkgName, Version: v.InstalledVersion, Ecosystem: ecosystemFromType[res.Type],
					PURL: v.PkgIdentifier.PURL, FixedVersions: splitFixed(v.FixedVersion)},
				References: append([]string{v.PrimaryURL}, v.References...),
				Aliases:    v.VendorIDs,
				Tools:      []string{"trivy"},
			}
			if v.Title != "" {
				f.Title += ": " + v.Title
			}
			if finding.IsCVE(v.VulnerabilityID) {
				f.CVE = []string{v.VulnerabilityID}
			} else {
				f.Aliases = append(f.Aliases, v.VulnerabilityID)
			}
			for _, c := range v.CweIDs {
				if n := finding.NormalizeCWE(c); n != "" {
					f.CWE = append(f.CWE, n)
				}
			}
			f.CVSS = pickCVSS(v.CVSS)
			if f.Package.Ecosystem == "" {
				f.Package.Ecosystem = res.Type
			}
			if v.FixedVersion != "" {
				f.Remediation = fmt.Sprintf("Upgrade %s to %s.", v.PkgName, v.FixedVersion)
			} else {
				f.Remediation = "No fixed version available yet; monitor the advisory or mitigate."
			}
			out = append(out, f)
		}
		for _, m := range res.Misconfigurations {
			if m.Status != "" && m.Status != "FAIL" {
				continue
			}
			id := m.ID
			if id == "" {
				id = m.AVDID
			}
			cat := finding.CategoryIaC
			if strings.EqualFold(res.Type, "dockerfile") {
				cat = finding.CategoryContainer
			}
			out = append(out, finding.Finding{
				// Trivy's checks are deterministic policy evaluations: the
				// misconfiguration is confirmed, its exploitability is not.
				Kind: finding.KindPotentialRisk, Category: cat,
				Title: m.Title, Description: strings.TrimSpace(m.Description + " " + m.Message),
				RuleID: id, RuleFamily: familyFor(id),
				Severity: finding.ParseSeverity(m.Severity), Confidence: finding.ConfidenceHigh,
				Location:    finding.Location{Path: target, StartLine: m.CauseMetadata.StartLine, EndLine: m.CauseMetadata.EndLine, Resource: m.CauseMetadata.Resource},
				Remediation: m.Resolution, References: append([]string{m.PrimaryURL}, m.References...),
				Evidence: m.Message, Tools: []string{"trivy"}, Tags: []string{"policy-check"},
			})
		}
		for _, s := range res.Secrets {
			// Trivy masks the secret in Match; we redact again downstream.
			out = append(out, finding.Finding{
				Kind: finding.KindPotentialRisk, Category: finding.CategorySecret,
				Title: s.Title + " in " + target, RuleID: "trivy-" + s.RuleID, RuleFamily: secretFamily(s.RuleID),
				Description: "Trivy secret scanner matched rule " + s.RuleID + ".",
				Severity:    finding.ParseSeverity(s.Severity), Confidence: finding.ConfidenceHigh,
				Location: finding.Location{Path: target, StartLine: s.StartLine, EndLine: s.EndLine},
				Evidence: s.Match, CWE: []string{"CWE-798"},
				Remediation: "Revoke and rotate the credential, remove it from code and Git history, and use a secret manager.",
				Tools:       []string{"trivy"},
			})
		}
	}
	return out, nil
}

func splitFixed(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// pickCVSS prefers NVD, then GHSA, then any other source (sorted for stability).
func pickCVSS(m map[string]struct {
	V2Vector  string  `json:"V2Vector"`
	V3Vector  string  `json:"V3Vector"`
	V2Score   float64 `json:"V2Score"`
	V3Score   float64 `json:"V3Score"`
	V40Vector string  `json:"V40Vector"`
	V40Score  float64 `json:"V40Score"`
}) *finding.CVSS {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		rank := func(k string) int {
			switch k {
			case "nvd":
				return 0
			case "ghsa":
				return 1
			default:
				return 2
			}
		}
		if rank(keys[i]) != rank(keys[j]) {
			return rank(keys[i]) < rank(keys[j])
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		c := m[k]
		switch {
		case c.V3Score > 0:
			ver := "3.1"
			if strings.HasPrefix(c.V3Vector, "CVSS:3.0") {
				ver = "3.0"
			}
			return &finding.CVSS{Version: ver, Vector: c.V3Vector, Score: c.V3Score, Source: k}
		case c.V40Score > 0:
			return &finding.CVSS{Version: "4.0", Vector: c.V40Vector, Score: c.V40Score, Source: k}
		case c.V2Score > 0:
			return &finding.CVSS{Version: "2.0", Vector: c.V2Vector, Score: c.V2Score, Source: k}
		}
	}
	return nil
}

// familyFor maps Trivy check IDs to cross-tool rule families.
func familyFor(id string) string {
	id = strings.ToUpper(strings.TrimPrefix(strings.ToUpper(id), "AVD-"))
	switch id {
	case "DS-0002", "DS002":
		return "dockerfile.root-user"
	case "DS-0001", "DS001":
		return "dockerfile.unpinned-image"
	case "DS-0005", "DS005":
		return "dockerfile.add-instead-of-copy"
	case "DS-0004", "DS004":
		return "dockerfile.expose-ssh"
	case "DS-0026", "DS026":
		return "dockerfile.no-healthcheck"
	case "DS-0031", "DS031":
		return "dockerfile.secret-in-env"
	case "KSV-0017", "KSV017":
		return "k8s.privileged-container"
	case "KSV-0001", "KSV001":
		return "k8s.privilege-escalation"
	case "KSV-0012", "KSV012":
		return "k8s.run-as-root"
	case "KSV-0014", "KSV014":
		return "k8s.writable-root-fs"
	case "KSV-0009", "KSV009", "KSV-0010", "KSV010", "KSV-0008", "KSV008":
		return "k8s.host-namespace"
	case "KSV-0011", "KSV011", "KSV-0018", "KSV018", "KSV-0015", "KSV015", "KSV-0016", "KSV016":
		return "k8s.no-resource-limits"
	case "KSV-0013", "KSV013":
		return "k8s.unpinned-image"
	case "AWS-0107", "AWS-0104", "AWS-0124", "GCP-0027", "AZU-0047", "AZU-0050":
		return "iac.public-ingress"
	case "AWS-0092":
		return "iac.storage-public-acl"
	case "AWS-0086", "AWS-0087", "AWS-0091", "AWS-0093":
		return "iac.storage-public-access-block"
	case "AWS-0180", "AWS-0082":
		return "iac.publicly-accessible"
	}
	return ""
}

func secretFamily(rule string) string {
	switch {
	case strings.Contains(rule, "aws-access-key"):
		return "secret.aws-access-key"
	case strings.HasPrefix(rule, "github"):
		return "secret.github-token"
	case strings.Contains(rule, "private-key"):
		return "secret.private-key"
	case strings.HasPrefix(rule, "slack"):
		return "secret.slack-token"
	case strings.HasPrefix(rule, "stripe"):
		return "secret.stripe-key"
	case strings.HasPrefix(rule, "gcp"):
		return "secret.gcp-api-key"
	case strings.Contains(rule, "jwt"):
		return "secret.jwt"
	}
	return "secret." + rule
}
