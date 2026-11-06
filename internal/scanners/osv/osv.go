// Package osv adapts Google's OSV-Scanner v2.
package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/config"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/detector"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/execx"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/finding"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/normalizer"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/scanners"
	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/toolcache"
)

// Scanner is the OSV-Scanner adapter.
type Scanner struct{}

// New creates the adapter.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (*Scanner) Name() string { return "osv-scanner" }

// Native implements scanners.Scanner.
func (*Scanner) Native() bool { return false }

// Tool implements scanners.Scanner.
func (*Scanner) Tool() *execx.Tool {
	return &execx.Tool{
		Name: "osv-scanner", Binary: "osv-scanner", Image: "ghcr.io/google/osv-scanner:v2.7.0",
		VersionArgs: []string{"--version"},
		InstallHint: "Install OSV-Scanner: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest, or download a release from https://github.com/google/osv-scanner/releases.",
	}
}

// Applicable when manifests exist.
func (*Scanner) Applicable(p *detector.Profile, _ *config.Config) bool { return p.HasManifests() }

// Scan implements scanners.Scanner. Vulnerability data is always matched
// locally (--offline-vulnerabilities) so the dependency list is never sent
// to api.osv.dev; online mode only downloads the public databases.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request, res execx.Resolution) ([]finding.Finding, error) {
	args := []string{"scan", "source", "-r", "--format", "json", "--verbosity", "error", "--allow-no-lockfiles"}
	if req.Config.Offline {
		args = append(args, "--offline")
	} else {
		args = append(args, "--offline-vulnerabilities", "--download-offline-databases", "--no-resolve")
	}
	args = append(args, req.Config.Scanners.For("osv-scanner").Args...)
	args = append(args, "{{src}}")
	out, err := req.Exec.Run(ctx, *s.Tool(), res, execx.Spec{
		Args: args, SrcDir: req.Root, CacheDir: toolcache.Dir("osv-scanner"),
		Env:        map[string]string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "{{cache}}"},
		AcceptExit: []int{1, 128}, Network: !req.Config.Offline,
	})
	if err != nil {
		if out != nil && strings.Contains(string(out.Stderr), "no offline version") {
			return nil, scanners.Skip("osv-scanner has no local database for some ecosystems of this project; run once with --online to download them")
		}
		return nil, err
	}
	if out.ExitCode == 128 || len(strings.TrimSpace(string(out.Stdout))) == 0 {
		return nil, nil
	}
	return Parse(out.Stdout, req.Root)
}

// Output mirrors osv-scanner's JSON output.
type Output struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
				PURL      string `json:"purl"`
			} `json:"package"`
			Groups []struct {
				IDs         []string `json:"ids"`
				Aliases     []string `json:"aliases"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
			Vulnerabilities []struct {
				ID       string   `json:"id"`
				Aliases  []string `json:"aliases"`
				Summary  string   `json:"summary"`
				Details  string   `json:"details"`
				Severity []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				} `json:"severity"`
				Affected []struct {
					Package struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
					Ranges []struct {
						Events []map[string]string `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
				DatabaseSpecific struct {
					Severity string   `json:"severity"`
					CWEIDs   []string `json:"cwe_ids"`
				} `json:"database_specific"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

// Parse converts osv-scanner JSON into findings. Each OSV "group" (records
// that are aliases of each other) becomes a single finding.
func Parse(data []byte, root string) ([]finding.Finding, error) {
	var o Output
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("parse osv-scanner output: %w", err)
	}
	var out []finding.Finding
	for _, r := range o.Results {
		path := normalizer.RelPath(root, r.Source.Path)
		for _, p := range r.Packages {
			byID := map[string]int{}
			for i, v := range p.Vulnerabilities {
				byID[v.ID] = i
			}
			groups := p.Groups
			if len(groups) == 0 { // older versions: one group per vuln
				for _, v := range p.Vulnerabilities {
					groups = append(groups, struct {
						IDs         []string `json:"ids"`
						Aliases     []string `json:"aliases"`
						MaxSeverity string   `json:"max_severity"`
					}{IDs: []string{v.ID}, Aliases: v.Aliases})
				}
			}
			for _, g := range groups {
				ids := append(append([]string{}, g.IDs...), g.Aliases...)
				f := finding.Finding{
					Kind: finding.KindVulnerability, Category: finding.CategoryDependencyVuln,
					Confidence: finding.ConfidenceHigh, Tools: []string{"osv-scanner"},
					Location: finding.Location{Path: path},
					Package:  &finding.Package{Name: p.Package.Name, Version: p.Package.Version, Ecosystem: p.Package.Ecosystem, PURL: p.Package.PURL},
				}
				var sevLabel string
				for _, id := range g.IDs {
					i, ok := byID[id]
					if !ok {
						continue
					}
					v := p.Vulnerabilities[i]
					ids = append(ids, v.Aliases...)
					if f.Description == "" {
						f.Description = v.Details
					}
					if f.Title == "" && v.Summary != "" {
						f.Title = v.Summary
					}
					for _, s := range v.Severity {
						if c, ok := normalizer.CVSSFromVector(s.Score, "osv"); ok && (f.CVSS == nil || c.Score > f.CVSS.Score) {
							f.CVSS = c
						}
					}
					if sevLabel == "" {
						sevLabel = v.DatabaseSpecific.Severity
					}
					for _, c := range v.DatabaseSpecific.CWEIDs {
						if n := finding.NormalizeCWE(c); n != "" {
							f.CWE = append(f.CWE, n)
						}
					}
					for _, a := range v.Affected {
						if a.Package.Name != p.Package.Name {
							continue
						}
						for _, rg := range a.Ranges {
							for _, e := range rg.Events {
								if fx := e["fixed"]; fx != "" {
									f.Package.FixedVersions = append(f.Package.FixedVersions, fx)
								}
							}
						}
					}
					for _, ref := range v.References {
						f.References = append(f.References, ref.URL)
					}
				}
				for _, id := range finding.UniqueSorted(ids) {
					if finding.IsCVE(id) {
						f.CVE = append(f.CVE, id)
					} else {
						f.Aliases = append(f.Aliases, id)
					}
				}
				canon := finding.CanonicalVulnID(ids...)
				f.RuleID = canon
				summary := f.Title
				f.Title = fmt.Sprintf("%s in %s@%s", canon, p.Package.Name, p.Package.Version)
				if summary != "" {
					f.Title += ": " + summary
				}
				switch {
				case f.CVSS != nil && f.CVSS.Score > 0:
					f.Severity = finding.SeverityFromScore(f.CVSS.Score)
				case g.MaxSeverity != "":
					if sc, ok := normalizer.ParseScore(g.MaxSeverity); ok && sc > 0 {
						f.Severity = finding.SeverityFromScore(sc)
					}
				}
				if f.Severity == "" && sevLabel != "" {
					f.Severity = finding.ParseSeverity(sevLabel)
				}
				if strings.HasPrefix(canon, "MAL-") {
					f.Severity = finding.SeverityCritical
				}
				f.Package.FixedVersions = finding.UniqueSorted(f.Package.FixedVersions)
				if len(f.Package.FixedVersions) > 0 {
					f.Remediation = fmt.Sprintf("Upgrade %s to a fixed version (%s).", p.Package.Name, strings.Join(f.Package.FixedVersions, ", "))
				}
				out = append(out, f)
			}
		}
	}
	return out, nil
}
