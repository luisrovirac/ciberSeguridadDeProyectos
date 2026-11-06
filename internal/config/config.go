// Package config defines SecureProjects configuration, defaults and validation.
package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/secureprojects/secureprojects/internal/finding"
)

// Runner modes for external tools.
const (
	RunnerAuto   = "auto"   // local binary, else docker image if docker is available
	RunnerLocal  = "local"  // local binary only
	RunnerDocker = "docker" // docker image only
)

// Config is the full configuration. Field tags are used by both YAML and Viper.
type Config struct {
	Formats  []string `mapstructure:"formats" yaml:"formats" json:"formats"`
	Output   string   `mapstructure:"output" yaml:"output" json:"output"`
	FailOn   string   `mapstructure:"fail_on" yaml:"fail_on" json:"failOn"`
	Offline  bool     `mapstructure:"offline" yaml:"offline" json:"offline"`
	Safe     bool     `mapstructure:"safe" yaml:"safe" json:"safe"`
	NoColor  bool     `mapstructure:"no_color" yaml:"no_color" json:"noColor"`
	Baseline string   `mapstructure:"baseline" yaml:"baseline" json:"baseline,omitempty"`
	DiffOnly bool     `mapstructure:"diff" yaml:"diff" json:"diff"`
	// FailOnPotentialMinConfidence: potential-risk findings below this confidence never fail CI.
	FailOnPotentialMinConfidence string `mapstructure:"fail_on_potential_min_confidence" yaml:"fail_on_potential_min_confidence" json:"failOnPotentialMinConfidence"`

	Limits   Limits   `mapstructure:"limits" yaml:"limits" json:"limits"`
	Scanners Scanners `mapstructure:"scanners" yaml:"scanners" json:"scanners"`
	Exclude  []string `mapstructure:"exclude" yaml:"exclude" json:"exclude,omitempty"`

	IgnoreFile  string `mapstructure:"ignore_file" yaml:"ignore_file" json:"ignoreFile,omitempty"`
	CustomRules string `mapstructure:"custom_rules" yaml:"custom_rules" json:"customRules,omitempty"`

	Cache  Cache  `mapstructure:"cache" yaml:"cache" json:"cache"`
	VulnDB VulnDB `mapstructure:"vulndb" yaml:"vulndb" json:"vulndb"`

	Active ActiveScan `mapstructure:"active" yaml:"active" json:"active"`
	LLM    LLM        `mapstructure:"llm" yaml:"llm" json:"llm"`

	ScanGitHistory bool `mapstructure:"scan_git_history" yaml:"scan_git_history" json:"scanGitHistory"`
}

// Limits bounds resource usage.
type Limits struct {
	MaxFileSizeBytes  int64         `mapstructure:"max_file_size_bytes" yaml:"max_file_size_bytes" json:"maxFileSizeBytes"`
	MaxFiles          int           `mapstructure:"max_files" yaml:"max_files" json:"maxFiles"`
	ScanTimeout       time.Duration `mapstructure:"scan_timeout" yaml:"scan_timeout" json:"scanTimeout"`
	ToolTimeout       time.Duration `mapstructure:"tool_timeout" yaml:"tool_timeout" json:"toolTimeout"`
	MaxToolOutputByte int64         `mapstructure:"max_tool_output_bytes" yaml:"max_tool_output_bytes" json:"maxToolOutputBytes"`
	Concurrency       int           `mapstructure:"concurrency" yaml:"concurrency" json:"concurrency"`
	DockerMemory      string        `mapstructure:"docker_memory" yaml:"docker_memory" json:"dockerMemory"`
}

// ScannerConfig configures one scanner.
type ScannerConfig struct {
	Enabled *bool    `mapstructure:"enabled" yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Runner  string   `mapstructure:"runner" yaml:"runner,omitempty" json:"runner,omitempty"`
	Path    string   `mapstructure:"path" yaml:"path,omitempty" json:"path,omitempty"`
	Image   string   `mapstructure:"image" yaml:"image,omitempty" json:"image,omitempty"`
	Args    []string `mapstructure:"args" yaml:"args,omitempty" json:"args,omitempty"`
	Config  string   `mapstructure:"config" yaml:"config,omitempty" json:"config,omitempty"`
}

// IsEnabled returns the enabled flag with a default.
func (s ScannerConfig) IsEnabled(def bool) bool {
	if s.Enabled == nil {
		return def
	}
	return *s.Enabled
}

// Scanners holds per-scanner configuration keyed by scanner name.
type Scanners struct {
	Runner   string                   `mapstructure:"runner" yaml:"runner" json:"runner"`
	Only     []string                 `mapstructure:"only" yaml:"only,omitempty" json:"only,omitempty"`
	Disable  []string                 `mapstructure:"disable" yaml:"disable,omitempty" json:"disable,omitempty"`
	Settings map[string]ScannerConfig `mapstructure:"settings" yaml:"settings,omitempty" json:"settings,omitempty"`
}

// For returns the configuration for a scanner by name.
func (s Scanners) For(name string) ScannerConfig {
	if s.Settings == nil {
		return ScannerConfig{}
	}
	return s.Settings[name]
}

// Cache configures result caching.
type Cache struct {
	Enabled bool   `mapstructure:"enabled" yaml:"enabled" json:"enabled"`
	Dir     string `mapstructure:"dir" yaml:"dir,omitempty" json:"dir,omitempty"`
}

// VulnDB configures the local OSV database used by the native matcher.
type VulnDB struct {
	Dir        string   `mapstructure:"dir" yaml:"dir,omitempty" json:"dir,omitempty"`
	Ecosystems []string `mapstructure:"ecosystems" yaml:"ecosystems,omitempty" json:"ecosystems,omitempty"`
	MaxAgeDays int      `mapstructure:"max_age_days" yaml:"max_age_days" json:"maxAgeDays"`
}

// ActiveScan configures opt-in DAST.
type ActiveScan struct {
	Allowed    bool   `mapstructure:"allowed" yaml:"allowed" json:"allowed"`
	TargetURL  string `mapstructure:"target_url" yaml:"target_url,omitempty" json:"targetURL,omitempty"`
	Authorized bool   `mapstructure:"i_have_authorization" yaml:"i_have_authorization" json:"iHaveAuthorization"`
	MaxMinutes int    `mapstructure:"max_minutes" yaml:"max_minutes" json:"maxMinutes"`
	ZAPImage   string `mapstructure:"zap_image" yaml:"zap_image,omitempty" json:"zapImage,omitempty"`
}

// LLM configures the optional, non-authoritative explanation feature.
type LLM struct {
	Enabled      bool   `mapstructure:"enabled" yaml:"enabled" json:"enabled"`
	Consent      bool   `mapstructure:"consent" yaml:"consent" json:"consent"`
	Provider     string `mapstructure:"provider" yaml:"provider,omitempty" json:"provider,omitempty"`
	Model        string `mapstructure:"model" yaml:"model,omitempty" json:"model,omitempty"`
	Endpoint     string `mapstructure:"endpoint" yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	APIKeyEnv    string `mapstructure:"api_key_env" yaml:"api_key_env,omitempty" json:"apiKeyEnv,omitempty"`
	MaxFindings  int    `mapstructure:"max_findings" yaml:"max_findings" json:"maxFindings"`
	SendSnippets bool   `mapstructure:"send_snippets" yaml:"send_snippets" json:"sendSnippets"`
	MinSeverity  string `mapstructure:"min_severity" yaml:"min_severity,omitempty" json:"minSeverity,omitempty"`
}

// Default returns the secure-by-default configuration.
func Default() Config {
	return Config{
		Formats:                      []string{"table"},
		Output:                       "secureprojects-report",
		FailOn:                       "high",
		Offline:                      true, // passive/offline by default; --online allows tool DB updates
		Safe:                         true,
		FailOnPotentialMinConfidence: "medium",
		Limits: Limits{
			MaxFileSizeBytes:  2 << 20, // 2 MiB
			MaxFiles:          50000,
			ScanTimeout:       30 * time.Minute,
			ToolTimeout:       10 * time.Minute,
			MaxToolOutputByte: 256 << 20,
			Concurrency:       4,
			DockerMemory:      "2g",
		},
		Scanners: Scanners{Runner: RunnerAuto},
		Exclude: []string{
			".git/**", "**/node_modules/**", "**/vendor/**", "**/.venv/**", "**/venv/**",
			"**/dist/**", "**/build/**", "**/target/**", "**/__pycache__/**", "**/.terraform/**",
			"**/*.min.js", "**/*.map",
		},
		IgnoreFile:     ".secureprojects-ignore.yaml",
		ScanGitHistory: true,
		Cache:          Cache{Enabled: true},
		VulnDB: VulnDB{
			Ecosystems: []string{"Go", "npm", "PyPI", "Maven", "RubyGems", "Packagist", "crates.io", "NuGet"},
			MaxAgeDays: 7,
		},
		Active: ActiveScan{MaxMinutes: 10, ZAPImage: "ghcr.io/zaproxy/zaproxy:stable"},
		LLM:    LLM{Provider: "anthropic", Model: "claude-opus-5-5", APIKeyEnv: "ANTHROPIC_API_KEY", MaxFindings: 20, MinSeverity: "high"}, //nolint:gosec // G101: env var NAME, not a credential
	}
}

// ErrInvalid wraps configuration validation errors (exit code 3).
var ErrInvalid = errors.New("invalid configuration")

var validFormats = map[string]bool{"json": true, "sarif": true, "html": true, "table": true}

// Validate checks the configuration and normalizes some fields.
func (c *Config) Validate() error {
	var errs []error
	var formats []string
	for _, f := range c.Formats {
		for _, p := range strings.Split(f, ",") {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if !validFormats[p] {
				errs = append(errs, fmt.Errorf("unknown format %q (valid: json, sarif, html, table)", p))
			}
			formats = append(formats, p)
		}
	}
	if len(formats) == 0 {
		formats = []string{"table"}
	}
	c.Formats = finding.UniqueSorted(formats)

	c.FailOn = strings.ToLower(strings.TrimSpace(c.FailOn))
	switch c.FailOn {
	case "critical", "high", "medium", "low", "info", "none":
	default:
		errs = append(errs, fmt.Errorf("--fail-on must be critical|high|medium|low|info|none, got %q", c.FailOn))
	}
	switch strings.ToLower(c.FailOnPotentialMinConfidence) {
	case "", "low", "medium", "high":
	default:
		errs = append(errs, fmt.Errorf("fail_on_potential_min_confidence must be low|medium|high"))
	}
	switch c.Scanners.Runner {
	case "":
		c.Scanners.Runner = RunnerAuto
	case RunnerAuto, RunnerLocal, RunnerDocker:
	default:
		errs = append(errs, fmt.Errorf("scanners.runner must be auto|local|docker, got %q", c.Scanners.Runner))
	}
	for name, s := range c.Scanners.Settings {
		switch s.Runner {
		case "", RunnerAuto, RunnerLocal, RunnerDocker:
		default:
			errs = append(errs, fmt.Errorf("scanners.settings.%s.runner invalid: %q", name, s.Runner))
		}
	}
	if c.Limits.Concurrency <= 0 {
		c.Limits.Concurrency = 1
	}
	if c.Limits.MaxFileSizeBytes <= 0 {
		errs = append(errs, errors.New("limits.max_file_size_bytes must be > 0"))
	}
	if c.Limits.ToolTimeout <= 0 || c.Limits.ScanTimeout <= 0 {
		errs = append(errs, errors.New("limits timeouts must be > 0"))
	}
	if c.DiffOnly && c.Baseline == "" {
		errs = append(errs, errors.New("--diff requires --baseline"))
	}
	if c.Active.Allowed {
		if c.Active.TargetURL == "" {
			errs = append(errs, errors.New("--allow-active-scan requires --target-url"))
		} else if !strings.HasPrefix(c.Active.TargetURL, "http://") && !strings.HasPrefix(c.Active.TargetURL, "https://") {
			errs = append(errs, errors.New("--target-url must be an http(s) URL"))
		}
		if c.Offline {
			errs = append(errs, errors.New("--allow-active-scan cannot be combined with --offline"))
		}
		c.Safe = false
	} else if c.Active.TargetURL != "" {
		errs = append(errs, errors.New("--target-url given without --allow-active-scan"))
	}
	if c.LLM.Enabled && !c.LLM.Consent {
		errs = append(errs, errors.New("llm.enabled requires explicit llm.consent: true (or --llm-consent)"))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalid, errors.Join(errs...))
	}
	return nil
}

// Redacted returns a copy safe to embed in reports.
func (c Config) Redacted() Config {
	cp := c
	cp.LLM.Endpoint = ""
	return cp
}
