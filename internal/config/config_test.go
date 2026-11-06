package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultIsSecure(t *testing.T) {
	c := Default()
	if !c.Offline || !c.Safe || c.Active.Allowed || c.LLM.Enabled {
		t.Fatalf("defaults must be offline, safe, no DAST, no LLM: %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	bad := []func(*Config){
		func(c *Config) { c.Formats = []string{"pdf"} },
		func(c *Config) { c.FailOn = "urgent" },
		func(c *Config) { c.DiffOnly = true },
		func(c *Config) { c.Active.Allowed = true },
		func(c *Config) { c.Active.Allowed, c.Active.TargetURL, c.Offline = true, "https://x", true },
		func(c *Config) { c.Active.TargetURL = "https://x" },
		func(c *Config) { c.LLM.Enabled = true },
		func(c *Config) { c.Scanners.Runner = "podman" },
	}
	for i, mut := range bad {
		c := Default()
		mut(&c)
		if err := c.Validate(); err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: expected ErrInvalid, got %v", i, err)
		}
	}
	c := Default()
	c.Formats = []string{"json,sarif", "html"}
	if err := c.Validate(); err != nil || len(c.Formats) != 3 {
		t.Fatalf("%v %v", err, c.Formats)
	}
}

func TestLoadYAMLAndEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	_ = os.WriteFile(p, []byte("fail_on: critical\nlimits:\n  tool_timeout: 3m\nscanners:\n  disable: [semgrep]\n  settings:\n    trivy:\n      runner: docker\n"), 0o600)
	t.Setenv("SECUREPROJECTS_OUTPUT", "out-from-env")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.FailOn != "critical" || c.Limits.ToolTimeout != 3*time.Minute || c.Output != "out-from-env" {
		t.Fatalf("%+v", c)
	}
	if c.Scanners.For("trivy").Runner != "docker" || c.Scanners.Disable[0] != "semgrep" {
		t.Fatalf("%+v", c.Scanners)
	}
	if !c.Offline {
		t.Fatal("unset keys must keep defaults")
	}
	_ = os.WriteFile(p, []byte("fail_on: [oops"), 0o600)
	if _, err := Load(p); !IsInvalid(err) {
		t.Fatal("broken YAML must be a config error")
	}
}
