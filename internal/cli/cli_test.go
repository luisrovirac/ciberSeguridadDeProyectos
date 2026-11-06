package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fixture(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "fixtures", name)
}

// isolate keeps tests independent from tools installed on the machine.
func isolate(t *testing.T) []string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	y := "cache:\n  enabled: false\nvulndb:\n  dir: " + filepath.ToSlash(t.TempDir()) + "\nscanners:\n  runner: local\n  only: [native-secrets, native-dockerfile, native-iac, native-sast, native-deps, native-osv]\n"
	if err := os.WriteFile(cfg, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"-c", cfg, "-q", "-o", t.TempDir()}
}

func TestExitCodes(t *testing.T) {
	base := isolate(t)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"findings above threshold", append([]string{"scan", fixture("node-app")}, base...), ExitFindings},
		{"fail-on none", append([]string{"scan", fixture("node-app"), "--fail-on", "none"}, base...), ExitOK},
		{"clean project", append([]string{"scan", t.TempDir()}, base...), ExitOK},
		{"invalid fail-on", append([]string{"scan", fixture("node-app"), "--fail-on", "urgent"}, base...), ExitConfig},
		{"invalid format", append([]string{"scan", fixture("node-app"), "--format", "pdf"}, base...), ExitConfig},
		{"diff without baseline", append([]string{"scan", fixture("node-app"), "--diff"}, base...), ExitConfig},
		{"active scan without url", append([]string{"scan", fixture("node-app"), "--allow-active-scan"}, base...), ExitConfig},
		{"active scan not authorized", append([]string{"scan", fixture("node-app"), "--allow-active-scan", "--target-url", "https://example.invalid"}, base...), ExitConfig},
		{"missing baseline", append([]string{"scan", fixture("node-app"), "--baseline", "nope.json"}, base...), ExitConfig},
		{"unknown flag", []string{"scan", "--bogus"}, ExitConfig},
		{"missing config file", []string{"scan", "-c", "does-not-exist.yaml"}, ExitConfig},
		{"merge unreadable report", []string{"report", "merge", "nope.json"}, ExitConfig},
		{"version", []string{"version"}, ExitOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Run(c.args); got != c.want {
				t.Fatalf("exit code %d, want %d (args %v)", got, c.want, c.args)
			}
		})
	}
}

func TestReportMerge(t *testing.T) {
	out := t.TempDir()
	base := isolate(t)
	base[len(base)-1] = out
	for _, app := range []string{"node-app", "python-app"} {
		dir := filepath.Join(out, app)
		args := append([]string{"scan", fixture(app), "--format", "json", "--fail-on", "none"}, base...)
		args[len(args)-1] = dir
		if code := Run(args); code != ExitOK {
			t.Fatalf("scan %s: %d", app, code)
		}
	}
	code := Run([]string{"report", "merge", "-q", filepath.Join(out, "node-app", "secureprojects-report.json"), filepath.Join(out, "python-app", "secureprojects-report.json"),
		"--format", "json,sarif,html", "-o", filepath.Join(out, "merged"), "--fail-on", "critical"})
	if code != ExitFindings && code != ExitOK {
		t.Fatalf("merge exit %d", code)
	}
	for _, f := range []string{"secureprojects-merged.json", "secureprojects-merged.sarif", "secureprojects-merged.html"} {
		if _, err := os.Stat(filepath.Join(out, "merged", f)); err != nil {
			t.Fatal(err)
		}
	}
}
