package fsutil

import "testing"

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		p, n string
		want bool
	}{
		{"**/node_modules/**", "a/node_modules/x/y.js", true},
		{"**/node_modules/**", "node_modules/x.js", true},
		{"**/*.min.js", "web/app.min.js", true},
		{"deploy/**", "deploy/k8s/a.yaml", true},
		{"deploy/**", "src/deploy.go", false},
		{".git/**", ".git/HEAD", true},
		{"*.go", "a/b.go", false},
	}
	for _, c := range cases {
		if got := MatchGlob(c.p, c.n); got != c.want {
			t.Errorf("MatchGlob(%q,%q)=%v", c.p, c.n, got)
		}
	}
}

func TestIsTestPath(t *testing.T) {
	for p, want := range map[string]bool{"internal/x_test.go": true, "tests/test_a.py": true, "src/app.spec.ts": true, "src/main.go": false} {
		if IsTestPath(p) != want {
			t.Errorf("%s", p)
		}
	}
}
