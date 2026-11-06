package detector

import (
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func fixture(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "fixtures", name)
}

func TestDetect(t *testing.T) {
	excl := []string{"**/node_modules/**"}
	p, err := Detect(fixture("node-app"), excl, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Has("JavaScript") || !p.Has("npm") || len(p.Dockerfile) != 1 || !slices.Contains(p.Manifests["npm"], "package-lock.json") {
		t.Fatalf("node-app: %+v", p)
	}
	p, _ = Detect(fixture("python-app"), excl, 1000)
	if !p.Has("Python") || !p.Has("PyPI") {
		t.Fatalf("python-app: %+v", p)
	}
	p, _ = Detect(fixture("go-app"), excl, 1000)
	if !p.Has("Go") || len(p.K8s) != 1 || p.K8s[0] != "deploy/deployment.yaml" {
		t.Fatalf("go-app: %+v", p)
	}
	p, _ = Detect(fixture("iac"), excl, 1000)
	if len(p.Terraform) != 1 || len(p.Compose) != 1 || !p.HasIaC() {
		t.Fatalf("iac: %+v", p)
	}
	if _, err := Detect(filepath.Join(fixture("iac"), "main.tf"), nil, 10); err == nil {
		t.Fatal("file target must be rejected")
	}
}

func TestDetectFileLimit(t *testing.T) {
	p, err := Detect(fixture("node-app"), nil, 2)
	if err != nil || !p.Truncated {
		t.Fatalf("expected truncation: %v %+v", err, p)
	}
}
