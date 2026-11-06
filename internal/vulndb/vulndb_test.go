package vulndb

import (
	"errors"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func testdata(parts ...string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(append([]string{filepath.Dir(file), "..", "..", "testdata"}, parts...)...)
}

func ids(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Vuln.ID)
	}
	slices.Sort(out)
	return out
}

// The OSV records in testdata/osv are real records fetched from api.osv.dev.
func TestLookupRealRecords(t *testing.T) {
	npm, err := BuildFromDir(testdata("osv", "npm"), "npm")
	if err != nil {
		t.Fatal(err)
	}
	got := ids(npm.Lookup("lodash", "4.17.15"))
	if !slices.Contains(got, "GHSA-p6mc-m468-83gw") { // CVE-2020-8203, fixed in 4.17.19
		t.Fatalf("lodash 4.17.15 should match GHSA-p6mc-m468-83gw, got %v", got)
	}
	if slices.Contains(ids(npm.Lookup("lodash", "4.17.19")), "GHSA-p6mc-m468-83gw") {
		t.Fatal("lodash 4.17.19 is the fixed version and must not match GHSA-p6mc-m468-83gw")
	}
	m := npm.Lookup("lodash", "4.17.15")
	for _, x := range m {
		if x.Vuln.ID == "GHSA-p6mc-m468-83gw" && !slices.Contains(x.Fixed, "4.17.19") {
			t.Errorf("fixed versions = %v, want 4.17.19", x.Fixed)
		}
	}

	py, err := BuildFromDir(testdata("osv", "PyPI"), "PyPI")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ids(py.Lookup("PyYAML", "5.3")), "GHSA-8q59-q68h-6hv4") { // CVE-2020-14343; name normalization
		t.Fatalf("PyYAML 5.3: %v", ids(py.Lookup("PyYAML", "5.3")))
	}
	if slices.Contains(ids(py.Lookup("requests", "2.31.0")), "GHSA-j8r2-6x86-q33q") { // fixed in 2.31.0
		t.Fatal("requests 2.31.0 must not match CVE-2023-32681")
	}
	if !slices.Contains(ids(py.Lookup("requests", "2.25.0")), "GHSA-j8r2-6x86-q33q") {
		t.Fatal("requests 2.25.0 must match CVE-2023-32681")
	}

	gox, err := BuildFromDir(testdata("osv", "Go"), "Go")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ids(gox.Lookup("golang.org/x/text", "0.3.7")), "GO-2022-1059") {
		t.Fatal("x/text 0.3.7 must match GO-2022-1059")
	}
	if slices.Contains(ids(gox.Lookup("golang.org/x/text", "0.3.8")), "GO-2022-1059") {
		t.Fatal("x/text 0.3.8 is fixed")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	ix, err := BuildFromDir(testdata("osv", "npm"), "npm")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := ix.Save(dir); err != nil {
		t.Fatal(err)
	}
	back, err := Load(dir, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Vulns) != len(ix.Vulns) || len(back.Lookup("lodash", "4.17.15")) == 0 {
		t.Fatal("round trip lost data")
	}
	if _, err := Load(dir, "PyPI"); !errors.Is(err, ErrNoIndex) {
		t.Fatalf("missing index: %v", err)
	}
}

func TestInRangeLastAffected(t *testing.T) {
	ix := NewIndex("npm", "test")
	ix.Add(Vuln{ID: "TEST-1", Affected: []Affected{{Name: "pkg", Ranges: []Range{{Type: "SEMVER", Events: []Event{{Introduced: "1.0.0"}, {LastAffected: "1.2.0"}}}}}}})
	for v, want := range map[string]bool{"0.9.0": false, "1.0.0": true, "1.2.0": true, "1.2.1": false} {
		if got := len(ix.Lookup("pkg", v)) > 0; got != want {
			t.Errorf("version %s affected=%v want %v", v, got, want)
		}
	}
}
