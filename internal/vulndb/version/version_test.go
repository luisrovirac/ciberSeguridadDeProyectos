package version

import "testing"

func check(t *testing.T, name string, cmp Comparator, cases [][3]string) {
	t.Helper()
	for _, c := range cases {
		want := map[string]int{"<": -1, "=": 0, ">": 1}[c[1]]
		got, ok := cmp(c[0], c[2])
		if !ok {
			t.Errorf("%s: %s vs %s unparseable", name, c[0], c[2])
			continue
		}
		if got != want {
			t.Errorf("%s: %s %s %s, got %d", name, c[0], c[1], c[2], got)
		}
	}
}

func TestSemverLike(t *testing.T) {
	check(t, "semver", CompareSemverLike, [][3]string{
		{"4.17.15", "<", "4.17.21"},
		{"1.0.0-alpha", "<", "1.0.0"},
		{"1.0.0-alpha.1", "<", "1.0.0-beta"},
		{"1.0.0-rc.1", ">", "1.0.0-beta.11"},
		{"0.3.7", "<", "0.3.8"},
		{"v1.2.3", "=", "1.2.3"},
		{"1.2", "=", "1.2.0"},
		{"2.0.0+incompatible", "=", "2.0.0"},
		{"0.0.0-20210101000000-abcdef123456", "<", "0.0.1"},
		{"10.0.0", ">", "9.99.99"},
	})
	if _, ok := CompareSemverLike("not a version", "1.0"); ok {
		t.Fatal("garbage parsed")
	}
}

func TestPEP440(t *testing.T) {
	check(t, "pep440", ComparePEP440, [][3]string{
		{"2.25.0", "<", "2.31.0"},
		{"5.3", "<", "5.4"},
		{"5.3", "=", "5.3.0"},
		{"1.0a1", "<", "1.0b1"},
		{"1.0rc1", "<", "1.0"},
		{"1.0", "<", "1.0.post1"},
		{"1.0.dev1", "<", "1.0a1"},
		{"1!0.1", ">", "2.0"},
		{"1.0+local", "=", "1.0"},
	})
}

func TestMaven(t *testing.T) {
	check(t, "maven", CompareMaven, [][3]string{
		{"2.14.1", "<", "2.15.0"},
		{"1.0-alpha", "<", "1.0-beta"},
		{"1.0-rc1", "<", "1.0"},
		{"1.0", "=", "1.0.0"},
		{"1.0-SNAPSHOT", "<", "1.0"},
		{"1.0", "<", "1.0-sp1"},
		{"2.17.1", ">", "2.3"},
	})
}

func TestGem(t *testing.T) {
	check(t, "gem", CompareGem, [][3]string{
		{"6.1.7", "<", "6.1.7.1"},
		{"7.0.0.rc1", "<", "7.0.0"},
		{"1.0", "=", "1.0.0"},
	})
}

func TestFor(t *testing.T) {
	if For("PyPI") == nil || For("npm") == nil || For("Maven") == nil || For("RubyGems") == nil {
		t.Fatal("missing comparator")
	}
	if For("Debian") != nil {
		t.Fatal("unsupported ecosystem should return nil")
	}
}
