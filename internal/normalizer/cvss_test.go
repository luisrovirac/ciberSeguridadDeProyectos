package normalizer

import "testing"

func TestCVSS3BaseScore(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H": 7.2, // CVE-2021-23337
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1, // typical reflected XSS
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for v, want := range cases {
		got, ok := CVSS3BaseScore(v)
		if !ok || got != want {
			t.Errorf("%s = %v (ok=%v), want %v", v, got, ok, want)
		}
	}
	if _, ok := CVSS3BaseScore("CVSS:3.1/AV:X"); ok {
		t.Fatal("invalid vector accepted")
	}
}

func TestCVSS2(t *testing.T) {
	got, ok := CVSS2BaseScore("AV:N/AC:L/Au:N/C:P/I:P/A:P")
	if !ok || got != 7.5 {
		t.Fatalf("got %v", got)
	}
}

func TestCVSSFromVectorV4KeepsVector(t *testing.T) {
	c, ok := CVSSFromVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "osv")
	if ok || c == nil || c.Version != "4.0" {
		t.Fatalf("%+v %v", c, ok)
	}
}

func TestRelPath(t *testing.T) {
	if got := RelPath(`C:\proj`, "/src/app/x.go"); got != "app/x.go" {
		t.Errorf("docker path: %q", got)
	}
	if got := RelPath("/proj", "./a/b.txt"); got != "a/b.txt" {
		t.Errorf("relative: %q", got)
	}
}
