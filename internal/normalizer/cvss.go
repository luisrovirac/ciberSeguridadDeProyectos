// Package normalizer holds helpers shared by adapters to convert tool output
// into the common finding model (CVSS parsing, path normalization, ...).
package normalizer

import (
	"math"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/secureprojects/secureprojects/internal/finding"
)

// CVSS3BaseScore computes the CVSS v3.0/v3.1 base score from a vector string
// such as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". ok=false if invalid.
func CVSS3BaseScore(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			return 0, false
		}
		m[k] = v
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	val := map[string]float64{}
	for k, w := range weights {
		x, ok := w[m[k]]
		if !ok {
			return 0, false
		}
		val[k] = x
	}
	scope := m["S"]
	if scope != "U" && scope != "C" {
		return 0, false
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if scope == "C" {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if scope == "C" {
			pr = 0.5
		}
	default:
		return 0, false
	}
	iss := 1 - (1-val["C"])*(1-val["I"])*(1-val["A"])
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	expl := 8.22 * val["AV"] * val["AC"] * pr * val["UI"]
	if impact <= 0 {
		return 0, true
	}
	if scope == "U" {
		return roundUp(math.Min(impact+expl, 10)), true
	}
	return roundUp(math.Min(1.08*(impact+expl), 10)), true
}

// roundUp implements the CVSS v3.1 Roundup function.
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

// CVSS2BaseScore computes a CVSS v2 base score from "AV:N/AC:L/Au:N/C:P/I:P/A:P".
func CVSS2BaseScore(vector string) (float64, bool) {
	vector = strings.TrimPrefix(strings.TrimPrefix(vector, "("), "CVSS:2.0/")
	vector = strings.TrimSuffix(vector, ")")
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			return 0, false
		}
		m[k] = v
	}
	av := map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}[m["AV"]]
	ac := map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}[m["AC"]]
	au := map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}[m["Au"]]
	cia := map[string]float64{"N": 0, "P": 0.275, "C": 0.660}
	c, okC := cia[m["C"]]
	i, okI := cia[m["I"]]
	a, okA := cia[m["A"]]
	if av == 0 || ac == 0 || au == 0 || !okC || !okI || !okA {
		return 0, false
	}
	impact := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	expl := 20 * av * ac * au
	f := 1.176
	if impact == 0 {
		f = 0
	}
	score := ((0.6 * impact) + (0.4 * expl) - 1.5) * f
	return math.Round(score*10) / 10, true
}

// CVSSFromVector builds a finding.CVSS from any supported vector.
// CVSS v4 vectors are kept without a computed score (score 0, ok=false).
func CVSSFromVector(vector, source string) (*finding.CVSS, bool) {
	vector = strings.TrimSpace(vector)
	switch {
	case strings.HasPrefix(vector, "CVSS:3"):
		s, ok := CVSS3BaseScore(vector)
		if !ok {
			return nil, false
		}
		return &finding.CVSS{Version: vector[5:8], Vector: vector, Score: s, Source: source}, true
	case strings.HasPrefix(vector, "CVSS:4"):
		return &finding.CVSS{Version: "4.0", Vector: vector, Source: source}, false
	case strings.HasPrefix(vector, "AV:") || strings.HasPrefix(vector, "(AV:"):
		s, ok := CVSS2BaseScore(vector)
		if !ok {
			return nil, false
		}
		return &finding.CVSS{Version: "2.0", Vector: vector, Score: s, Source: source}, true
	}
	return nil, false
}

// ParseScore parses a numeric score string ("7.5").
func ParseScore(s string) (float64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f < 0 || f > 10 {
		return 0, false
	}
	return f, true
}

// RelPath converts a tool-reported path into a forward-slash path relative to root.
// Container paths (/src/...) used in docker mode are handled too.
func RelPath(root, p string) string {
	if p == "" {
		return ""
	}
	p = strings.TrimPrefix(p, "file://")
	for _, prefix := range []string{"/src/", "/src"} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(strings.TrimPrefix(p, prefix), "/")
		}
	}
	if filepath.IsAbs(p) || (len(p) > 2 && p[1] == ':') {
		if rel, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return strings.TrimPrefix(filepath.ToSlash(p), "./")
}
