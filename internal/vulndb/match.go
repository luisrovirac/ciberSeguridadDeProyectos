package vulndb

import (
	"slices"
	"strings"

	"github.com/secureprojects/secureprojects/internal/vulndb/version"
)

// Match is a vulnerability affecting a specific package version.
type Match struct {
	Vuln       *Vuln
	Fixed      []string
	ExactMatch bool // matched through the explicit "versions" list
	ByRange    bool // matched through range evaluation
}

// Lookup returns vulnerabilities affecting name@ver in this index.
func (ix *Index) Lookup(name, ver string) []Match {
	key := NormalizeName(ix.Ecosystem, name)
	cmp := version.For(ix.Ecosystem)
	var out []Match
	for _, i := range ix.Packages[key] {
		v := &ix.Vulns[i]
		for _, a := range v.Affected {
			if a.Name != key {
				continue
			}
			m := Match{Vuln: v}
			if containsVersion(a.Versions, ver, ix.Ecosystem) {
				m.ExactMatch = true
			}
			for _, r := range a.Ranges {
				if cmp == nil {
					break
				}
				hit, fixed, ok := inRange(r, ver, cmp)
				if !ok {
					continue
				}
				if hit {
					m.ByRange = true
				}
				m.Fixed = append(m.Fixed, fixed...)
			}
			if m.ExactMatch || m.ByRange {
				slices.Sort(m.Fixed)
				m.Fixed = slices.Compact(m.Fixed)
				out = append(out, m)
				break
			}
		}
	}
	return out
}

func containsVersion(list []string, ver, eco string) bool {
	for _, v := range list {
		if v == ver {
			return true
		}
		if strings.EqualFold(eco, "Go") && strings.TrimPrefix(v, "v") == strings.TrimPrefix(ver, "v") {
			return true
		}
	}
	return false
}

// inRange evaluates an OSV range per the spec: events are sorted by version
// and processed in order. ok=false if any version could not be compared.
func inRange(r Range, ver string, cmp version.Comparator) (affected bool, fixed []string, ok bool) {
	type ev struct {
		kind string
		v    string
	}
	var evs []ev
	for _, e := range r.Events {
		switch {
		case e.Introduced != "":
			evs = append(evs, ev{"introduced", e.Introduced})
		case e.Fixed != "":
			evs = append(evs, ev{"fixed", e.Fixed})
			fixed = append(fixed, e.Fixed)
		case e.LastAffected != "":
			evs = append(evs, ev{"last_affected", e.LastAffected})
		}
	}
	less := func(a, b string) (int, bool) {
		if a == b {
			return 0, true
		}
		if a == "0" {
			return -1, true
		}
		if b == "0" {
			return 1, true
		}
		return cmp(a, b)
	}
	valid := true
	slices.SortStableFunc(evs, func(a, b ev) int {
		c, k := less(a.v, b.v)
		if !k {
			valid = false
		}
		return c
	})
	if !valid {
		return false, fixed, false
	}
	if _, k := cmp(ver, ver); !k {
		return false, fixed, false
	}
	for _, e := range evs {
		c, k := less(ver, e.v)
		if !k {
			return false, fixed, false
		}
		switch e.kind {
		case "introduced":
			if c >= 0 {
				affected = true
			}
		case "fixed":
			if c >= 0 {
				affected = false
			}
		case "last_affected":
			if c > 0 {
				affected = false
			}
		}
	}
	return affected, fixed, true
}
