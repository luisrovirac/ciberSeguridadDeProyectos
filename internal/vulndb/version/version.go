// Package version implements version comparison for the package ecosystems
// supported by the native OSV matcher. Comparators are deliberately
// conservative: when a version cannot be parsed, Compare reports ok=false and
// the caller must not claim a match based on ranges.
package version

import (
	"math/big"
	"regexp"
	"strings"
)

// Comparator compares two versions of the same ecosystem.
// It returns -1, 0, +1 and ok=false if either version is unparseable.
type Comparator func(a, b string) (int, bool)

// For returns the comparator for an OSV ecosystem name.
func For(ecosystem string) Comparator {
	switch strings.ToLower(ecosystem) {
	case "pypi":
		return ComparePEP440
	case "maven":
		return CompareMaven
	case "rubygems":
		return CompareGem
	case "go", "npm", "crates.io", "nuget", "packagist", "pub", "hex", "semver":
		return CompareSemverLike
	default:
		return nil
	}
}

// ---------- semver-like (Go, npm, crates.io, NuGet, Packagist) ----------

type semverLike struct {
	nums []*big.Int
	pre  []string // nil = release
}

var semverRe = regexp.MustCompile(`^[vV]?(\d+(?:\.\d+)*)(?:[-.]?((?:alpha|beta|rc|dev|pre|preview|snapshot|a|b|c|patch|p|pl)[0-9A-Za-z.-]*|[0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z.-]+)?$`)

func parseSemverLike(s string) (semverLike, bool) {
	s = strings.TrimSpace(s)
	m := semverRe.FindStringSubmatch(s)
	if m == nil {
		return semverLike{}, false
	}
	var v semverLike
	for _, p := range strings.Split(m[1], ".") {
		n, ok := new(big.Int).SetString(p, 10)
		if !ok {
			return semverLike{}, false
		}
		v.nums = append(v.nums, n)
	}
	if m[2] != "" {
		pre := strings.ToLower(m[2])
		// Composer/Packagist "patch"/"p"/"pl" suffixes are post-releases, treat as release.
		if pre == "patch" || strings.HasPrefix(pre, "pl") || (strings.HasPrefix(pre, "p") && len(pre) > 1 && isDigits(pre[1:])) {
			return v, true
		}
		v.pre = strings.FieldsFunc(pre, func(r rune) bool { return r == '.' || r == '-' })
		if len(v.pre) == 0 {
			v.pre = []string{pre}
		}
	}
	return v, true
}

// CompareSemverLike compares SemVer 2.0 and dotted-numeric versions with
// any number of components (missing components are treated as zero).
func CompareSemverLike(a, b string) (int, bool) {
	va, ok1 := parseSemverLike(a)
	vb, ok2 := parseSemverLike(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	n := max(len(va.nums), len(vb.nums))
	for i := 0; i < n; i++ {
		x, y := big.NewInt(0), big.NewInt(0)
		if i < len(va.nums) {
			x = va.nums[i]
		}
		if i < len(vb.nums) {
			y = vb.nums[i]
		}
		if c := x.Cmp(y); c != 0 {
			return c, true
		}
	}
	switch {
	case va.pre == nil && vb.pre == nil:
		return 0, true
	case va.pre == nil:
		return 1, true
	case vb.pre == nil:
		return -1, true
	}
	return compareIdentifiers(va.pre, vb.pre), true
}

func compareIdentifiers(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aNum := new(big.Int).SetString(a[i], 10)
		bn, bNum := new(big.Int).SetString(b[i], 10)
		switch {
		case aNum && bNum:
			if c := an.Cmp(bn); c != 0 {
				return c
			}
		case aNum:
			return -1
		case bNum:
			return 1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(a), len(b))
}

// ---------- PEP 440 ----------

type pep440 struct {
	epoch   *big.Int
	release []*big.Int
	preKind int // -1 none ; 0 a ; 1 b ; 2 rc
	preNum  *big.Int
	post    *big.Int // nil = none
	dev     *big.Int // nil = none
}

var pep440Re = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|alpha|b|beta|rc|c|pre|preview)[-_.]?(\d*))?(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d*)))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

func parsePEP440(s string) (pep440, bool) {
	m := pep440Re.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return pep440{}, false
	}
	v := pep440{epoch: big.NewInt(0), preKind: -1}
	if m[1] != "" {
		v.epoch, _ = new(big.Int).SetString(m[1], 10)
	}
	for _, p := range strings.Split(m[2], ".") {
		n, _ := new(big.Int).SetString(p, 10)
		v.release = append(v.release, n)
	}
	// trim trailing zeros: 1.0 == 1.0.0
	for len(v.release) > 1 && v.release[len(v.release)-1].Sign() == 0 {
		v.release = v.release[:len(v.release)-1]
	}
	if m[3] != "" {
		switch m[3] {
		case "a", "alpha":
			v.preKind = 0
		case "b", "beta":
			v.preKind = 1
		default:
			v.preKind = 2
		}
		v.preNum = numOrZero(m[4])
	}
	if m[5] != "" {
		v.post = numOrZero(m[5])
	} else if m[6] != "" {
		v.post = numOrZero(m[7])
	}
	if m[8] != "" {
		v.dev = numOrZero(m[9])
	}
	return v, true
}

// ComparePEP440 compares Python package versions per PEP 440 (local labels ignored).
func ComparePEP440(a, b string) (int, bool) {
	va, ok1 := parsePEP440(a)
	vb, ok2 := parsePEP440(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if c := va.epoch.Cmp(vb.epoch); c != 0 {
		return c, true
	}
	n := max(len(va.release), len(vb.release))
	for i := 0; i < n; i++ {
		x, y := big.NewInt(0), big.NewInt(0)
		if i < len(va.release) {
			x = va.release[i]
		}
		if i < len(vb.release) {
			y = vb.release[i]
		}
		if c := x.Cmp(y); c != 0 {
			return c, true
		}
	}
	// Ordering key per PEP 440: dev-only < pre < release < post.
	ka, kb := pepPhase(va), pepPhase(vb)
	if c := cmpInt(ka, kb); c != 0 {
		return c, true
	}
	if va.preKind >= 0 && vb.preKind >= 0 {
		if c := cmpInt(va.preKind, vb.preKind); c != 0 {
			return c, true
		}
		if c := va.preNum.Cmp(vb.preNum); c != 0 {
			return c, true
		}
	}
	if c := cmpOptional(va.post, vb.post, -1); c != 0 {
		return c, true
	}
	// a dev release sorts before the same version without dev
	return cmpOptional(va.dev, vb.dev, 1), true
}

// pepPhase: 0 = dev release of a final (1.0.dev1), 1 = pre-release, 2 = final/post.
func pepPhase(v pep440) int {
	switch {
	case v.preKind < 0 && v.post == nil && v.dev != nil:
		return 0
	case v.preKind >= 0:
		return 1
	default:
		return 2
	}
}

// cmpOptional compares optional numbers; missingSign says how "absent" sorts
// relative to present (-1: absent is lower, +1: absent is higher).
func cmpOptional(a, b *big.Int, missingSign int) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return missingSign
	case b == nil:
		return -missingSign
	default:
		return a.Cmp(b)
	}
}

// ---------- Maven (simplified ComparableVersion) ----------

var mavenQualifiers = map[string]int{
	"alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3, "rc": 4, "cr": 4,
	"snapshot": 5, "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7,
}

type mavenItem struct {
	num  *big.Int
	qual string
}

func parseMaven(s string) []mavenItem {
	s = strings.ToLower(strings.TrimSpace(s))
	var items []mavenItem
	var cur strings.Builder
	flush := func() {
		t := cur.String()
		cur.Reset()
		if t == "" {
			return
		}
		if n, ok := new(big.Int).SetString(t, 10); ok {
			items = append(items, mavenItem{num: n})
		} else {
			items = append(items, mavenItem{qual: t})
		}
	}
	prevDigit := false
	for i, r := range s {
		isDigit := r >= '0' && r <= '9'
		if r == '.' || r == '-' || r == '_' {
			flush()
			prevDigit = false
			continue
		}
		if i > 0 && cur.Len() > 0 && isDigit != prevDigit {
			flush()
		}
		cur.WriteRune(r)
		prevDigit = isDigit
	}
	flush()
	// strip trailing zero / release-equivalent items
	for len(items) > 1 {
		last := items[len(items)-1]
		if (last.num != nil && last.num.Sign() == 0) || (last.num == nil && mavenQualifiers[last.qual] == 6 && last.qual != "") {
			items = items[:len(items)-1]
			continue
		}
		break
	}
	return items
}

func mavenItemCmp(a, b *mavenItem) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -mavenItemCmp(b, nil)
	case b == nil:
		if a.num != nil {
			return a.num.Sign()
		}
		return cmpInt(qualRank(a.qual), 6)
	case a.num != nil && b.num != nil:
		return a.num.Cmp(b.num)
	case a.num != nil:
		return 1 // number > qualifier
	case b.num != nil:
		return -1
	default:
		ra, rb := qualRank(a.qual), qualRank(b.qual)
		if ra != rb {
			return cmpInt(ra, rb)
		}
		return strings.Compare(a.qual, b.qual)
	}
}

func qualRank(q string) int {
	if r, ok := mavenQualifiers[q]; ok {
		return r
	}
	return 8 // unknown qualifiers sort after known ones
}

// CompareMaven compares Maven versions (simplified ComparableVersion semantics).
func CompareMaven(a, b string) (int, bool) {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return 0, false
	}
	ia, ib := parseMaven(a), parseMaven(b)
	n := max(len(ia), len(ib))
	for i := 0; i < n; i++ {
		var x, y *mavenItem
		if i < len(ia) {
			x = &ia[i]
		}
		if i < len(ib) {
			y = &ib[i]
		}
		if c := mavenItemCmp(x, y); c != 0 {
			return c, true
		}
	}
	return 0, true
}

// ---------- RubyGems ----------

// CompareGem compares RubyGems versions: segments split on '.', letters mark prereleases.
func CompareGem(a, b string) (int, bool) {
	sa, ok1 := gemSegments(a)
	sb, ok2 := gemSegments(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	n := max(len(sa), len(sb))
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(sa) {
			x = sa[i]
		}
		if i < len(sb) {
			y = sb[i]
		}
		xn, xNum := new(big.Int).SetString(x, 10)
		yn, yNum := new(big.Int).SetString(y, 10)
		switch {
		case xNum && yNum:
			if c := xn.Cmp(yn); c != 0 {
				return c, true
			}
		case xNum:
			return 1, true
		case yNum:
			return -1, true
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c, true
			}
		}
	}
	return 0, true
}

var gemRe = regexp.MustCompile(`^[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z.-]+)?$`)
var gemSplitRe = regexp.MustCompile(`[0-9]+|[a-zA-Z]+`)

func gemSegments(s string) ([]string, bool) {
	s = strings.TrimSpace(s)
	if !gemRe.MatchString(s) {
		return nil, false
	}
	s = strings.ReplaceAll(s, "-", ".pre.")
	segs := gemSplitRe.FindAllString(s, -1)
	for len(segs) > 1 && segs[len(segs)-1] == "0" {
		segs = segs[:len(segs)-1]
	}
	return segs, true
}

// ---------- helpers ----------

func numOrZero(s string) *big.Int {
	if s == "" {
		return big.NewInt(0)
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return big.NewInt(0)
	}
	return n
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
