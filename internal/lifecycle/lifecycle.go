// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package lifecycle says how old a device's operating system is and
// whether it is still supported, from the version alone.
//
// # Why it is computed here
//
// A device tool reports a version — "macOS 13.6.1", "10.0.19045.4529" — and
// rarely whether that version is still patched. Whether it is decides
// whether every vulnerability found after its end of support stays open on
// that machine for ever, which is the question an assessor asks. So the
// version is looked up against the release lines of each operating system:
// when the line came out, when its security support ends, and the newest
// version in it. A device whose tool says nothing about its age still gets
// one.
//
// # Where the dates come from
//
// endoflife.date, whose data is MIT-licensed, embedded as lifecycle.json
// and refreshed by hand with scripts/genlifecycle. The program never
// fetches it: a device page must not depend on a third party being up,
// and a lookup must not tell anybody which versions this estate runs.
package lifecycle

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

//go:embed lifecycle.json
var data []byte

// Cycle is one release line: macOS 14, iOS 17, Windows 11 23H2.
type Cycle struct {
	Cycle      string `json:"cycle"`
	Label      string `json:"label"`
	Released   string `json:"released"`
	EOL        string `json:"eol,omitempty"`
	Latest     string `json:"latest,omitempty"`
	LatestDate string `json:"latest_date,omitempty"`
}

type catalogue struct {
	Source   string             `json:"source"`
	Fetched  string             `json:"fetched"`
	Products map[string][]Cycle `json:"products"`
}

var cat = func() catalogue {
	var c catalogue
	if err := json.Unmarshal(data, &c); err != nil {
		panic("lifecycle.json: " + err.Error())
	}
	return c
}()

// Fetched is the day the embedded dates were taken, so a page can say how
// current its own knowledge is.
func Fetched() string { return cat.Fetched }

// Currency is where a version stands.
type Currency string

const (
	// Current: a supported line, at its newest version or with no newer
	// one known.
	Current Currency = "current"
	// UpdateAvailable: a supported line with a newer version in it.
	UpdateAvailable Currency = "update"
	// EndingSoon: support ends within the warning window.
	EndingSoon Currency = "ending"
	// Unsupported: past the end of security support.
	Unsupported Currency = "unsupported"
	// Unknown: no line matches, so nothing is claimed.
	Unknown Currency = "unknown"
)

// Warning is how close to the end of support counts as ending soon.
const Warning = 90 * 24 * time.Hour

// Assessment is what the version says about a device.
type Assessment struct {
	Product  string
	Cycle    Cycle
	Currency Currency
	// Age is how long ago the line was released: the age of what the
	// device runs, worked out when no tool reports it.
	Age time.Duration
	// EOL is the end of security support, zero when none is announced.
	EOL time.Time
	// Latest is the newest version of the line, when it is newer than the
	// device's.
	Latest string
	// Newer is how many later lines have been released since.
	Newer int
}

// Assess looks a device's operating system up.
func Assess(osName, version string, now time.Time) Assessment {
	product, cycle, ok := match(osName, version)
	if !ok {
		return Assessment{Currency: Unknown}
	}
	a := Assessment{Product: product, Cycle: cycle}
	if t, err := time.Parse("2006-01-02", cycle.Released); err == nil {
		a.Age = now.Sub(t)
	}
	for _, c := range cat.Products[product] {
		if c.Released > cycle.Released && sameTrack(product, c, cycle) {
			a.Newer++
		}
	}
	if t, err := time.Parse("2006-01-02", cycle.EOL); err == nil {
		a.EOL = t
	}
	switch {
	case !a.EOL.IsZero() && !now.Before(a.EOL):
		a.Currency = Unsupported
	case !a.EOL.IsZero() && a.EOL.Sub(now) <= Warning:
		a.Currency = EndingSoon
	case cycle.Latest != "" && product != "windows" && product != "android" && older(version, cycle.Latest):
		a.Currency = UpdateAvailable
		a.Latest = cycle.Latest
	default:
		a.Currency = Current
	}
	return a
}

// sameTrack is whether a later line is a successor to this one. For
// Windows that means the same edition (Home and Pro, or Enterprise), and
// never a long-term servicing line, which is not what a desktop moves to.
func sameTrack(product string, later, this Cycle) bool {
	if product != "windows" {
		return true
	}
	if strings.Contains(later.Cycle, "lts") || strings.Contains(later.Cycle, "iot") {
		return false
	}
	a, b := edition(this.Cycle), edition(later.Cycle)
	return a == "" || b == "" || a == b
}

// edition is the w or e a Windows line ends with, or empty for one line
// shared by every edition.
func edition(cycle string) string {
	if i := strings.LastIndex(cycle, "-"); i >= 0 {
		if e := cycle[i+1:]; e == "w" || e == "e" {
			return e
		}
	}
	return ""
}

// match finds the release line a version belongs to.
func match(osName, version string) (string, Cycle, bool) {
	name := strings.ToLower(osName + " " + version)
	version = strings.TrimSpace(version)
	switch {
	case strings.Contains(name, "ipados"):
		return byMajor("ipados", version)
	case strings.Contains(name, "ios") && !strings.Contains(name, "macos"):
		return byMajor("ios", version)
	case strings.Contains(name, "mac") || strings.Contains(name, "os x") || strings.Contains(name, "darwin"):
		return byMajor("macos", version)
	case strings.Contains(name, "android"):
		return byMajor("android", version)
	case strings.Contains(name, "windows"):
		return windows(name, version)
	}
	return "", Cycle{}, false
}

// byMajor matches 14.6.1 to line 14. macOS 10 lines are 10.15, 10.14…, so
// for them the minor is part of the line.
func byMajor(product, version string) (string, Cycle, bool) {
	parts := strings.Split(version, ".")
	if len(parts) == 0 || parts[0] == "" {
		return "", Cycle{}, false
	}
	want := parts[0]
	if product == "macos" && want == "10" && len(parts) > 1 {
		want = "10." + parts[1]
	}
	for _, c := range cat.Products[product] {
		if c.Cycle == want {
			return product, c, true
		}
	}
	return "", Cycle{}, false
}

// windows matches by build number: 10.0.22631.4317 is build 22631, which
// is the line whose newest version is 10.0.22631. Home and Pro (w) unless
// the name says Enterprise or Education (e), whose support runs longer.
func windows(name, version string) (string, Cycle, bool) {
	build := ""
	for _, f := range strings.FieldsFunc(version, func(r rune) bool { return r == '.' || r == ' ' }) {
		if n, err := strconv.Atoi(f); err == nil && n >= 10000 {
			build = f
			break
		}
	}
	if build == "" {
		return "", Cycle{}, false
	}
	edition := "w"
	if strings.Contains(name, "enterprise") || strings.Contains(name, "education") {
		edition = "e"
	}
	var fallback *Cycle
	for i, c := range cat.Products["windows"] {
		if !strings.HasSuffix(c.Latest, "."+build) || strings.Contains(c.Cycle, "lts") || strings.Contains(c.Cycle, "iot") {
			continue
		}
		if strings.HasSuffix(c.Cycle, "-"+edition) {
			return "windows", c, true
		}
		if fallback == nil {
			fallback = &cat.Products["windows"][i]
		}
		// Windows 10 22H2 is one line for every edition.
		if !strings.Contains(c.Cycle, "-e") && !strings.Contains(c.Cycle, "-w") {
			return "windows", c, true
		}
	}
	if fallback != nil {
		return "windows", *fallback, true
	}
	return "", Cycle{}, false
}

// older reports whether version a is before b, comparing numerically part
// by part; a part that is not a number ends the comparison as equal.
func older(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := 0, 0
		if i < len(pa) {
			n, err := strconv.Atoi(pa[i])
			if err != nil {
				return false
			}
			x = n
		}
		if i < len(pb) {
			n, err := strconv.Atoi(pb[i])
			if err != nil {
				return false
			}
			y = n
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// Words is the age of a line as somebody says it: "2 years 3 months".
func Words(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days < 0 {
		return "not out yet"
	}
	// Whole months, counted from the total. Counting from the remainder of
	// the year in thirty-day months said "4 years 12 months" for the last
	// five days of every year.
	total := days * 12 / 365
	years, months := total/12, total%12
	plural := func(n int, w string) string {
		if n == 1 {
			return fmt.Sprintf("1 %s", w)
		}
		return fmt.Sprintf("%d %ss", n, w)
	}
	switch {
	case years > 0 && months > 0:
		return plural(years, "year") + " " + plural(months, "month")
	case years > 0:
		return plural(years, "year")
	case months > 0:
		return plural(months, "month")
	default:
		return plural(days, "day")
	}
}
