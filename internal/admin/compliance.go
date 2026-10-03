// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/estate"
	"github.com/quilzo/quilzo/internal/lifecycle"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Device compliance on the workforce screens: each machine measured
// against estate.DeviceControls, and the operating system it runs judged
// against its release's support dates (internal/lifecycle).
//
// # The charts
//
// Two donuts, because each answers "what share of the machines" at a
// glance, with at most four parts: compliant, with violations, not
// measured; and current, behind, unsupported, unknown. The parts are status
// colours, so each carries its icon and word in the legend and its own
// label, and never meets a neighbour it could be mistaken for: in ring
// order, red never touches green, and the grey of "unknown" is a step apart
// from both (checked with the palette validator for both themes).
//
// Everything else is a comparison of counts, so it is a bar chart in one
// colour: which controls fail most, which platforms there are.

// donutSeg is one part of a donut.
type donutSeg struct {
	Label, Tone, Icon string
	Count             int
	Pct               string
	// D is the arc, drawn as a stroke along the ring.
	D   string
	Tip string
	// LX, LY place the direct label outside the ring; LAnchor aligns it.
	LX, LY  float64
	LAnchor string
}

// donut is a part-to-whole chart of a few status classes.
type donut struct {
	Label        string
	Total        int
	Center, Unit string
	Segs         []donutSeg
}

type donutPart struct {
	label, tone, icon string
	n                 int
}

// The ring: centre (110, 110), radius 72, a 20-wide stroke, and 2 pixels
// of surface between parts.
const (
	ringR   = 72.0
	ringGap = 2.0
)

func makeDonut(label, unit string, parts []donutPart) donut {
	d := donut{Label: label, Unit: unit}
	for _, p := range parts {
		d.Total += p.n
	}
	d.Center = fmt.Sprint(d.Total)
	if d.Total == 0 {
		return d
	}
	angle := -math.Pi / 2
	gap := ringGap / ringR
	shown := 0
	for _, p := range parts {
		if p.n > 0 {
			shown++
		}
	}
	for _, p := range parts {
		if p.n == 0 {
			continue
		}
		sweep := 2 * math.Pi * float64(p.n) / float64(d.Total)
		s := donutSeg{Label: p.label, Tone: p.tone, Icon: p.icon, Count: p.n,
			Pct: fmt.Sprintf("%d%%", int(math.Round(100*float64(p.n)/float64(d.Total))))}
		s.Tip = fmt.Sprintf("%s: %d (%s)", p.label, p.n, s.Pct)
		a0, a1 := angle, angle+sweep
		if shown > 1 {
			a0 += gap / 2
			a1 -= gap / 2
		}
		s.D = arc(110, 110, ringR, a0, a1)
		mid := (a0 + a1) / 2
		s.LX, s.LY = 110+(ringR+26)*math.Cos(mid), 110+(ringR+26)*math.Sin(mid)+4
		switch {
		case math.Cos(mid) > 0.3:
			s.LAnchor = "start"
		case math.Cos(mid) < -0.3:
			s.LAnchor = "end"
		default:
			s.LAnchor = "middle"
		}
		d.Segs = append(d.Segs, s)
		angle += sweep
	}
	return d
}

// arc is an SVG path along a circle from a0 to a1 (radians, clockwise);
// a whole circle is drawn as two halves, which a single arc cannot be.
func arc(cx, cy, r, a0, a1 float64) string {
	pt := func(a float64) string {
		return fmt.Sprintf("%.2f %.2f", cx+r*math.Cos(a), cy+r*math.Sin(a))
	}
	if a1-a0 >= 2*math.Pi-1e-9 {
		mid := a0 + math.Pi
		return fmt.Sprintf("M %s A %.0f %.0f 0 1 1 %s A %.0f %.0f 0 1 1 %s", pt(a0), r, r, pt(mid), r, r, pt(a0))
	}
	large := 0
	if a1-a0 > math.Pi {
		large = 1
	}
	return fmt.Sprintf("M %s A %.0f %.0f 0 %d 1 %s", pt(a0), r, r, large, pt(a1))
}

// deviceRow is a machine's compliance on the Machines screen.
type deviceRow struct {
	OS, Age, AgeTitle    string
	Support, SupportTone string
	SupportTitle         string
	Status, StatusTone   string
	Violations           []violation
	Unknown              int
}

type violation struct {
	Name, Detail, Tone, By string
}

// sevTone is the status tone a severity is shown in.
func sevTone(s telemetry.Severity) string {
	switch {
	case s >= telemetry.SeverityCritical:
		return "critical"
	case s >= telemetry.SeverityHigh:
		return "serious"
	case s >= telemetry.SeverityMedium:
		return "warning"
	}
	return "low"
}

func complianceRow(c estate.Compliance, now time.Time) deviceRow {
	r := deviceRow{OS: strings.TrimSpace(c.OS + " " + c.Version)}
	if r.OS == "" {
		r.OS = "not reported"
	}
	a := c.Lifecycle
	if a.Currency != lifecycle.Unknown {
		r.Age = lifecycle.Words(a.Age)
		r.AgeTitle = fmt.Sprintf("%s came out on %s", a.Cycle.Label, a.Cycle.Released)
		if a.Newer > 0 {
			r.AgeTitle += "; " + countOf(a.Newer, "newer release", "newer releases") + " since"
		}
	}
	switch a.Currency {
	case lifecycle.Current:
		r.Support, r.SupportTone = "Current", "good"
		r.SupportTitle = a.Cycle.Label + ", newest version"
	case lifecycle.UpdateAvailable:
		r.Support, r.SupportTone = "Update due", "warning"
		r.SupportTitle = a.Latest + " is out"
	case lifecycle.EndingSoon:
		days := int(a.EOL.Sub(now).Hours()/24) + 1
		r.Support, r.SupportTone = fmt.Sprintf("Ends in %d days", days), "warning"
		r.SupportTitle = "Security support ends " + a.EOL.Format("2 January 2006")
	case lifecycle.Unsupported:
		r.Support, r.SupportTone = "Unsupported", "critical"
		r.SupportTitle = "No security fixes since " + a.EOL.Format("2 January 2006")
	default:
		r.Support, r.SupportTone = "Unknown", "unknown"
		r.SupportTitle = "Not a version this program has dates for"
	}
	for _, v := range c.Violations() {
		r.Violations = append(r.Violations, violation{Name: v.Control.Name, Detail: v.Detail,
			Tone: sevTone(v.Control.Severity), By: strings.Join(v.By, ", ")})
	}
	for _, res := range c.Results {
		if res.Verdict == estate.Unknown {
			r.Unknown++
		}
	}
	switch c.Status {
	case "compliant":
		r.Status, r.StatusTone = "Compliant", "good"
	case "violations":
		n := len(r.Violations)
		r.Status = fmt.Sprintf("%d violation", n)
		if n != 1 {
			r.Status += "s"
		}
		r.StatusTone = sevTone(c.Worst)
		if r.StatusTone == "low" {
			r.StatusTone = "warning"
		}
	default:
		r.Status, r.StatusTone = "Not measured", "unknown"
	}
	return r
}

// complianceSummary is what the overview shows of every machine.
type complianceSummary struct {
	Machines             int
	Compliance, Currency donut
	Failing              []barItem
	Platforms            wfChart
	Tests                []complianceTest
	TestsFailing         int
	Fetched              string
	// Stale says the release dates are old enough that new versions will
	// be shown as unknown, and how to refresh them.
	Stale string
}

// barItem is one row of a bar list: the words, the count, and the bar
// drawn to scale against the largest.
type barItem struct {
	Label, Width, Tone, Title string
	Value                     int
}

type complianceTest struct {
	Name, Category, Source string
	Passing                *bool
	Failing                int
}

func summarise(e *estate.Estate, now time.Time) complianceSummary {
	s := complianceSummary{Fetched: lifecycle.Fetched()}
	if t, err := time.Parse("2006-01-02", s.Fetched); err == nil && now.Sub(t) > 180*24*time.Hour {
		s.Stale = fmt.Sprintf("The release dates were taken %s ago, so versions released since are shown as unknown. "+
			"Refresh them with go run ./scripts/genlifecycle.", lifecycle.Words(now.Sub(t)))
	}
	status := map[string]int{}
	currency := map[lifecycle.Currency]int{}
	failing := map[string]int{}
	platforms := map[string]int{}
	for _, m := range e.Machines {
		c := estate.Comply(m, now)
		s.Machines++
		status[c.Status]++
		currency[c.Lifecycle.Currency]++
		for _, v := range c.Violations() {
			failing[v.Control.Name]++
		}
		platforms[platformOf(c.OS)]++
	}
	s.Compliance = makeDonut("Machines by compliance", "machines", []donutPart{
		{"Compliant", "good", "check_circle", status["compliant"]},
		{"Not measured", "unknown", "help", status["unknown"]},
		{"With violations", "critical", "dangerous", status["violations"]},
	})
	s.Currency = makeDonut("Machines by operating system support", "machines", []donutPart{
		{"Current", "good", "check_circle", currency[lifecycle.Current]},
		{"Update due or ending", "warning", "error", currency[lifecycle.UpdateAvailable] + currency[lifecycle.EndingSoon]},
		{"Unsupported", "critical", "dangerous", currency[lifecycle.Unsupported]},
		{"Unknown version", "unknown", "help", currency[lifecycle.Unknown]},
	})
	type fail struct {
		ctl estate.DeviceControl
		n   int
	}
	var fails []fail
	for _, ctl := range estate.DeviceControls {
		if n := failing[ctl.Name]; n > 0 {
			fails = append(fails, fail{ctl, n})
		}
	}
	sort.SliceStable(fails, func(i, j int) bool { return fails[i].n > fails[j].n })
	max := 0
	for _, f := range fails {
		if f.n > max {
			max = f.n
		}
	}
	for _, f := range fails {
		s.Failing = append(s.Failing, barItem{Label: f.ctl.Name, Value: f.n,
			Width: fmt.Sprintf("%.1f", 100*float64(f.n)/float64(max)), Tone: sevTone(f.ctl.Severity),
			Title: fmt.Sprintf("%s: %d machines fail it, and %s", f.ctl.Name, f.n, f.ctl.Why)})
	}
	var pbars []wfBar
	var pvals []int
	for _, p := range sortedKeysByCount(platforms) {
		pbars = append(pbars, wfBar{Label: p, Value: fmt.Sprint(platforms[p]), Tone: "series",
			Title: fmt.Sprintf("%s: %d machines", p, platforms[p])})
		pvals = append(pvals, platforms[p])
	}
	s.Platforms = chart("Machines by platform", pbars, pvals)
	for _, c := range e.Controls {
		t := complianceTest{Name: c.Name, Category: c.Category, Source: c.ID.Issuer, Passing: c.Passing, Failing: c.Failing}
		if c.Passing != nil && !*c.Passing {
			s.TestsFailing++
		}
		s.Tests = append(s.Tests, t)
	}
	sort.SliceStable(s.Tests, func(i, j int) bool {
		fi := s.Tests[i].Passing != nil && !*s.Tests[i].Passing
		fj := s.Tests[j].Passing != nil && !*s.Tests[j].Passing
		if fi != fj {
			return fi
		}
		return s.Tests[i].Failing > s.Tests[j].Failing
	})
	return s
}

func platformOf(os string) string {
	low := strings.ToLower(os)
	switch {
	case strings.Contains(low, "ipados"):
		return "iPadOS"
	case strings.Contains(low, "ios"):
		return "iOS"
	case strings.Contains(low, "mac"):
		return "macOS"
	case strings.Contains(low, "windows"):
		return "Windows"
	case strings.Contains(low, "android"):
		return "Android"
	case strings.Contains(low, "linux"), strings.Contains(low, "ubuntu"):
		return "Linux"
	case low == "":
		return "Not reported"
	}
	return "Other"
}

func sortedKeysByCount(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}
