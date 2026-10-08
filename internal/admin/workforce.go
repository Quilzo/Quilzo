// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/estate"
)

// The workforce screens: people's risk, from what their tools say.
//
// Admin only, like the findings they sit beside. A person's score is a file
// on an employee, so it is shown to the people who administer security and
// no one else, and opening one is written to the audit log with who looked:
// GDPR expects the people profiled to be able to learn who saw the profile.
//
// Charts are drawn here, as SVG, with no script. Each carries its values in
// a <title> for the pointer and in a table beside it for everybody else —
// a chart whose numbers can only be read by hovering is one a keyboard or
// a screen reader cannot read at all.

// Workforce is what the screens read.
type Workforce struct {
	// Load joins the tools' latest reads and runs the checks.
	Load func(now time.Time) (*estate.Estate, estate.Outcome, error)
	// History is the daily aggregates, oldest first.
	History func() ([]estate.Summary, error)
	// Status says when the tools were last read and whether a read is
	// under way; Sync starts one in the background.
	Status func() (SyncStatus, error)
	Sync   func(by string) error
}

// SyncStatus is the state of reading the tools.
type SyncStatus struct {
	Last     time.Time
	Tools    int
	Problems []string
	Running  bool
	Every    time.Duration
}

// wfLoad is the shared start of every workforce page.
func (s *Server) wfLoad(w http.ResponseWriter, r *http.Request, nav,
	title, tpl string) (principal, *estate.Estate, estate.Outcome,
	map[string]any, bool) {

	p, ok := s.securityReader(w, r)
	if !ok {
		return principal{}, nil, estate.Outcome{}, nil, false
	}
	data := map[string]any{"Nav": nav, "Title": title, "Principal": p}
	if s.Workforce == nil || s.Workforce.Load == nil {
		data["Unavailable"] = "This build was started without the estate. " +
			"That is not a workforce with no risk in it: a page showing " +
			"nothing here would say nothing is wrong, and this build cannot " +
			"see whether anything is."
		s.render(w, r, tpl, data)
		return p, nil, estate.Outcome{}, nil, false
	}
	e, o, err := s.Workforce.Load(time.Now().UTC())
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, tpl, data)
		return p, nil, estate.Outcome{}, nil, false
	}
	// A made-up company's data says so on every screen it is shown on.
	for _, snap := range e.Sources {
		if snap.Sample {
			data["Sample"] = true
		}
	}
	return p, e, o, data, true
}

// wfTile is one number at the top of the page.
type wfTile struct {
	Label, Value, Note string
	Tone               string
}

// wfBar is one bar of a horizontal bar chart, in viewBox units.
type wfBar struct {
	Label, Value, Title, Tone, Href string
	Y, W, H, TextX, TextY           float64
	// D is the bar's outline: square where it meets the baseline, rounded
	// by 4 at the end that carries the value.
	D string
}

// wfCell is one cell of the heatmap.
type wfCell struct {
	Value, Title, Step string
	Dark               bool
}

type wfRow struct {
	Label, Title string
	Count        int
	Cells        []wfCell
}

// wfPoint is one point of the trend line.
type wfPoint struct {
	X, Y        float64
	Date, Value string
}

func bandTone(b estate.Band) string {
	switch b {
	case estate.BandCritical:
		return "critical"
	case estate.BandHigh:
		return "serious"
	case estate.BandModerate:
		return "warning"
	}
	return "good"
}

func bandLabel(b estate.Band) string {
	return strings.ToUpper(string(b)[:1]) + string(b)[1:]
}

var areaLabel = map[estate.Area]string{
	estate.AreaPhishing: "Phishing", estate.AreaTraining: "Training",
	estate.AreaPolicies: "Policies", estate.AreaDevice: "Device",
	estate.AreaPatching: "Patching", estate.AreaLifecycle: "Left",
}

// hbars lays out a horizontal bar chart: label column, then bars scaled to
// the largest value, value at the tip. Bars are 20 units thick with 12 of
// air, so the chart reads as marks rather than as blocks.
func hbars(items []wfBar, values []int) ([]wfBar, float64) {
	const top, thick, gap, x0, width = 4.0, 20.0, 12.0, 0.0, 440.0
	most := 1
	for _, v := range values {
		if v > most {
			most = v
		}
	}
	for i := range items {
		items[i].Y = top + float64(i)*(thick+gap)
		items[i].H = thick
		w := math.Round(float64(values[i])/float64(most)*width*10) / 10
		if values[i] > 0 && w < 3 {
			// Visible, but never claiming to be more than it is.
			w = 3
		}
		items[i].W = w
		items[i].D = barPath(x0, items[i].Y, w, thick)
		items[i].TextX = x0 + w + 8
		items[i].TextY = items[i].Y + thick/2 + 5
	}
	return items, top + float64(len(items))*(thick+gap)
}

func barPath(x, y, w, h float64) string {
	if w <= 0 {
		return ""
	}
	r := 4.0
	if w < r {
		r = w
	}
	return fmt.Sprintf("M%.1f %.1fh%.1fq%.1f 0 %.1f %.1fv%.1fq0 %.1f -%.1f %.1fh-%.1fz",
		x, y, w-r, r, r, r, h-2*r, r, r, r, w-r)
}

func (s *Server) handleWorkforce(w http.ResponseWriter, r *http.Request) {
	_, e, o, data, ok := s.wfLoad(w, r, "workforce", "Workforce risk",
		"workforce.html")
	if !ok {
		return
	}
	data["Message"], data["Error"] = r.URL.Query().Get("m"),
		r.URL.Query().Get("e")
	now := time.Now().UTC()
	scores := e.Scores(now)

	// Filters, one row, scoping everything below them.
	q := r.URL.Query()
	dept, bandQ := q.Get("department"), estate.Band(q.Get("band"))
	var departments []string
	seenDept := map[string]bool{}
	for _, sc := range scores {
		d := deptOf(sc)
		if !seenDept[d] {
			seenDept[d] = true
			departments = append(departments, d)
		}
	}
	sort.Strings(departments)
	var shown []estate.Score
	for _, sc := range scores {
		if dept != "" && deptOf(sc) != dept {
			continue
		}
		if bandQ != "" && sc.Band != bandQ {
			continue
		}
		shown = append(shown, sc)
	}
	scoped := estate.Summarise(shown, now)
	data["Departments"], data["Department"] = departments, dept
	data["Band"], data["BandList"] = string(bandQ), estate.Bands()
	data["Filtered"] = dept != "" || bandQ != ""

	// The one number the page leads with.
	atRisk := scoped.Bands[estate.BandHigh] + scoped.Bands[estate.BandCritical]
	data["Hero"] = atRisk
	data["HeroOf"] = scoped.Scored
	joined := 0
	for _, p := range e.People {
		if len(p.Sources) > 1 {
			joined++
		}
	}
	bySerial := 0
	for _, m := range e.Machines {
		if len(m.Sources) > 1 {
			bySerial++
		}
	}
	data["Tiles"] = []wfTile{
		{Label: "Average score", Value: fmt.Sprintf("%.0f", scoped.Mean),
			Note: "out of 100"},
		{Label: "People known to two or more tools",
			Value: fmt.Sprintf("%d of %d", joined, len(e.People))},
		{Label: "Machines matched by serial",
			Value: fmt.Sprintf("%d of %d", bySerial, len(e.Machines))},
		{Label: "Disagreements found", Value: fmt.Sprint(len(o.Findings)),
			Tone: map[bool]string{true: "serious"}[len(o.Findings) > 0]},
	}

	// Bands: how many people in each, as bars with the count at the tip.
	var bands []wfBar
	var bandVals []int
	for _, b := range estate.Bands() {
		n := scoped.Bands[b]
		href := wfHref(dept, string(b))
		bands = append(bands, wfBar{Label: bandLabel(b), Value: fmt.Sprint(n),
			Tone: bandTone(b), Href: href,
			Title: fmt.Sprintf("%s: %d people", bandLabel(b), n)})
		bandVals = append(bandVals, n)
	}
	data["Bands"] = chart("People in each band", bands, bandVals)

	// Areas: how many people have a reason in each.
	var areas []wfBar
	var areaVals []int
	for _, a := range estate.Areas() {
		n := scoped.Areas[a]
		areas = append(areas, wfBar{Label: areaLabel[a], Value: fmt.Sprint(n),
			Tone: "series", Title: fmt.Sprintf("%s: %d people", areaLabel[a], n)})
		areaVals = append(areaVals, n)
	}
	data["Areas"] = chart("People with a reason in each area", areas, areaVals)

	// Heatmap: department by area, the share of each department with a
	// reason in each area. The twelve largest departments; the rest are
	// folded into one row rather than given colours nobody can tell apart.
	data["Heat"] = heatmap(shown)
	data["AreaNames"] = func() []string {
		var out []string
		for _, a := range estate.Areas() {
			out = append(out, areaLabel[a])
		}
		return out
	}()

	// The trend, from the daily aggregates.
	if s.Workforce.History != nil {
		hist, herr := s.Workforce.History()
		if herr == nil {
			pts, note := trend(hist)
			data["Trend"], data["TrendNote"] = pts, note
			if len(pts) > 0 {
				var line []string
				for _, p := range pts {
					line = append(line, fmt.Sprintf("%.1f,%.1f", p.X, p.Y))
				}
				data["TrendLine"] = strings.Join(line, " ")
				data["TrendEnd"] = pts[len(pts)-1]
				data["TrendStart"] = pts[0]
			}
			type day struct {
				Date           string
				Scored, AtRisk int
				Mean           float64
			}
			var days []day
			for _, d := range hist {
				days = append(days, day{Date: d.Date, Scored: d.Scored,
					Mean:   d.Mean,
					AtRisk: d.Bands[estate.BandHigh] + d.Bands[estate.BandCritical]})
			}
			data["History"] = days
		}
	}

	// The people, highest first.
	type personRow struct {
		estate.Score
		Dept, Tone, Top, Path string
		Meter                 int
	}
	var rows []personRow
	for _, sc := range shown {
		row := personRow{Score: sc, Dept: deptOf(sc), Tone: bandTone(sc.Band),
			Meter: sc.Points, Path: url.PathEscape(sc.Key)}
		if len(sc.Factors) > 0 {
			row.Top = sc.Factors[0].What
		}
		rows = append(rows, row)
	}
	data["People"] = rows

	// What the page could not see.
	type source struct{ Name, State string }
	var sources []source
	for _, name := range sortedStrings(e.Sources) {
		snap := e.Sources[name]
		var partial []string
		for ep, info := range snap.Endpoints {
			if !info.Complete {
				partial = append(partial, ep)
			}
		}
		sort.Strings(partial)
		state := "read " + wfAge(now.Sub(snap.At)) + " ago"
		if len(partial) > 0 {
			state += "; not read to the end: " + strings.Join(partial, ", ")
		}
		sources = append(sources, source{Name: name, State: state})
	}
	data["Sources"] = sources
	if s.Workforce.Status != nil {
		if st, serr := s.Workforce.Status(); serr == nil {
			data["Sync"] = st
			if !st.Last.IsZero() {
				data["SyncAge"] = wfAge(now.Sub(st.Last))
			}
			if st.Every > 0 {
				data["SyncEvery"] = st.Every.String()
			}
		}
	}
	data["Skipped"] = o.Skipped
	data["Notes"] = e.Notes
	data["Unplaced"] = e.Unplaced
	data["Weights"] = estate.Weights
	data["Compliance"] = summarise(e, time.Now().UTC())
	s.render(w, r, "workforce.html", data)
}

func wfHref(dept, band string) string {
	v := url.Values{}
	if dept != "" {
		v.Set("department", dept)
	}
	if band != "" {
		v.Set("band", band)
	}
	if len(v) == 0 {
		return "/workforce"
	}
	return "/workforce?" + v.Encode()
}

// wfChart is a bar chart ready to draw: its bars, its height and the name a
// screen reader announces.
type wfChart struct {
	Label string
	H     string
	Bars  []wfBar
}

func chart(label string, items []wfBar, values []int) wfChart {
	out, h := hbars(items, values)
	return wfChart{Label: label, H: fmt.Sprintf("%.0f", h), Bars: out}
}

func deptOf(sc estate.Score) string {
	if strings.TrimSpace(sc.Department) == "" {
		return "Not recorded"
	}
	return sc.Department
}

// heatSteps are the five steps of the one-hue scale the heatmap fills with,
// named for the CSS that colours them in each scheme.
func heatStep(share float64) (string, bool) {
	switch {
	case share <= 0:
		return "h0", false
	case share < 0.10:
		return "h1", false
	case share < 0.25:
		return "h2", false
	case share < 0.50:
		return "h3", true
	}
	return "h4", true
}

func heatmap(scores []estate.Score) []wfRow {
	per := map[string][]estate.Score{}
	for _, sc := range scores {
		per[deptOf(sc)] = append(per[deptOf(sc)], sc)
	}
	names := make([]string, 0, len(per))
	for d := range per {
		names = append(names, d)
	}
	sort.Slice(names, func(i, j int) bool {
		if len(per[names[i]]) != len(per[names[j]]) {
			return len(per[names[i]]) > len(per[names[j]])
		}
		return names[i] < names[j]
	})
	const most = 12
	if len(names) > most {
		var other []estate.Score
		for _, d := range names[most-1:] {
			other = append(other, per[d]...)
		}
		names = append(names[:most-1], "Other departments")
		per["Other departments"] = other
	}
	var rows []wfRow
	for _, d := range names {
		group := per[d]
		row := wfRow{Label: d, Count: len(group)}
		for _, a := range estate.Areas() {
			n := 0
			for _, sc := range group {
				if sc.Has(a) {
					n++
				}
			}
			share := float64(n) / float64(len(group))
			step, dark := heatStep(share)
			row.Cells = append(row.Cells, wfCell{
				Value: fmt.Sprintf("%.0f%%", share*100), Step: step, Dark: dark,
				Title: fmt.Sprintf("%s, %s: %d of %d people", d,
					areaLabel[a], n, len(group))})
		}
		rows = append(rows, row)
	}
	return rows
}

// trend lays out the people at high or critical risk over the last ninety
// days of history.
func trend(hist []estate.Summary) ([]wfPoint, string) {
	if len(hist) > 90 {
		hist = hist[len(hist)-90:]
	}
	if len(hist) < 2 {
		return nil, "The trend appears after the estate has been built on " +
			"two different days."
	}
	// Room above the highest point for its label, and below the lowest for
	// the baseline, inside the drawing rather than spilling out of it.
	const w, h, pad, top = 600.0, 120.0, 10.0, 28.0
	most := 1
	for _, d := range hist {
		if n := d.Bands[estate.BandHigh] + d.Bands[estate.BandCritical]; n > most {
			most = n
		}
	}
	var pts []wfPoint
	for i, d := range hist {
		n := d.Bands[estate.BandHigh] + d.Bands[estate.BandCritical]
		pts = append(pts, wfPoint{
			X:    math.Round((pad+float64(i)/float64(len(hist)-1)*(w-2*pad))*10) / 10,
			Y:    math.Round((h-pad-float64(n)/float64(most)*(h-pad-top))*10) / 10,
			Date: d.Date, Value: fmt.Sprint(n)})
	}
	return pts, ""
}

func sortedStrings[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func wfAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "moments"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// handleWorkforcePerson is one person: their score taken apart, what each
// tool says about them, their machines, training and phishing results.
func (s *Server) handleWorkforcePerson(w http.ResponseWriter, r *http.Request) {
	p, e, _, data, ok := s.wfLoad(w, r, "workforce", "Person",
		"workforce_person.html")
	if !ok {
		return
	}
	// The key is a tool's identifier with the tool's name in front, and it
	// arrives path-escaped: an identifier with a slash or a question mark in
	// it is still one segment.
	key, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(),
		"/workforce/person/"))
	if err != nil || key == "" {
		http.NotFound(w, r)
		return
	}
	var ind *estate.Individual
	for _, x := range e.People {
		if x.Key == key {
			ind = x
		}
	}
	if ind == nil {
		http.NotFound(w, r)
		return
	}
	now := time.Now().UTC()
	var score *estate.Score
	for _, sc := range e.Scores(now) {
		if sc.Key == key {
			sc := sc
			score = &sc
		}
	}
	// Written before it is shown: who looked at whose profile.
	s.audit("workforce.viewed", "/workforce/person", map[string]string{
		"by": p.Name, "subject": key,
	})
	data["Title"] = ind.Name()
	data["Person"] = ind
	data["Score"] = score
	if score != nil {
		data["Tone"] = bandTone(score.Band)
		var bars []wfBar
		var vals []int
		for _, f := range score.Factors {
			v := f.Points
			tone := "series"
			if v < 0 {
				v, tone = -v, "good"
			}
			bars = append(bars, wfBar{Label: areaLabel[f.Area],
				Value: fmt.Sprintf("%+d", f.Points), Tone: tone,
				Title: fmt.Sprintf("%s (%s): %+d", f.What, f.Source, f.Points)})
			vals = append(vals, v)
		}
		data["Factors"] = chart("What the score is made of", bars, vals)
	}
	data["Machines"] = machineRows(ind.Devices, now)
	s.render(w, r, "workforce_person.html", data)
}

// machineRow is one machine with each tool's word on each property.
type machineRow struct {
	Name, Serial, Class, Seen, Owner, OwnerKey, Tools string
	Posture                                           []postureCell
	Live                                              bool
}

type postureCell struct {
	Label, Word, Tone, Title string
}

func machineRows(ms []*estate.Machine, now time.Time) []machineRow {
	var out []machineRow
	for _, m := range ms {
		row := machineRow{Name: m.Name(), Serial: m.Serial,
			Class: string(m.Class), Tools: strings.Join(sortedStrings(m.Sources), ", ")}
		if m.Owner != nil {
			row.Owner, row.OwnerKey = m.Owner.Name(), url.PathEscape(m.Owner.Key)
		} else if len(m.Owners) > 1 {
			row.Owner = "disputed: " + strings.Join(m.Owners, ", ")
		}
		if seen := m.Seen(); !seen.IsZero() {
			row.Seen = wfAge(now.Sub(seen)) + " ago"
			row.Live = now.Sub(seen) <= estate.Live
		} else {
			row.Seen = "never"
		}
		for _, prop := range []struct {
			label string
			get   func(estate.Device) *bool
		}{
			{"Encrypted", func(d estate.Device) *bool { return d.Encrypted }},
			{"Screen lock", func(d estate.Device) *bool { return d.ScreenLock }},
			{"Antivirus", func(d estate.Device) *bool { return d.Antivirus }},
			{"Passcode", func(d estate.Device) *bool { return d.Passcode }},
		} {
			said := m.Posture(prop.get)
			cell := postureCell{Label: prop.label, Word: "—", Tone: "unknown",
				Title: prop.label + ": no tool reports this"}
			var yes, no []string
			for src, v := range said {
				if v {
					yes = append(yes, src)
				} else {
					no = append(no, src)
				}
			}
			sort.Strings(yes)
			sort.Strings(no)
			switch {
			case len(yes) > 0 && len(no) > 0:
				cell.Word, cell.Tone = "Disputed", "serious"
				cell.Title = fmt.Sprintf("%s: yes per %s, no per %s",
					prop.label, strings.Join(yes, ", "), strings.Join(no, ", "))
			case len(no) > 0:
				cell.Word, cell.Tone = "No", "critical"
				cell.Title = prop.label + ": no, per " + strings.Join(no, ", ")
			case len(yes) > 0:
				cell.Word, cell.Tone = "Yes", "good"
				cell.Title = prop.label + ": yes, per " + strings.Join(yes, ", ")
			}
			row.Posture = append(row.Posture, cell)
		}
		out = append(out, row)
	}
	return out
}

// handleWorkforceDevices is every machine and which tools know it.
func (s *Server) handleWorkforceDevices(w http.ResponseWriter, r *http.Request) {
	_, e, _, data, ok := s.wfLoad(w, r, "workforce", "Machines",
		"workforce_devices.html")
	if !ok {
		return
	}
	now := time.Now().UTC()
	view := r.URL.Query().Get("show")
	var tools []string
	for _, name := range sortedStrings(e.Sources) {
		for _, info := range e.Sources[name].Endpoints {
			if info.Produces == estate.KindDevice {
				tools = append(tools, name)
				break
			}
		}
	}
	type row struct {
		machineRow
		deviceRow
		In []bool
	}
	counts := map[string]int{}
	var rows []row
	for _, mr := range e.Machines {
		base := machineRows([]*estate.Machine{mr}, now)[0]
		in := make([]bool, len(tools))
		missing := false
		for i, t := range tools {
			in[i] = mr.Sources[t]
			missing = missing || !in[i]
		}
		comp := complianceRow(estate.Comply(mr, now), now)
		if comp.StatusTone != "good" && comp.StatusTone != "unknown" {
			counts["violations"]++
		}
		if comp.SupportTone == "critical" {
			counts["unsupported"]++
		}
		unowned := mr.Owner == nil
		disputed := false
		for _, c := range base.Posture {
			disputed = disputed || c.Tone == "serious"
		}
		disputed = disputed || len(mr.Owners) > 1
		counts["all"]++
		if missing && mr.Serial != "" && base.Live {
			counts["partial"]++
		}
		if unowned && base.Live {
			counts["unowned"]++
		}
		if disputed {
			counts["disputed"]++
		}
		switch view {
		case "partial":
			if !missing || mr.Serial == "" || !base.Live {
				continue
			}
		case "unowned":
			if !unowned || !base.Live {
				continue
			}
		case "disputed":
			if !disputed {
				continue
			}
		case "violations":
			if comp.StatusTone == "good" || comp.StatusTone == "unknown" {
				continue
			}
		case "unsupported":
			if comp.SupportTone != "critical" {
				continue
			}
		}
		rows = append(rows, row{machineRow: base, deviceRow: comp, In: in})
	}
	type chip struct {
		Label, Href string
		Count       int
		On          bool
	}
	var chips []chip
	for _, c := range []struct{ key, label string }{
		{"", "All"}, {"violations", "With violations"}, {"unsupported", "Unsupported OS"},
		{"partial", "Missing from a tool"},
		{"unowned", "In use, no owner"}, {"disputed", "Tools disagree"},
	} {
		href := "/workforce/devices"
		if c.key != "" {
			href += "?show=" + c.key
		}
		n := counts[c.key]
		if c.key == "" {
			n = counts["all"]
		}
		chips = append(chips, chip{Label: c.label, Href: href, Count: n,
			On: view == c.key})
	}
	data["Chips"], data["Tools"], data["Rows"] = chips, tools, rows
	s.render(w, r, "workforce_devices.html", data)
}

// handleWorkforceSync starts reading every tool, in the background: a read
// paced to the tools' limits can take many minutes, longer than a browser
// waits for an answer.
func (s *Server) handleWorkforceSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the button", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	if s.Workforce == nil || s.Workforce.Sync == nil {
		http.Error(w, "this build cannot read the tools",
			http.StatusServiceUnavailable)
		return
	}
	v := url.Values{}
	if err := s.Workforce.Sync(p.Name); err != nil {
		v.Set("e", err.Error())
	} else {
		v.Set("m", "Reading the tools. This page shows the result when it "+
			"finishes; reload in a few minutes.")
	}
	http.Redirect(w, r, "/workforce?"+v.Encode(), http.StatusSeeOther)
}
