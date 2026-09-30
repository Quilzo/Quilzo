// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/incident"
)

// Cases: an incident, the findings it gathers, and its clocks.
//
// The findings queue is one row per thing a rule noticed. An incident is
// what several of those turn out to be, and what it adds is not a bigger
// row: it is who is running it, what has been decided, and the deadlines
// that started when somebody decided it.
//
// The screen's first job is the one the package was written for. A clock
// nobody has started is shown as that — a decision waiting for a person,
// with what making it would start — and never as nothing being due.
//
// Everything here goes through incident.Apply, the same as the command
// line. The screen has no rule of its own about what may be done.

// Cases is what the screens need from whoever holds the store.
type Cases struct {
	List func() ([]*incident.Incident, error)
	Get  func(id string) (*incident.Incident, error)
	// Regimes is what a new incident starts under.
	Regimes func() []string
	Declare func(title string, grade incident.Grade, regimes,
		findings []string, by string) (string, error)
	Act func(id, by string, a incident.Action) error
}

func caseHref(id string) string { return "/security/case/" + url.PathEscape(id) }

// caseSpan says a duration the way somebody watching a deadline reads it.
func caseSpan(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h %02d min", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// clockRow is one obligation on the screen.
type clockRow struct {
	incident.Duty
	Word, Tone, Detail, DueText, FromText string
	// W is how much of the time allowed has gone, out of 100.
	W      float64
	Timed  bool
	Settle bool
}

func clockOf(d incident.Duty, now time.Time) clockRow {
	row := clockRow{Duty: d, Settle: !d.Done && !d.Waived}
	switch {
	case d.Done:
		row.Word, row.Tone, row.Detail = "done", "good", d.Why
	case d.Waived:
		row.Word, row.Tone, row.Detail = "ruled out", "unknown", d.Why
	case !d.Started:
		row.Word, row.Tone = "no clock yet", "warning"
		row.Detail = fmt.Sprintf("Nobody has recorded %q. That is not the "+
			"same as nothing being due.", d.Needs)
	case d.Within == 0:
		row.Word, row.Tone = "owed", "serious"
		row.Detail = "No deadline: without undue delay."
	case d.Left < 0:
		row.Word, row.Tone = "late", "critical"
		row.Detail = "Late by " + caseSpan(-d.Left) + "."
	case d.Left <= time.Hour:
		row.Word, row.Tone = "due within the hour", "critical"
		row.Detail = caseSpan(d.Left) + " left."
	default:
		row.Word, row.Tone = "running", "serious"
		row.Detail = caseSpan(d.Left) + " left."
	}
	if d.Started {
		row.FromText = d.From.Format("2 Jan 15:04 UTC")
	}
	if d.Started && d.Within > 0 {
		row.Timed = true
		row.DueText = d.Due.Format("Mon 2 Jan 15:04 UTC")
		used := float64(now.Sub(d.From)) / float64(d.Due.Sub(d.From))
		row.W = math.Round(math.Max(0, math.Min(1, used))*1000) / 10
	}
	return row
}

func gradeTone(g incident.Grade) string {
	switch g {
	case incident.Sev1:
		return "critical"
	case incident.Sev2:
		return "serious"
	case incident.Sev3:
		return "warning"
	}
	return "unknown"
}

func stateTone(s incident.State) string {
	switch s {
	case incident.Open:
		return "serious"
	case incident.Watching:
		return "warning"
	}
	return "good"
}

func (s *Server) handleCases(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Nav": "cases", "Title": "Cases", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Cases == nil || s.Cases.List == nil {
		data["Unavailable"] = "This build was started without the incident store."
		s.render(w, r, "cases.html", data)
		return
	}
	all, err := s.Cases.List()
	if err != nil {
		data["Unavailable"] = "The incidents could not be read: " +
			err.Error() + ". That is not the same as there being none."
		s.render(w, r, "cases.html", data)
		return
	}
	now := time.Now().UTC()
	type row struct {
		ID, Href, Title, Grade, GradeTone, State, StateTone string
		Commander, Age, Next, NextTone                      string
		Unstarted, Findings                                 int
	}
	var rows []row
	var open, watching, late, unstarted int
	for _, i := range all {
		rw := row{ID: i.ID, Href: caseHref(i.ID), Title: i.Title,
			Grade: string(i.Grade), GradeTone: gradeTone(i.Grade),
			State: string(i.State), StateTone: stateTone(i.State),
			Commander: i.Filled[incident.Commander],
			Age:       agoText(now.Sub(i.Declared)), Findings: len(i.Findings)}
		if i.State != incident.Closed {
			if i.State == incident.Open {
				open++
			} else {
				watching++
			}
			rw.Unstarted = len(i.Unstarted(now))
			unstarted += rw.Unstarted
			if d, ok := i.Next(now); ok {
				c := clockOf(d, now)
				rw.Next, rw.NextTone = d.Regime+": "+strings.ToLower(
					strings.TrimSuffix(c.Detail, ".")), c.Tone
				if d.Late() {
					late++
				}
			}
		}
		rows = append(rows, rw)
	}
	data["Rows"] = rows
	tiles := []wfTile{
		{Label: "Open", Value: fmt.Sprint(open)},
		{Label: "Being watched", Value: fmt.Sprint(watching),
			Note: "believed fixed, not yet trusted"},
		{Label: "Deadlines missed", Value: fmt.Sprint(late)},
		{Label: "Clocks nobody has started", Value: fmt.Sprint(unstarted),
			Note: "a decision is waiting for a person"},
	}
	if late > 0 {
		tiles[2].Tone = "critical"
	}
	if unstarted > 0 {
		tiles[3].Tone = "serious"
	}
	data["Tiles"] = tiles

	// The form to declare one, under the regimes this organisation set.
	set := map[string]bool{}
	if s.Cases.Regimes != nil {
		for _, x := range s.Cases.Regimes() {
			set[x] = true
		}
	}
	type scope struct {
		Name    string
		On      bool
		Regimes string
	}
	var scopes []scope
	for _, sc := range incident.Scopes() {
		var names []string
		for _, o := range incident.Obligations {
			if o.Scope == sc {
				names = append(names, o.Regime)
			}
		}
		scopes = append(scopes, scope{sc, set[sc], strings.Join(names, ", ")})
	}
	data["Scopes"], data["NoRegimes"] = scopes, len(set) == 0
	data["Grades"] = incident.Grades
	data["Finding"] = strings.TrimSpace(r.URL.Query().Get("finding"))
	s.render(w, r, "cases.html", data)
}

func (s *Server) handleCase(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	id := strings.TrimPrefix(r.URL.Path, "/security/case/")
	if s.Cases == nil || s.Cases.Get == nil || !incident.ValidID(id) {
		http.NotFound(w, r)
		return
	}
	i, err := s.Cases.Get(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	now := time.Now().UTC()
	data := map[string]any{"Nav": "cases", "Title": i.Title, "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"I": i, "GradeTone": gradeTone(i.Grade), "StateTone": stateTone(i.State),
		"Declared": i.Declared.Format("Mon 2 Jan 2006 15:04 UTC"),
		"Age":      agoText(now.Sub(i.Declared)),
		"Closed":   i.State == incident.Closed,
		"Watching": i.State == incident.Watching}

	var clocks []clockRow
	for _, d := range i.Duties(now) {
		clocks = append(clocks, clockOf(d, now))
	}
	data["Clocks"] = clocks

	// The decisions: each one an applicable obligation is waiting on, made
	// or not, and what making it starts.
	type decision struct {
		Trigger       incident.Trigger
		Means, Starts string
		Made          bool
		By, Why, When string
	}
	var decisions []decision
	waiting := 0
	for _, t := range incident.Triggers {
		var starts []string
		for _, d := range i.Duties(now) {
			if d.Needs == t {
				starts = append(starts, d.Regime)
			}
		}
		if len(starts) == 0 {
			continue
		}
		dec := decision{Trigger: t, Means: t.Means(),
			Starts: strings.Join(starts, ", ")}
		if m, made := i.Started(t); made {
			dec.Made, dec.By, dec.Why = true, m.By, m.Why
			dec.When = m.At.Format("Mon 2 Jan 15:04 UTC")
		} else {
			waiting++
		}
		decisions = append(decisions, dec)
	}
	data["Decisions"], data["Waiting"] = decisions, waiting
	data["NoRegimes"] = len(i.Regimes) == 0

	type role struct {
		Role incident.Role
		Who  string
	}
	var roles []role
	for _, ro := range incident.Roles {
		roles = append(roles, role{ro, i.Filled[ro]})
	}
	data["Roles"] = roles
	data["NoCommander"] = i.State != incident.Closed &&
		strings.TrimSpace(i.Filled[incident.Commander]) == ""

	// The findings it gathers, as the register has them now.
	type linked struct {
		ID, Title, Sev, State string
		Gone                  bool
	}
	known := map[string]finding.Finding{}
	if s.Findings != nil && s.Findings.Queue != nil {
		if q, _, qerr := s.Findings.Queue(now); qerr == nil {
			for _, f := range q {
				known[f.ID] = f
			}
		}
	}
	var findings []linked
	for _, fid := range i.Findings {
		f, have := known[fid]
		if !have {
			findings = append(findings, linked{ID: fid, Gone: true})
			continue
		}
		findings = append(findings, linked{ID: fid, Title: f.Title,
			Sev: severityName(f.Severity), State: string(f.State)})
	}
	data["Findings"] = findings

	type entry struct{ When, By, What string }
	var timeline []entry
	for _, e := range i.Timeline() {
		timeline = append(timeline, entry{e.At.Format("2 Jan 15:04"), e.By,
			e.What})
	}
	data["Timeline"] = timeline
	s.render(w, r, "case.html", data)
}

func (s *Server) handleCasesAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	if s.Cases == nil || s.Cases.Act == nil || s.Cases.Declare == nil {
		http.Error(w, "this build cannot change an incident",
			http.StatusServiceUnavailable)
		return
	}
	back := func(to, msg string, err error) {
		v := url.Values{}
		if err != nil {
			v.Set("e", err.Error())
		} else {
			v.Set("m", msg)
		}
		http.Redirect(w, r, to+"?"+v.Encode(), http.StatusSeeOther)
	}
	do := r.FormValue("do")
	if do == "declare" {
		var findings []string
		if f := strings.TrimSpace(r.FormValue("finding")); f != "" {
			findings = []string{f}
		}
		id, err := s.Cases.Declare(strings.TrimSpace(r.FormValue("title")),
			incident.Grade(r.FormValue("grade")), r.Form["regime"], findings,
			p.Name)
		if err != nil {
			back("/security/cases", "", err)
			return
		}
		back(caseHref(id), "Declared. Nothing is on a clock until "+
			"somebody records the decision that starts it.", nil)
		return
	}
	id := r.FormValue("id")
	if !incident.ValidID(id) {
		http.Error(w, "which incident", http.StatusBadRequest)
		return
	}
	a := incident.Action{Do: do, Text: strings.TrimSpace(r.FormValue("text")),
		Role:    incident.Role(r.FormValue("role")),
		Who:     strings.TrimSpace(r.FormValue("who")),
		Trigger: incident.Trigger(r.FormValue("trigger")),
		Regime:  r.FormValue("regime"),
		Finding: strings.TrimSpace(r.FormValue("finding"))}
	if do == "close" {
		a.Actions = strings.Split(r.FormValue("actions"), "\n")
	}
	said := map[string]string{
		"note": "Noted.", "assign": "The role is filled.",
		"decide":    "Recorded. The clocks that run from it have started.",
		"discharge": "Recorded as met.", "waive": "Recorded as ruled out.",
		"link": "The finding is part of this.", "unlink": "The finding is no longer part of this.",
		"watch": "Being watched.", "reopen": "Open again.", "close": "Closed.",
	}[do]
	if said == "" {
		http.Error(w, "nothing to do", http.StatusBadRequest)
		return
	}
	back(caseHref(id), said, s.Cases.Act(id, p.Name, a))
}

// agoText says how long ago, without "just now ago".
func agoText(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	return plainAge(d) + " ago"
}
