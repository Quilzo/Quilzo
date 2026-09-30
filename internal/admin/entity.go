// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/vuln"
)

// One account or one machine, and everything held about it.
//
// A finding says a rule noticed something about okta:dana. The next
// question is always the same — what else is there about okta:dana — and
// answering it meant four screens and remembering the name between them.
// This page is that question: the findings about it, the incidents those
// are part of, what it has been doing in the events, and what is wrong with
// the software on it.
//
// It is a view, assembled per request from the stores the other screens
// read. Nothing is kept about an entity here, so there is no profile to
// go stale and no second copy of anybody's activity.
//
// An entity is often a person. Opening this page is written to the audit
// log first, under the pseudonym every other record uses for them.

// MaxEntityEvents is how many of an entity's events the page lists.
const MaxEntityEvents = 50

func entityHref(id telemetry.ID) string {
	return "/security/entity/" + url.PathEscape(id.String())
}

// parseEntity reads issuer:value. A bare value is allowed and matches
// under any issuer, because that is what somebody has when they start.
func parseEntity(s string) (telemetry.ID, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 512 || strings.ContainsAny(s, "\x00\r\n") {
		return telemetry.ID{}, false
	}
	issuer, value, found := strings.Cut(s, ":")
	if !found {
		return telemetry.ID{Value: s}, true
	}
	if strings.TrimSpace(value) == "" {
		return telemetry.ID{}, false
	}
	return telemetry.ID{Issuer: issuer, Value: value}, true
}

// sameEntity compares the way the page matches: exactly, or on the value
// alone when no issuer was given.
func sameEntity(want, got telemetry.ID) bool {
	if got.Zero() {
		return false
	}
	if want.Issuer == "" {
		return got.Value == want.Value
	}
	return got == want
}

func (s *Server) handleEntity(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Nav": "findings", "Title": "Entity", "Principal": p}
	raw := strings.TrimPrefix(r.URL.Path, "/security/entity/")
	if raw == "" {
		// The lookup: a form that lands on the path.
		if q := r.URL.Query().Get("q"); q != "" {
			if id, ok := parseEntity(q); ok {
				http.Redirect(w, r, entityHref(id), http.StatusSeeOther)
				return
			}
			data["Error"] = "An entity is written issuer:value, for " +
				"example okta:dana or mdm:MBP-1004."
		}
		s.render(w, r, "entity.html", data)
		return
	}
	id, ok := parseEntity(raw)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Written before it is shown: who looked at whom.
	s.audit("entity.viewed", "/security/entity", map[string]string{
		"by": p.Name, "subject": id.String(),
	})
	now := time.Now().UTC()
	data["Title"], data["ID"], data["Showing"] = id.String(), id, true
	data["AnyIssuer"] = id.Issuer == ""
	hours := 168
	if r.URL.Query().Get("hours") == "24" {
		hours = 24
	}
	data["Hours"], data["Self"] = hours, entityHref(id)

	// Findings about it, in the order the queue ranks them.
	var mine []findingRow
	about := map[string]bool{}
	if s.Findings != nil && s.Findings.Queue != nil {
		q, _, err := s.Findings.Queue(now)
		if err != nil {
			data["FindingsError"] = err.Error()
		}
		for _, f := range q {
			if sameEntity(id, f.Entity) {
				about[f.ID] = true
				if len(mine) < 100 {
					mine = append(mine, rowOf(f, now))
				}
			}
		}
	} else {
		data["FindingsError"] = "this build was started without the register"
	}
	data["Findings"], data["FindingCount"] = mine, len(about)
	open := 0
	for _, f := range mine {
		if f.State == finding.Open {
			open++
		}
	}

	// The incidents those findings are part of.
	type caseRow struct{ ID, Href, Title, State, Tone string }
	var cases []caseRow
	if s.Cases != nil && s.Cases.List != nil {
		all, err := s.Cases.List()
		if err != nil {
			data["CasesError"] = err.Error()
		}
		for _, i := range all {
			for _, f := range i.Findings {
				if about[f] {
					cases = append(cases, caseRow{i.ID, caseHref(i.ID), i.Title,
						string(i.State), stateTone(i.State)})
					break
				}
			}
		}
	}
	data["Cases"] = cases

	// What is wrong with the software on it.
	type vulnRow struct {
		ID, Href, Package, Version, Why string
		Exploited                       bool
	}
	var vulns []vulnRow
	if s.Vulns != nil && s.Vulns.Load != nil {
		v, err := s.Vulns.Load(now)
		if err != nil {
			data["VulnsError"] = err.Error()
		}
		for _, e := range v.Matched {
			if e.Silenced || !sameEntity(id, e.Component.Where) {
				continue
			}
			yes, _ := e.Advisory.Attested()
			if len(vulns) < 100 {
				vulns = append(vulns, vulnRow{e.Advisory.ID,
					vulnHref(e.Advisory.ID), e.Component.Name,
					e.Component.Version, vulnWhy(e, now), yes})
			}
		}
	}
	data["Vulns"] = vulns

	// What it has been doing, and what has been done to it.
	activity := s.entityActivity(id, now, hours, data)

	data["Tiles"] = []wfTile{
		{Label: "Open findings", Value: fmt.Sprint(open),
			Note: fmt.Sprintf("of %d about it", len(about))},
		{Label: "Incidents", Value: fmt.Sprint(len(cases))},
		{Label: "Events", Value: fmt.Sprint(activity),
			Note: fmt.Sprintf("in the last %s", map[int]string{24: "24 hours",
				168: "7 days"}[hours])},
		{Label: "Open vulnerabilities", Value: fmt.Sprint(len(vulns))},
	}
	data["Nothing"] = len(about) == 0 && activity == 0 && len(vulns) == 0
	s.render(w, r, "entity.html", data)
}

// vulnWhy is an exposure's explanation, for a row that has room for one
// line.
func vulnWhy(e vuln.Exposure, now time.Time) string { return e.Explain(now) }

// entityActivity reads the events for one entity and fills the page's
// activity sections. It returns how many events named it.
func (s *Server) entityActivity(id telemetry.ID, now time.Time, hours int,
	data map[string]any) int {

	if s.Events == nil || s.Events.Open == nil {
		data["EventsError"] = "This build was started without a telemetry store."
		return 0
	}
	sp, closer, err := s.Events.Open()
	if errors.Is(err, ErrNeverCollected) {
		data["EventsError"] = "Nothing has ever been collected here, which " +
			"is not the same as this entity having done nothing."
		return 0
	}
	if err != nil {
		data["EventsError"] = "The telemetry store could not be opened: " + err.Error()
		return 0
	}
	defer func() { _ = closer() }()

	from := now.Add(-time.Duration(hours) * time.Hour)
	budget := s.Events.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}
	if wfrom, skipped := window(sp.Segments(), budget); skipped > 0 &&
		wfrom.After(from) {
		from = wfrom
		data["Short"] = from
	}
	type tally struct {
		Source, Outcome string
		Count           int
		Last            time.Time
	}
	by := map[string]*tally{}
	addresses := map[string]int{}
	roles := map[string]int{}
	var first, last time.Time
	var latest []telemetry.Event
	total := 0
	err = sp.Range(from, time.Time{}, func(e telemetry.Event) error {
		as := ""
		switch {
		case sameEntity(id, e.Actor):
			as = "did it"
		case sameEntity(id, e.Target):
			as = "it was done to"
		case sameEntity(id, e.Device):
			as = "it happened on"
		default:
			return nil
		}
		total++
		roles[as]++
		k := e.Source + "\x00" + e.Disposition.String()
		t := by[k]
		if t == nil {
			t = &tally{Source: e.Source, Outcome: e.Disposition.String()}
			by[k] = t
		}
		t.Count++
		if e.Time.After(t.Last) {
			t.Last = e.Time
		}
		if first.IsZero() || e.Time.Before(first) {
			first = e.Time
		}
		if e.Time.After(last) {
			last = e.Time
		}
		if len(addresses) < 2000 {
			for _, ip := range e.Of(telemetry.ObservableIP) {
				addresses[ip]++
			}
		}
		latest = append(latest, e)
		if len(latest) > MaxEntityEvents {
			latest = latest[1:]
		}
		return nil
	})
	if err != nil {
		data["EventsError"] = "The store could not be read through: " + err.Error()
		return 0
	}
	var tallies []tally
	for _, t := range by {
		tallies = append(tallies, *t)
	}
	sort.Slice(tallies, func(i, j int) bool {
		if tallies[i].Count != tallies[j].Count {
			return tallies[i].Count > tallies[j].Count
		}
		return tallies[i].Source+tallies[i].Outcome < tallies[j].Source+tallies[j].Outcome
	})
	type sourceRow struct {
		Source, Outcome, Last string
		Count                 int
		W                     float64
	}
	var sources []sourceRow
	for _, t := range tallies {
		sources = append(sources, sourceRow{t.Source, t.Outcome,
			t.Last.Format("2 Jan 15:04"), t.Count,
			float64(int(float64(t.Count)/float64(tallies[0].Count)*1000)) / 10})
	}
	data["Sources"] = sources

	// Addresses, rarest first: the one it used once is the one to read.
	type addr struct {
		Value string
		Count int
	}
	var addrs []addr
	for v, n := range addresses {
		addrs = append(addrs, addr{v, n})
	}
	sort.Slice(addrs, func(i, j int) bool {
		if addrs[i].Count != addrs[j].Count {
			return addrs[i].Count < addrs[j].Count
		}
		return addrs[i].Value < addrs[j].Value
	})
	data["AddressCount"] = len(addrs)
	if len(addrs) > 15 {
		addrs = addrs[:15]
	}
	data["Addresses"] = addrs

	for i, j := 0, len(latest)-1; i < j; i, j = i+1, j-1 {
		latest[i], latest[j] = latest[j], latest[i]
	}
	data["Events"] = latest
	if total > 0 {
		data["First"] = first.Format("2 Jan 15:04")
		data["Last"] = last.Format("2 Jan 15:04")
	}
	var parts []string
	for _, k := range []string{"did it", "it was done to", "it happened on"} {
		if roles[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d where %s", roles[k], map[string]string{
				"did it": "it acted", "it was done to": "it was acted on",
				"it happened on": "it was the machine"}[k]))
		}
	}
	data["Roles"] = strings.Join(parts, ", ")
	return total
}
