// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Hunting: looking at the events before there is a rule.
//
// Stacking — sort by how rare a thing is and read the top — is the oldest
// technique in security analysis and the one that keeps earning its place,
// because malicious activity is rare by definition. `quilzo hunt` did it
// over a file somebody exported. This does it over the store, where the
// events are.
//
// There is no query language. A hunt is one field to stack, one period and
// at most one comparison, each chosen from a closed set — the comparisons a
// rule makes, and no more. A box that takes a query string is a parser, and
// a parser over attacker-written log text is an attack surface with a
// friendly name.
//
// What a hunt finds is offered back as the draft of a rule, to be copied
// into the repository where rules are reviewed. Nothing here writes one.

// MaxDistinct is how many different values one hunt will stack. A field
// with more than this is nearly unique per event — a timestamp, a request
// id — and "rarest" means nothing on it.
const MaxDistinct = 5000

// MaxHuntEvents is how many matching events a hunt will list.
const MaxHuntEvents = 50

type huntRow struct {
	Value       string
	Count       int
	Actors      int
	First, Last string
	Share       string
	Href        string
	W           float64
}

var huntOps = []detect.Op{detect.Equals, detect.Contains, detect.Prefix,
	detect.Suffix}

func (s *Server) handleHunt(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Nav": "hunt", "Title": "Hunt", "Principal": p}
	if s.Events == nil || s.Events.Open == nil {
		data["Unavailable"] = "This build was started without a telemetry " +
			"store."
		s.render(w, r, "hunt.html", data)
		return
	}
	sp, closer, err := s.Events.Open()
	if errors.Is(err, ErrNeverCollected) {
		data["Unavailable"] = "Nothing has ever been collected here, so " +
			"there is nothing to hunt through. That is not a quiet estate."
		s.render(w, r, "hunt.html", data)
		return
	}
	if err != nil {
		data["Unavailable"] = "The telemetry store could not be opened: " +
			err.Error()
		s.render(w, r, "hunt.html", data)
		return
	}
	defer func() { _ = closer() }()

	q := r.URL.Query()
	field := strings.TrimSpace(q.Get("field"))
	hours := 24
	switch q.Get("hours") {
	case "1":
		hours = 1
	case "168":
		hours = 168
	}
	where := detect.Match{Field: strings.TrimSpace(q.Get("where")),
		Op: detect.Op(q.Get("op")), Values: []string{q.Get("is")}}
	filtered := where.Field != "" && strings.TrimSpace(q.Get("is")) != ""
	if filtered {
		opOK := false
		for _, o := range huntOps {
			opOK = opOK || o == where.Op
		}
		if !opOK {
			where.Op = detect.Equals
		}
		if uerr := where.Usable(); uerr != nil {
			data["Error"] = uerr.Error()
			filtered = false
		}
	}
	show := q.Get("show")
	showing := q.Has("show")
	data["Field"], data["Hours"] = field, hours
	data["Where"], data["Op"], data["Is"] = where.Field, string(where.Op), q.Get("is")
	data["Ops"] = huntOps

	now := time.Now().UTC()
	from := now.Add(-time.Duration(hours) * time.Hour)
	budget := s.Events.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}
	if wfrom, skipped := window(sp.Segments(), budget); skipped > 0 &&
		wfrom.After(from) {
		// Said, because a hunt that quietly read less than it was asked to
		// reports a value as rare that was common in the part it skipped.
		from = wfrom
		data["Short"] = from
	}

	type tally struct {
		n           int
		first, last time.Time
		actors      map[string]bool
	}
	counts := map[string]*tally{}
	fields := map[string]int{}
	sources := map[string]bool{}
	var scanned, matched, absent int
	var events []telemetry.Event
	var sample *telemetry.Event
	tooMany := false
	err = sp.Range(from, time.Time{}, func(e telemetry.Event) error {
		scanned++
		f := e.Fields()
		for k := range f {
			fields[k]++
		}
		if filtered && !where.Holds(f) {
			return nil
		}
		matched++
		if field == "" {
			return nil
		}
		v, present := f[field]
		if !present {
			absent++
			return nil
		}
		t := counts[v]
		if t == nil {
			if len(counts) >= MaxDistinct {
				tooMany = true
				return nil
			}
			t = &tally{first: e.Time, actors: map[string]bool{}}
			counts[v] = t
		}
		t.n++
		if e.Time.Before(t.first) {
			t.first = e.Time
		}
		if e.Time.After(t.last) {
			t.last = e.Time
		}
		if !e.Actor.Zero() && len(t.actors) < 1000 {
			t.actors[e.Actor.String()] = true
		}
		if showing && v == show {
			sources[e.Source] = true
			if sample == nil {
				ev := e
				sample = &ev
			}
			events = append(events, e)
			if len(events) > MaxHuntEvents {
				events = events[1:]
			}
		}
		return nil
	})
	if err != nil {
		data["Unavailable"] = "The store could not be read through: " + err.Error()
		s.render(w, r, "hunt.html", data)
		return
	}

	// The fields this store's events actually carry, most common first, so
	// the choice is from what is there rather than from a list of names.
	type fieldName struct {
		Name  string
		Count int
	}
	var names []fieldName
	for k, n := range fields {
		if k == "message" {
			// Free text written by whoever can reach the log. Stacking it
			// is a list of every line, and hunting on it is what an
			// attacker would have you do.
			continue
		}
		names = append(names, fieldName{k, n})
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i].Count != names[j].Count {
			return names[i].Count > names[j].Count
		}
		return names[i].Name < names[j].Name
	})
	data["Fields"] = names
	data["Scanned"], data["Matched"] = scanned, matched
	data["Absent"], data["TooMany"] = absent, tooMany
	data["Filtered"] = filtered

	link := func(value string, set bool) string {
		v := url.Values{"field": {field}, "hours": {fmt.Sprint(hours)}}
		if filtered {
			v.Set("where", where.Field)
			v.Set("op", string(where.Op))
			v.Set("is", q.Get("is"))
		}
		if set {
			v.Set("show", value)
		}
		return "/security/hunt?" + v.Encode()
	}
	if field != "" {
		var rows []huntRow
		most := 1
		for _, t := range counts {
			if t.n > most {
				most = t.n
			}
		}
		for v, t := range counts {
			rows = append(rows, huntRow{Value: v, Count: t.n,
				Actors: len(t.actors), First: t.first.Format("2 Jan 15:04"),
				Last:  t.last.Format("2 Jan 15:04"),
				Share: fmt.Sprintf("%.1f%%", float64(t.n)/float64(matched-absent)*100),
				Href:  link(v, true),
				W:     float64(int(float64(t.n)/float64(most)*1000)) / 10})
		}
		// Rarest first: that is the hunt. Ties by value, so two loads of
		// the same page read the same.
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Count != rows[j].Count {
				return rows[i].Count < rows[j].Count
			}
			return rows[i].Value < rows[j].Value
		})
		data["Distinct"] = len(rows)
		if len(rows) > 100 {
			data["More"] = len(rows) - 100
			rows = rows[:100]
		}
		data["Rows"] = rows
	}
	data["Back"] = link("", false)

	if showing {
		data["Show"], data["Showing"] = show, true
		for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
			events[i], events[j] = events[j], events[i]
		}
		data["Events"] = events
		if sample != nil {
			data["Draft"] = draftRule(field, show, where, filtered, sources,
				*sample)
		}
	}
	s.render(w, r, "hunt.html", data)
}

// draftRule writes what a hunt found as the start of a rule: the
// comparisons that found it, the sources it was found in, and the event
// itself as the fixture it must match. It is a draft — it has no fixture
// for what it must not match, and detect test refuses a rule until somebody
// has thought about that.
func draftRule(field, value string, where detect.Match, filtered bool,
	sources map[string]bool, sample telemetry.Event) string {

	all := []detect.Predicate{{Match: &detect.Match{Field: field,
		Op: detect.Equals, Values: []string{value}}}}
	if filtered {
		m := where
		all = append(all, detect.Predicate{Match: &m})
	}
	var srcs []string
	for s := range sources {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	r := detect.Rule{ID: "hunt.rename-me", Title: "Describe what this finds",
		Why:     "What was being looked for, and why it matters",
		Blind:   "What this deliberately does not catch",
		Sources: srcs, When: detect.Predicate{All: all},
		Severity: telemetry.SeverityMedium,
		Fixtures: []detect.Fixture{{Name: "found while hunting", Match: true,
			Event: sample}}}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
