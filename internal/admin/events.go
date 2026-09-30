// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// The events, in the interface.
//
// Everything this program can do with security telemetry has been reachable
// only from a shell: spool add, spool stats, hunt, triage. That is the same
// mistake internal/admin/assurance.go names about evidence, and it is worse
// here, because the person who notices that a source stopped sending is
// whoever is looking at a screen — and there was no screen.
//
// What this shows is deliberately not a dashboard of counts. The four
// things worth knowing about a security store are what it holds, how late
// things arrive, how far it can be trusted to be complete, and which of the
// sources that were sending have stopped. The first is a number anybody can
// produce. The other three are the ones that decide whether a query over
// this store means anything, and no product shows them.

// Events is the telemetry store, supplied by whatever wired this server up.
//
// A function rather than a handle, because the spool is a directory another
// process may be appending to and holding it open across the life of the
// server would keep a descriptor on a file that rotates.
type Events struct {
	// Open gives a read handle the caller closes.
	Open func() (*spool.Spool, func() error, error)
	// Recent is how many of the newest events to show. Zero means a
	// sensible default rather than none, because a screen that shows a
	// count and no events is the shape of every log product nobody trusts.
	Recent int
	// Budget is how many bytes of the newest segments one page load reads.
	// Zero means DefaultBudget.
	//
	// The store is capped at sixteen gigabytes. A screen that reads all of it
	// per request is a page any administrator can use to pin the disk and a
	// core, and one that gets slower as the thing it watches gets bigger.
	Budget int64
}

// ErrNeverCollected is what Open returns when no store exists at all.
//
// Its own error because it is its own fact: not a failure to read a store,
// and not an empty one. Nothing has ever been delivered.
var ErrNeverCollected = errors.New("no events have ever been stored")

// DefaultRecent is how many events the screen shows.
//
// Enough to recognise a pattern, few enough that the page is readable
// without a filter nobody has built yet.
const DefaultRecent = 50

// DefaultBudget is how much of the store one page load reads.
//
// Whole segments, newest first, until the next would pass this. Enough to
// hold days of an ordinary estate; when it is not, the screen says where it
// stopped rather than presenting a partial picture as the whole one.
const DefaultBudget int64 = 64 << 20

// sender is one source and what it has been doing.
type sender struct {
	Source string
	Count  int
	// Newest and Oldest are arrival times — this program's clock, stamped by
	// the spool — and not the time in the event. A source whose clock runs
	// fast would otherwise look like it sent something a minute from now,
	// sort as the least quiet, and sit at the bottom of the list the day it
	// stops.
	Newest time.Time
	Oldest time.Time
	// Quiet is how long since this source last sent anything.
	Quiet time.Duration
	// Ahead is how many of its events claim a time after they arrived. A
	// clock that is wrong is worth saying, and it is not the same fact as a
	// source that has gone quiet.
	Ahead int
	// Failed is how many of its events record something that did not work,
	// which is the one aggregate worth having on this page: a source whose
	// failures went from none to all of them has something to say.
	Failed int
}

func (s *Server) handleEventsScreen(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	// Who signed in from where. Not for a shared browser's cache or an
	// intermediary's, and stale the moment it is rendered anyway.
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{
		"Nav": "events", "Title": "Events", "Principal": p,
	}
	if s.Events == nil || s.Events.Open == nil {
		data["Unavailable"] = "This build was started without a telemetry " +
			"store. That is not the same as an empty one: a screen showing " +
			"no events would say the estate is quiet, and this build " +
			"cannot see whether it is."
		s.render(w, r, "events.html", data)
		return
	}
	sp, closer, err := s.Events.Open()
	if errors.Is(err, ErrNeverCollected) {
		data["Unavailable"] = "Nothing has ever been collected here: no " +
			"events have been stored in this site. That is not a quiet " +
			"estate — it is one nothing is watching. Events arrive with " +
			"quilzo spool add, or from a connector that runs it."
		s.render(w, r, "events.html", data)
		return
	}
	if err != nil {
		data["Unavailable"] = "The telemetry store could not be opened: " +
			err.Error() + ". A store that cannot be read is not a store " +
			"with nothing in it."
		s.render(w, r, "events.html", data)
		return
	}
	defer func() { _ = closer() }()

	now := time.Now().UTC()
	data["Count"] = sp.Events()
	data["Bytes"] = sp.Bytes()
	data["Segments"] = len(sp.Segments())
	data["Oldest"] = sp.Oldest()
	data["Watermark"] = sp.Watermark()
	data["Holds"] = sp.Holds()
	data["As"] = now

	// Arrival lateness, which is the number that decides whether a window
	// closed on the clock would have missed anything.
	data["Median"] = sp.Lateness(0.5)
	data["P99"] = sp.Lateness(0.99)
	data["Worst"] = sp.Lateness(1)
	// A window ending after the watermark is still waiting for events that
	// have not arrived. Said in time rather than as a timestamp, because
	// "forty minutes behind" is actionable and an ISO string is not.
	if wm := sp.Watermark(); !wm.IsZero() {
		data["Behind"] = now.Sub(wm)
	}

	want := s.Events.Recent
	if want <= 0 {
		want = DefaultRecent
	}
	budget := s.Events.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}
	from, skipped := window(sp.Segments(), budget)
	if skipped > 0 {
		data["From"], data["Skipped"] = from, skipped
	}
	recent, senders, err := walk(sp, from, want, now)
	if err != nil {
		data["Unavailable"] = "The store could not be read through: " +
			err.Error()
		s.render(w, r, "events.html", data)
		return
	}
	data["Recent"], data["Senders"] = recent, senders
	if sp.Events() > 0 && len(recent) == 0 {
		// Counted and unreadable. Worth saying out loud rather than
		// rendering an empty table under a non-zero count.
		data["Note"] = "The store reports events and none could be read " +
			"back. That is a store to verify rather than a quiet estate."
	}
	s.render(w, r, "events.html", data)
}

// window is where a page load starts reading so it stays inside budget.
//
// Whole segments, newest first. The newest one is always read whatever its
// size, because a screen that shows nothing when the store is busy is the
// wrong way round. The zero time means everything fits.
func window(segs []spool.Segment, budget int64) (from time.Time,
	skipped int) {

	var used int64
	for i := len(segs) - 1; i >= 0; i-- {
		used += segs[i].Bytes
		if used > budget && i < len(segs)-1 {
			return segs[i+1].First, i + 1
		}
	}
	return time.Time{}, 0
}

// walk reads the store once, collecting both the newest events and the
// per-source summary.
//
// Once rather than twice: the spool is a file and a screen that scanned it
// per section would read a large store several times to answer questions
// that share a pass.
func walk(sp *spool.Spool, from time.Time, want int, now time.Time) (
	[]telemetry.Event, []sender, error) {

	by := map[string]*sender{}
	// The newest by arrival, kept as a ring: the spool hands events back
	// in the order they were stored, so the last ones seen are the newest
	// and nothing has to be sorted on a clock anybody else controls.
	ring := make([]telemetry.Event, 0, want)
	next := 0
	// No upper bound. Everything in the store is on this program's clock,
	// and a bound here would only hide events stamped while that clock was
	// wrong — which is when somebody most needs to see them.
	err := sp.Range(from, time.Time{}, func(e telemetry.Event) error {
		s, ok := by[e.Source]
		if !ok {
			s = &sender{Source: e.Source}
			by[e.Source] = s
		}
		s.Count++
		if s.Oldest.IsZero() || e.Received.Before(s.Oldest) {
			s.Oldest = e.Received
		}
		if e.Received.After(s.Newest) {
			s.Newest = e.Received
		}
		if e.Time.After(e.Received) {
			s.Ahead++
		}
		switch e.Disposition {
		case telemetry.DispositionFailed, telemetry.DispositionBlocked:
			s.Failed++
		}
		if len(ring) < want {
			ring = append(ring, e)
		} else {
			ring[next] = e
		}
		next = (next + 1) % want
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	// Unroll the ring, newest first.
	recent := make([]telemetry.Event, 0, len(ring))
	for i := 0; i < len(ring); i++ {
		recent = append(recent, ring[(next-1-i+2*len(ring))%len(ring)])
	}

	out := make([]sender, 0, len(by))
	for _, s := range by {
		s.Quiet = now.Sub(s.Newest)
		if s.Quiet < 0 {
			// Stamped after this request began: it is still sending.
			s.Quiet = 0
		}
		out = append(out, *s)
	}
	// Quietest first: the source that has stopped is the one worth seeing,
	// and a list sorted by volume buries it under whatever is loudest. Name
	// breaks ties so the page does not reshuffle between loads.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Quiet != out[j].Quiet {
			return out[i].Quiet > out[j].Quiet
		}
		return out[i].Source < out[j].Source
	})
	return recent, out, nil
}
