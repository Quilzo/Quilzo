// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// event is a valid event from src, arriving at recv and claiming at.
func event(src, msg string, at, recv time.Time) telemetry.Event {
	return telemetry.Event{
		Source: src, Message: msg, Time: at, Received: recv,
		Class: telemetry.ClassAuthentication,
	}
}

// spoolWith writes events into a fresh spool and returns an Events that opens
// it the way the server does, counting how many handles were closed.
func spoolWith(t *testing.T, o spool.Options, in ...telemetry.Event) (*Events,
	*int) {

	t.Helper()
	dir := t.TempDir()
	sp, err := spool.Open(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range in {
		if _, err := sp.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	closed := new(int)
	return &Events{Open: func() (*spool.Spool, func() error, error) {
		sp, err := spool.Open(dir, spool.Options{})
		if err != nil {
			return nil, nil, err
		}
		return sp, func() error { *closed++; return sp.Close() }, nil
	}}, closed
}

// eventsScreen opens /security/events as an administrator.
func eventsScreen(t *testing.T, ev *Events) string {
	t.Helper()
	srv, token := setup(t)
	srv.Events = ev
	w := get(t, srv, "/security/events", token)
	if w.Code != http.StatusOK {
		t.Fatalf("answered %d:\n%s", w.Code, firstLines(w.Body.String(), 6))
	}
	return w.Body.String()
}

// TestAnUnwiredStoreIsNotAQuietOne.
//
// The screen's first job. A build without a store and a store with nothing
// in it are opposite facts that render the same, and only the second means
// the estate is quiet.
func TestAnUnwiredStoreIsNotAQuietOne(t *testing.T) {
	for name, ev := range map[string]*Events{
		"nil": nil, "no opener": {},
	} {
		body := eventsScreen(t, ev)
		if !strings.Contains(body, "without a telemetry store") {
			t.Errorf("%s: an unwired build did not say so:\n%s", name,
				firstLines(body, 20))
		}
		if strings.Contains(body, "Nothing has sent anything") {
			t.Errorf("%s: an unwired build reported an empty store", name)
		}
	}
}

// TestNeverCollectedIsItsOwnAnswer.
func TestNeverCollectedIsItsOwnAnswer(t *testing.T) {
	body := eventsScreen(t, &Events{
		Open: func() (*spool.Spool, func() error, error) {
			return nil, nil, fmt.Errorf("site: %w", ErrNeverCollected)
		},
	})
	if !strings.Contains(body, "Nothing has ever been collected here") {
		t.Fatalf("never collected was not said:\n%s", firstLines(body, 20))
	}
	if strings.Contains(body, "could not be opened") {
		t.Fatal("never collected was reported as a failure to open")
	}
}

// TestAStoreThatCannotBeOpenedSaysWhy, and says it escaped.
//
// The error text is a filesystem message, and part of it can be a path an
// attacker chose. It reaches the page through the template, not around it.
func TestAStoreThatCannotBeOpenedSaysWhy(t *testing.T) {
	body := eventsScreen(t, &Events{
		Open: func() (*spool.Spool, func() error, error) {
			return nil, nil, errors.New("index.json is <b>unreadable</b>")
		},
	})
	if !strings.Contains(body, "could not be opened") {
		t.Fatalf("an open failure was swallowed:\n%s", firstLines(body, 20))
	}
	if strings.Contains(body, "<b>unreadable</b>") {
		t.Fatal("the error reached the page unescaped")
	}
	if !strings.Contains(body, "&lt;b&gt;unreadable&lt;/b&gt;") {
		t.Fatal("the error text is missing")
	}
}

// TestWhatASourceSentIsEscaped.
//
// Every field on this screen was written by somebody outside: the message,
// the source name, the actor. A log viewer that renders them is a stored
// cross-site scripting hole into the one screen an administrator opens
// during an incident.
func TestWhatASourceSentIsEscaped(t *testing.T) {
	now := time.Now().UTC()
	ev, _ := spoolWith(t, spool.Options{},
		event(`<img src=x onerror=alert(1)>`, `<script>alert(2)</script>`,
			now.Add(-time.Minute), now.Add(-time.Minute)))
	body := eventsScreen(t, ev)
	for _, raw := range []string{
		`<script>alert(2)</script>`, `<img src=x onerror=alert(1)>`,
	} {
		if strings.Contains(body, raw) {
			t.Errorf("%s reached the page unescaped", raw)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;alert(2)&lt;/script&gt;") {
		t.Fatalf("the message is missing:\n%s", body)
	}
}

// TestAFastClockDoesNotHideAStoppedSource.
//
// The failure this screen was nearly shipped with. Quiet was measured on
// the time inside the event, so a source whose clock ran an hour fast
// looked as though it had sent something in the future, sorted as the
// least quiet, and stayed at the bottom of the list after it stopped.
// Arrival is this program's clock and the source cannot move it.
func TestAFastClockDoesNotHideAStoppedSource(t *testing.T) {
	now := time.Now().UTC()
	ev, _ := spoolWith(t, spool.Options{},
		// Stopped three hours ago, with a clock a day fast.
		event("fast-and-stopped", "last word", now.Add(21*time.Hour),
			now.Add(-3*time.Hour)),
		// Still sending, on time.
		event("healthy", "ok", now.Add(-time.Minute), now.Add(-time.Minute)),
	)
	body := eventsScreen(t, ev)
	stopped := strings.Index(body, "<code>fast-and-stopped</code>")
	healthy := strings.Index(body, "<code>healthy</code>")
	if stopped < 0 || healthy < 0 {
		t.Fatalf("a source is missing:\n%s", body)
	}
	if stopped > healthy {
		t.Fatal("the stopped source with a fast clock was listed after the " +
			"one still sending")
	}
	if !strings.Contains(body, "1 event(s) dated after they arrived") {
		t.Fatal("a clock running ahead was not reported")
	}
}

// TestSendersAreOrderedTheSameWayEveryTime.
func TestSendersAreOrderedTheSameWayEveryTime(t *testing.T) {
	at := time.Now().UTC().Add(-time.Hour)
	var in []telemetry.Event
	for _, s := range []string{"delta", "alpha", "charlie", "bravo"} {
		in = append(in, event(s, "tick", at, at))
	}
	ev, _ := spoolWith(t, spool.Options{}, in...)
	body := eventsScreen(t, ev)
	last := -1
	for _, s := range []string{"alpha", "bravo", "charlie", "delta"} {
		i := strings.Index(body, "<code>"+s+"</code>")
		if i < last {
			t.Fatalf("equally quiet sources are not in name order at %s", s)
		}
		last = i
	}
}

// TestRecentShowsTheNewestArrivalsAndNoMore.
func TestRecentShowsTheNewestArrivalsAndNoMore(t *testing.T) {
	base := time.Now().UTC().Add(-time.Hour)
	var in []telemetry.Event
	for i := 0; i < 10; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		// Event times run backwards, so ordering on them would pick the
		// wrong three.
		in = append(in, event("app", fmt.Sprintf("event-%02d", i),
			base.Add(-time.Duration(i)*time.Minute), at))
	}
	ev, _ := spoolWith(t, spool.Options{}, in...)
	ev.Recent = 3
	body := eventsScreen(t, ev)

	for i := 0; i < 10; i++ {
		msg := fmt.Sprintf("event-%02d", i)
		shown := strings.Contains(body, msg)
		if want := i >= 7; shown != want {
			t.Errorf("%s shown=%v, want %v", msg, shown, want)
		}
	}
	// Newest first.
	if strings.Index(body, "event-09") > strings.Index(body, "event-07") {
		t.Fatal("recent events are not newest first")
	}
}

// TestAPageLoadReadsABoundedAmount, and says where it stopped.
//
// The store may hold sixteen gigabytes. Reading all of it per request is
// a page any administrator can hold open to pin a disk, so the screen
// reads the newest segments up to a budget — and a source that went quiet
// before that point must not simply vanish without the page saying so.
func TestAPageLoadReadsABoundedAmount(t *testing.T) {
	day := time.Now().UTC().Truncate(24 * time.Hour)
	ev, _ := spoolWith(t, spool.Options{},
		// A segment per arrival day.
		event("long-gone", "old", day.Add(-48*time.Hour),
			day.Add(-48*time.Hour)),
		event("recent", "new", day.Add(-24*time.Hour),
			day.Add(-24*time.Hour)),
		event("recent", "newer", day, day),
	)
	ev.Budget = 1 // smaller than any segment
	body := eventsScreen(t, ev)
	if strings.Contains(body, "<code>long-gone</code>") {
		t.Fatal("a segment outside the budget was read")
	}
	if !strings.Contains(body, "newer") {
		t.Fatal("the newest segment was not read; it always should be")
	}
	if !strings.Contains(body, "were not read on this page load") {
		t.Fatalf("the page did not say it stopped short:\n%s", body)
	}
	// The totals still describe the whole store.
	if !strings.Contains(body, "3 event(s)") {
		t.Fatal("the count stopped describing the whole store")
	}
}

// TestTheBudgetWindowAlwaysKeepsTheNewestSegment.
func TestTheBudgetWindowAlwaysKeepsTheNewestSegment(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	segs := []spool.Segment{
		{First: t0, Bytes: 100},
		{First: t0.Add(24 * time.Hour), Bytes: 100},
		{First: t0.Add(48 * time.Hour), Bytes: 100},
	}
	for _, c := range []struct {
		budget  int64
		from    time.Time
		skipped int
	}{
		{1000, time.Time{}, 0},
		{300, time.Time{}, 0},
		{250, t0.Add(24 * time.Hour), 1},
		{100, t0.Add(48 * time.Hour), 2},
		{1, t0.Add(48 * time.Hour), 2},
	} {
		from, skipped := window(segs, c.budget)
		if !from.Equal(c.from) || skipped != c.skipped {
			t.Errorf("budget %d: from %v skipped %d, want %v and %d",
				c.budget, from, skipped, c.from, c.skipped)
		}
	}
	if from, skipped := window(nil, 1); !from.IsZero() || skipped != 0 {
		t.Error("an empty store was windowed")
	}
}

// TestTheHandleIsClosedEveryTime.
//
// Opened per request so nothing is held across a rotation. That only
// works if every request closes what it opened.
func TestTheHandleIsClosedEveryTime(t *testing.T) {
	now := time.Now().UTC()
	ev, closed := spoolWith(t, spool.Options{},
		event("app", "x", now, now))
	srv, token := setup(t)
	srv.Events = ev
	for i := 0; i < 3; i++ {
		if w := get(t, srv, "/security/events", token); w.Code != 200 {
			t.Fatalf("answered %d", w.Code)
		}
	}
	if *closed != 3 {
		t.Fatalf("closed %d of 3 handles", *closed)
	}
}

// TestTheEventsAreNotCached.
func TestTheEventsAreNotCached(t *testing.T) {
	now := time.Now().UTC()
	ev, _ := spoolWith(t, spool.Options{}, event("idp", "x", now, now))
	srv, token := setup(t)
	srv.Events = ev
	w := get(t, srv, "/security/events", token)
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

// TestOnlyAnAdministratorSeesTheEvents.
//
// The store holds who signed in from where. That is an administrator's
// view, the same rung as the audit log, and a publisher is refused.
func TestOnlyAnAdministratorSeesTheEvents(t *testing.T) {
	now := time.Now().UTC()
	for _, role := range []auth.Role{
		auth.RoleReader, auth.RoleAuthor, auth.RolePublisher,
	} {
		srv, token := asRole(t, role)
		ev, closed := spoolWith(t, spool.Options{},
			event("idp", "someone signed in", now, now))
		srv.Events = ev
		w := get(t, srv, "/security/events", token)
		if w.Code == http.StatusOK {
			t.Errorf("a %s opened the event store", role)
		}
		if strings.Contains(w.Body.String(), "someone signed in") {
			t.Errorf("a %s was shown an event", role)
		}
		if *closed != 0 {
			t.Errorf("the store was opened for a %s before refusing", role)
		}
	}
}
