// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package correlate

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

var t0 = time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

func ev(at time.Time, user string) telemetry.Event {
	return telemetry.Event{
		Time: at, Received: at, Source: "windows/security",
		Class: telemetry.ClassAuthentication, Activity: 1,
		Severity: telemetry.SeverityLow,
		Raw:      map[string]string{"User": user, "Host": "ws-1"},
	}
}

const countRule = `
title: Many failed logons for one account
id: corr-1
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - raw.User
    timespan: 15m
    condition:
        gte: 5
level: high
`

func read(t *testing.T, src string) Rule {
	t.Helper()
	rs, err := Read([]byte(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("%d rule(s)", len(rs))
	}
	return rs[0]
}

func TestReadsACorrelationRule(t *testing.T) {
	r := read(t, countRule)
	if r.Type != EventCount || r.Timespan != 15*time.Minute {
		t.Fatalf("%+v", r)
	}
	if r.Test.Op != "gte" || r.Test.N != 5 {
		t.Fatalf("condition = %+v", r.Test)
	}
	if len(r.GroupBy) != 1 || r.GroupBy[0] != "raw.User" {
		t.Fatalf("group-by = %v", r.GroupBy)
	}
	if r.Severity != telemetry.SeverityHigh {
		t.Fatalf("severity = %v", r.Severity)
	}
	if r.Generate {
		t.Fatal("generate defaults off, because a correlation usually " +
			"exists so the individual events do not alert")
	}
}

func TestTimespanIsSigmasNotGos(t *testing.T) {
	for _, c := range []struct {
		in   string
		want time.Duration
	}{
		{"30s", 30 * time.Second},
		{"15m", 15 * time.Minute},
		{"2h", 2 * time.Hour},
		{"1d", 24 * time.Hour},
	} {
		got, err := Timespan(c.in)
		if err != nil || got != c.want {
			t.Errorf("%s = %v, %v", c.in, got, err)
		}
	}
	// Go accepts these and Sigma does not; accepting more than the
	// standard means writing a rule no other backend takes.
	for _, bad := range []string{"1h30m", "15", "m", "0m", "-5m", "15w"} {
		if _, err := Timespan(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// TestWindowsCloseOnTheWatermarkNotTheClock is the whole point.
func TestWindowsCloseOnTheWatermarkNotTheClock(t *testing.T) {
	e, err := New(read(t, countRule))
	if err != nil {
		t.Fatal(err)
	}
	// Five failures at 10:01..10:05, all in the 10:00 window.
	for i := range 5 {
		at := t0.Add(time.Duration(i+1) * time.Minute)
		if err := e.Observe(Seen{Rule: "failed_logon",
			Event: ev(at, "ada")}, t0); err != nil {
			t.Fatal(err)
		}
	}
	// The clock says 10:20, so a clock-closed window would have fired.
	// The watermark says only 10:10 is complete, and the window ends at
	// 10:15, so nothing has been decided.
	if hits := e.Close(t0.Add(10 * time.Minute)); len(hits) != 0 {
		t.Fatalf("fired before the window closed: %+v", hits)
	}
	// A late event that still belongs in the window.
	if err := e.Observe(Seen{Rule: "failed_logon",
		Event: ev(t0.Add(6*time.Minute), "ada")},
		t0.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if e.Late() != 0 {
		t.Fatal("an event inside an open window was counted as late")
	}

	hits := e.Close(t0.Add(20 * time.Minute))
	if len(hits) != 1 {
		t.Fatalf("%d hit(s)", len(hits))
	}
	h := hits[0]
	if h.Count != 6 {
		t.Fatalf("count = %d; the late event should be in it", h.Count)
	}
	if h.Group["raw.User"] != "ada" {
		t.Fatalf("group = %v", h.Group)
	}
	if !h.From.Equal(t0) || !h.To.Equal(t0.Add(15*time.Minute)) {
		t.Fatalf("window %s..%s", h.From, h.To)
	}
	if !strings.Contains(h.Why(), "raw.User=ada") {
		t.Fatalf("why = %q", h.Why())
	}
	// Closed once; closing again produces nothing.
	if again := e.Close(t0.Add(time.Hour)); len(again) != 0 {
		t.Fatal("a window fired twice")
	}
}

// TestAnEventAfterItsWindowClosedIsCountedNotSwallowed.
func TestAnEventAfterItsWindowClosedIsCountedNotSwallowed(t *testing.T) {
	e, err := New(read(t, countRule))
	if err != nil {
		t.Fatal(err)
	}
	e.Close(t0.Add(20 * time.Minute)) // closes the 10:00 window
	err = e.Observe(Seen{Rule: "failed_logon", Event: ev(t0.Add(time.Minute),
		"ada")}, t0.Add(20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if e.Late() != 1 {
		t.Fatalf("late = %d; a rising late count is how you find out the "+
			"watermark is too aggressive for a source", e.Late())
	}
	if hits := e.Flush(); len(hits) != 0 {
		t.Fatal("a late event resurrected a closed window")
	}
}

// TestGroupsArePerValue.
func TestGroupsArePerValue(t *testing.T) {
	e, err := New(read(t, countRule))
	if err != nil {
		t.Fatal(err)
	}
	// Four each for two users: neither reaches five.
	for _, u := range []string{"ada", "grace"} {
		for i := range 4 {
			if err := e.Observe(Seen{Rule: "failed_logon",
				Event: ev(t0.Add(time.Duration(i+1)*time.Minute), u)},
				t0); err != nil {
				t.Fatal(err)
			}
		}
	}
	if hits := e.Flush(); len(hits) != 0 {
		t.Fatalf("eight events across two users fired: %+v", hits)
	}
}

// TestAnEventMissingItsGroupingFieldIsDroppedNotPooled.
func TestAnEventMissingItsGroupingFieldIsDroppedNotPooled(t *testing.T) {
	e, err := New(read(t, countRule))
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		bad := ev(t0.Add(time.Minute), "")
		delete(bad.Raw, "User")
		if err := e.Observe(Seen{Rule: "failed_logon", Event: bad},
			t0); err != nil {
			t.Fatal(err)
		}
	}
	if e.Dropped() != 10 {
		t.Fatalf("dropped = %d", e.Dropped())
	}
	if hits := e.Flush(); len(hits) != 0 {
		t.Fatal("events with no group pooled into one bucket and fired")
	}
}

const valueRule = `
title: One account touching many hosts
correlation:
    type: value_count
    rules:
        - logon
    group-by:
        - raw.User
    field: raw.Host
    timespan: 1h
    condition:
        gte: 3
level: high
`

func TestValueCountCountsDistinctValues(t *testing.T) {
	e, err := New(read(t, valueRule))
	if err != nil {
		t.Fatal(err)
	}
	// Ten logons but only two hosts: not a spread.
	for i := range 10 {
		x := ev(t0.Add(time.Duration(i)*time.Minute), "ada")
		x.Raw["Host"] = []string{"ws-1", "ws-2"}[i%2]
		if err := e.Observe(Seen{Rule: "logon", Event: x}, t0); err != nil {
			t.Fatal(err)
		}
	}
	if hits := e.Flush(); len(hits) != 0 {
		t.Fatalf("two hosts fired a three-host rule: %+v", hits)
	}

	e2, _ := New(read(t, valueRule))
	for i, host := range []string{"ws-1", "ws-2", "ws-3"} {
		x := ev(t0.Add(time.Duration(i)*time.Minute), "ada")
		x.Raw["Host"] = host
		if err := e2.Observe(Seen{Rule: "logon", Event: x}, t0); err != nil {
			t.Fatal(err)
		}
	}
	hits := e2.Flush()
	if len(hits) != 1 || hits[0].Count != 3 {
		t.Fatalf("hits = %+v", hits)
	}
}

const temporalRule = `
title: Recon then execution on one host
correlation:
    type: temporal
    rules:
        - recon
        - execution
    group-by:
        - raw.Host
    timespan: 30m
level: critical
`

const orderedRule = `
title: Recon before execution on one host
correlation:
    type: temporal_ordered
    rules:
        - recon
        - execution
    group-by:
        - raw.Host
    timespan: 30m
level: critical
`

func observe(t *testing.T, e *Engine, rule string, min int) {
	t.Helper()
	x := ev(t0.Add(time.Duration(min)*time.Minute), "ada")
	if err := e.Observe(Seen{Rule: rule, Event: x}, t0); err != nil {
		t.Fatal(err)
	}
}

func TestTemporalNeedsEveryRule(t *testing.T) {
	e, err := New(read(t, temporalRule))
	if err != nil {
		t.Fatal(err)
	}
	observe(t, e, "recon", 1)
	observe(t, e, "recon", 2)
	if hits := e.Flush(); len(hits) != 0 {
		t.Fatal("one rule twice satisfied a two-rule temporal")
	}

	e2, _ := New(read(t, temporalRule))
	observe(t, e2, "recon", 1)
	observe(t, e2, "execution", 5)
	hits := e2.Flush()
	if len(hits) != 1 {
		t.Fatalf("%d hit(s)", len(hits))
	}
	if len(hits[0].Rules) != 2 {
		t.Fatalf("rules = %v", hits[0].Rules)
	}
}

// TestOrderedIsTheDifferenceBetweenCoincidenceAndTechnique.
func TestOrderedIsTheDifferenceBetweenCoincidenceAndTechnique(t *testing.T) {
	// The right order fires.
	e, err := New(read(t, orderedRule))
	if err != nil {
		t.Fatal(err)
	}
	observe(t, e, "recon", 1)
	observe(t, e, "execution", 5)
	if hits := e.Flush(); len(hits) != 1 {
		t.Fatalf("%d hit(s) in the right order", len(hits))
	}

	// The wrong order does not.
	e2, _ := New(read(t, orderedRule))
	observe(t, e2, "execution", 1)
	observe(t, e2, "recon", 5)
	if hits := e2.Flush(); len(hits) != 0 {
		t.Fatalf("the wrong order fired: %+v", hits)
	}

	// The same events unordered do fire, which is what tells the two
	// correlation types apart.
	e3, _ := New(read(t, temporalRule))
	observe(t, e3, "execution", 1)
	observe(t, e3, "recon", 5)
	if hits := e3.Flush(); len(hits) != 1 {
		t.Fatal("temporal should not care about order")
	}
}

// TestOrderedAllowsThingsInBetween.
func TestOrderedAllowsThingsInBetween(t *testing.T) {
	e, _ := New(read(t, orderedRule))
	observe(t, e, "recon", 1)
	observe(t, e, "execution", 3)
	observe(t, e, "recon", 5)
	if hits := e.Flush(); len(hits) != 1 {
		t.Fatal("a repeat of an earlier rule broke the sequence; other " +
			"things happening in between is normal")
	}
}

// TestValidationRefusesWhatCannotBeEvaluated.
func TestValidationRefusesWhatCannotBeEvaluated(t *testing.T) {
	for _, c := range []struct {
		name string
		r    Rule
		says string
	}{
		{"no type", Rule{Title: "t", Rules: []string{"a"},
			Timespan: time.Minute}, "correlation type"},
		{"no rules", Rule{Title: "t", Type: EventCount,
			Timespan: time.Minute}, "correlates nothing"},
		{"no timespan", Rule{Title: "t", Type: EventCount,
			Rules: []string{"a"}}, "no timespan"},
		{"too long", Rule{Title: "t", Type: EventCount,
			Rules: []string{"a"}, Timespan: 48 * time.Hour,
			Test: Test{Op: "gte", N: 1}}, "is a search"},
		{"value count with no field", Rule{Title: "t", Type: ValueCount,
			Rules: []string{"a"}, GroupBy: []string{"g"},
			Timespan: time.Minute, Test: Test{Op: "gte", N: 1}},
			"does not say of what"},
		{"temporal over one rule", Rule{Title: "t", Type: Temporal,
			Rules: []string{"a"}, GroupBy: []string{"g"},
			Timespan: time.Minute}, "is that rule"},
		{"temporal with no group", Rule{Title: "t", Type: Temporal,
			Rules: []string{"a", "b"}, Timespan: time.Minute},
			"together to what"},
		{"count with no condition", Rule{Title: "t", Type: EventCount,
			Rules: []string{"a"}, Timespan: time.Minute}, "no condition"},
	} {
		err := c.r.Validate()
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestCountingAcrossEverythingIsReportedNotRefused.
func TestCountingAcrossEverythingIsReportedNotRefused(t *testing.T) {
	r := Rule{Title: "everything", Type: EventCount, Rules: []string{"a"},
		Timespan: 15 * time.Minute, Test: Test{Op: "gte", N: 10}}
	if err := r.Validate(); err != nil {
		t.Fatalf("a construct Sigma permits was refused: %v", err)
	}
	why, broad := r.Broad()
	if !broad {
		t.Fatal("an ungrouped count was not reported as broad")
	}
	if !strings.Contains(why, "meaningful for an account") {
		t.Fatalf("why = %q", why)
	}

	// A falling condition has its own warning: it fires for groups that
	// have no events at all.
	fall := Rule{Title: "quiet", Type: EventCount, Rules: []string{"a"},
		GroupBy: []string{"g"}, Timespan: time.Hour,
		Test: Test{Op: "lt", N: 5}}
	if err := fall.Validate(); err != nil {
		t.Fatal(err)
	}
	why, broad = fall.Broad()
	if !broad || !strings.Contains(why, "never existed") {
		t.Fatalf("falling: %v %q", broad, why)
	}
}

// TestAReplayAndALiveRunAgree — the property that makes a correlation
// testable at all.
func TestAReplayAndALiveRunAgree(t *testing.T) {
	feed := func(e *Engine, watermarks []time.Time) []Hit {
		var all []Hit
		for i := range 12 {
			at := t0.Add(time.Duration(i) * 90 * time.Second)
			if err := e.Observe(Seen{Rule: "failed_logon",
				Event: ev(at, "ada")}, watermarks[i]); err != nil {
				t.Fatal(err)
			}
			all = append(all, e.Close(watermarks[i])...)
		}
		return append(all, e.Flush()...)
	}
	// Live: the watermark trails each event by the safe lateness.
	var live []time.Time
	for i := range 12 {
		live = append(live,
			Watermark(t0.Add(time.Duration(i)*90*time.Second), Safe))
	}
	a, _ := New(read(t, countRule))
	first := feed(a, live)

	// Replayed later with the same watermarks: the same answers.
	b, _ := New(read(t, countRule))
	second := feed(b, live)

	if len(first) != len(second) {
		t.Fatalf("live gave %d hit(s), replay gave %d", len(first),
			len(second))
	}
	for i := range first {
		if first[i].Why() != second[i].Why() {
			t.Fatalf("hit %d differs:\n  %s\n  %s", i, first[i].Why(),
				second[i].Why())
		}
	}
	if len(first) == 0 {
		t.Fatal("the fixture never fired, so this proves nothing")
	}
}

func TestAnEngineRefusesARuleItDoesNotWatch(t *testing.T) {
	e, _ := New(read(t, countRule))
	err := e.Observe(Seen{Rule: "something_else", Event: ev(t0, "ada")}, t0)
	if err == nil {
		t.Fatal("an unrelated rule was counted into the correlation")
	}
}
