// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

var base = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

// clock is a settable now, so a test can age a spool without sleeping.
type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

func openAt(t *testing.T, c *clock, o Options) (*Spool, string) {
	t.Helper()
	dir := t.TempDir()
	o.Now = c.now
	s, err := Open(dir, o)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s, dir
}

func event(at, received time.Time, msg string) telemetry.Event {
	return telemetry.Event{
		Time: at, Received: received, Class: telemetry.ClassAuthentication,
		Activity: 1, Severity: telemetry.SeverityInfo,
		Disposition: telemetry.DispositionAllowed,
		Source:      "okta/system", Message: msg,
	}
}

func TestAnEventGoesInTheSegmentForWhenItArrivedNotWhenItClaims(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()

	// A source claiming to be a week in the future, and one claiming to be a
	// week in the past. Both arrive now, and both must land in today's
	// segment — otherwise one lands in a partition already swept and the
	// other in one already dropped, and neither is an error anybody sees.
	for _, claimed := range []time.Time{
		base.Add(7 * 24 * time.Hour), base.Add(-7 * 24 * time.Hour), base,
	} {
		if _, err := s.Append(event(claimed, base, "login")); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	segs := s.Segments()
	if len(segs) != 1 {
		t.Fatalf("a source's clock split the spool into %d segments",
			len(segs))
	}
	if !strings.HasPrefix(segs[0].Name, "20260925") {
		t.Errorf("segment is named %q, not for the day of arrival",
			segs[0].Name)
	}
	if segs[0].Events != 3 {
		t.Errorf("segment holds %d events, want 3", segs[0].Events)
	}
}

func TestArrivalAndEventTimeAreSeparateQueries(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()

	// Happened yesterday, arrived today. A daily export does this every day.
	late := event(base.Add(-20*time.Hour), base, "yesterday's export")
	prompt := event(base, base, "arrived immediately")
	for _, e := range []telemetry.Event{late, prompt} {
		if _, err := s.Append(e); err != nil {
			t.Fatal(err)
		}
	}

	var arrived, happened []string
	if err := s.Range(base.Add(-time.Hour), base.Add(time.Hour),
		func(e telemetry.Event) error {
			arrived = append(arrived, e.Message)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if len(arrived) != 2 {
		t.Errorf("Range by arrival found %d, want both", len(arrived))
	}
	if err := s.During(base.Add(-time.Hour), base.Add(time.Hour),
		func(e telemetry.Event) error {
			happened = append(happened, e.Message)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if len(happened) != 1 || happened[0] != "arrived immediately" {
		t.Errorf("During by event time found %v, want only the one that "+
			"happened in the window", happened)
	}
}

func TestAReaderSeesEventsWrittenASecondAgo(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	if _, err := s.Append(event(base, base, "just now")); err != nil {
		t.Fatal(err)
	}
	// No Seal. A reader that only sees sealed segments reports an incident
	// in progress as a quiet period.
	var seen int
	if err := s.Range(time.Time{}, time.Time{},
		func(telemetry.Event) error { seen++; return nil }); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("an unsealed segment's events are invisible: saw %d", seen)
	}
}

func TestASegmentRollsOnTheDayAndOnSize(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{SegmentBytes: 400})
	defer s.Close()

	for range 10 {
		if _, err := s.Append(event(base, c.at, "a message long enough to "+
			"push the segment over four hundred bytes quickly")); err != nil {
			t.Fatal(err)
		}
	}
	bySize := len(s.Segments())
	if bySize < 2 {
		t.Fatalf("size never rolled the segment: %d segment(s)", bySize)
	}

	c.at = base.Add(24 * time.Hour)
	if _, err := s.Append(event(base, c.at, "next day")); err != nil {
		t.Fatal(err)
	}
	segs := s.Segments()
	if len(segs) != bySize+1 {
		t.Errorf("the day boundary did not roll: %d then %d",
			bySize, len(segs))
	}
	if !strings.HasPrefix(segs[len(segs)-1].Name, "20260926") {
		t.Errorf("the new segment is %q", segs[len(segs)-1].Name)
	}
}

func TestASealedSegmentIsDigestedAndTamperingShows(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	if _, err := s.Append(event(base, base, "login")); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	seg := s.Segments()[0]
	if !seg.Sealed() {
		t.Fatal("a sealed segment has no digest")
	}
	if bad, err := s.Verify(); err != nil || len(bad) != 0 {
		t.Fatalf("a fresh spool does not verify: %v %v", bad, err)
	}
	if len(s.Anchor()) != 1 {
		t.Error("nothing to anchor in the audit log")
	}

	// Rewrite history. One hash per segment is what makes this cheap enough
	// to do unconditionally on volume data.
	path := filepath.Join(dir, seg.Name)
	if err := os.WriteFile(path,
		[]byte(`{"time":"2026-09-25T12:00:00Z","received":"2026-09-25T12:00:00Z","class":3002,"activity":1,"severity":1,"disposition":1,"source":"okta/system","message":"nothing happened"}`+"\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	bad, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 1 || !strings.Contains(bad[0], seg.Name) {
		t.Fatalf("a rewritten segment verified: %v", bad)
	}
}

func TestAnOpenSegmentIsNotReportedAsUnverified(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	if _, err := s.Append(event(base, base, "login")); err != nil {
		t.Fatal(err)
	}
	bad, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 0 {
		t.Errorf("a segment still being written to was reported: %v", bad)
	}
}

func TestAgeAndSizeAreBothLimits(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{
		SegmentBytes: 200, Keep: 48 * time.Hour, Cap: 1 << 30,
	})
	defer s.Close()

	for day := range 5 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := s.Append(event(c.at, c.at, "day")); err != nil {
			t.Fatal(err)
		}
	}
	c.at = base.Add(5 * 24 * time.Hour)
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}

	p := s.Retain()
	if len(p.Drop) != 3 {
		t.Fatalf("age dropped %d segment(s), want the three over two days: %s",
			len(p.Drop), p.Why())
	}
	if p.Covers.IsZero() || p.Covers.Before(base.Add(72*time.Hour)) {
		t.Errorf("the spool would still claim to cover %s", p.Covers)
	}

	// Now the size limit alone, with nothing old enough to age out.
	c.at = base.Add(5 * 24 * time.Hour)
	s.opt.Keep = 365 * 24 * time.Hour
	s.opt.Cap = 400
	p = s.Retain()
	if p.Empty() {
		t.Fatal("a spool over its byte cap planned to drop nothing")
	}
	if p.Freed == 0 {
		t.Error("the plan frees nothing")
	}
}

func TestPlanningDeletesNothing(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{SegmentBytes: 200, Keep: time.Hour})
	for day := range 3 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := s.Append(event(c.at, c.at, "day")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	before, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))

	p := s.Retain()
	if p.Empty() {
		t.Fatal("nothing planned")
	}
	after, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(after) != len(before) {
		t.Fatalf("planning deleted %d file(s)", len(before)-len(after))
	}

	gone, err := s.Apply(p)
	if err != nil {
		t.Fatal(err)
	}
	if gone != len(p.Drop) {
		t.Errorf("applied deleted %d, planned %d", gone, len(p.Drop))
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(left) != len(before)-gone {
		t.Errorf("%d files left, expected %d", len(left), len(before)-gone)
	}
}

func TestAStalePlanIsRefused(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{SegmentBytes: 200, Keep: time.Hour})
	defer s.Close()
	for day := range 3 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := s.Append(event(c.at, c.at, "day")); err != nil {
			t.Fatal(err)
		}
	}
	p := s.Retain()

	// Ten minutes pass and another segment seals. The list the operator
	// approved is no longer the list that would run.
	c.at = base.Add(4 * 24 * time.Hour)
	if _, err := s.Append(event(c.at, c.at, "later")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(p); err == nil {
		t.Fatal("a plan made against a different spool was applied")
	}
}

func TestAPlanNobodyMadeIsRefused(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	if _, err := s.Apply(Plan{Drop: s.Segments()}); err == nil {
		t.Fatal("a hand-made plan deleted segments nobody had seen listed")
	}
}

func TestAHoldPinsEverythingAndSaysSo(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{SegmentBytes: 200, Keep: time.Hour})
	defer s.Close()
	for day := range 3 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := s.Append(event(c.at, c.at, "day")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}

	if err := s.Hold(Hold{Name: "inc-2026-41", By: "rashik",
		Why: "possible exfiltration under investigation"}); err != nil {
		t.Fatal(err)
	}
	p := s.Retain()
	if !p.Empty() {
		t.Fatalf("retention planned to drop %d segment(s) under a hold",
			len(p.Drop))
	}
	if len(p.Held) == 0 {
		t.Error("the plan does not report that a hold is the reason")
	}
	if !strings.Contains(p.Why(), "hold") {
		t.Errorf("the explanation does not mention the hold: %q", p.Why())
	}

	// And a plan made before the hold does not get to run afterwards.
	if err := s.Lift("inc-2026-41"); err != nil {
		t.Fatal(err)
	}
	fresh := s.Retain()
	if err := s.Hold(Hold{Name: "inc-2026-41", By: "rashik",
		Why: "reopened"}); err != nil {
		t.Fatal(err)
	}
	gone, err := s.Apply(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if gone != 0 {
		t.Fatalf("%d segment(s) deleted under a hold placed after the plan",
			gone)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(left) == 0 {
		t.Fatal("everything was deleted under a hold")
	}
}

func TestAHoldNobodyCanExplainIsRefused(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	for _, h := range []Hold{
		{By: "rashik", Why: "incident"},
		{Name: "x", Why: "incident"},
		{Name: "x", By: "rashik"},
	} {
		if err := s.Hold(h); err == nil {
			t.Errorf("accepted a hold missing something: %+v", h)
		}
	}
}

func TestTheWatermarkIsMeasuredRatherThanConfigured(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()

	// Ninety prompt arrivals and ten that took an hour. Nobody configured an
	// hour anywhere; the spool watched it happen.
	for i := range 90 {
		at := base.Add(time.Duration(i) * time.Second)
		if _, err := s.Append(event(at, at, "prompt")); err != nil {
			t.Fatal(err)
		}
	}
	var newest time.Time
	for i := range 10 {
		newest = base.Add(time.Duration(90+i) * time.Second)
		if _, err := s.Append(event(newest.Add(-time.Hour), newest,
			"an hour late")); err != nil {
			t.Fatal(err)
		}
	}

	if lat := s.Lateness(0.5); lat > time.Minute {
		t.Errorf("the median delay is %s; most events arrived at once", lat)
	}
	if lat := s.Lateness(0.99); lat < time.Hour {
		t.Errorf("the 99th percentile is %s, under the hour a tenth of the "+
			"events actually took", lat)
	}
	wm := s.Watermark()
	if !wm.Before(newest.Add(-time.Hour)) {
		t.Errorf("the watermark %s is not behind the newest arrival by the "+
			"observed tail", wm)
	}
}

// The stated limit, asserted rather than left in a comment: a source that is
// slow once in a while does not move the 99th percentile, so its late event
// falls outside a window that has already closed. That is the trade the
// quantile makes, and a caller who cannot accept it asks for a higher one.
func TestARareLateArrivalDoesNotMoveTheWatermarkAndIsSaidSo(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	for i := range 999 {
		at := base.Add(time.Duration(i) * time.Second)
		if _, err := s.Append(event(at, at, "prompt")); err != nil {
			t.Fatal(err)
		}
	}
	slow := base.Add(1000 * time.Second)
	if _, err := s.Append(event(slow.Add(-6*time.Hour), slow,
		"a daily export")); err != nil {
		t.Fatal(err)
	}
	if lat := s.Lateness(0.99); lat > time.Minute {
		t.Errorf("one arrival in a thousand moved the 99th percentile to %s",
			lat)
	}
	// And it is in the spool regardless. Excluded from a closed window is not
	// the same as dropped.
	var found bool
	if err := s.During(slow.Add(-7*time.Hour), slow,
		func(e telemetry.Event) error {
			if e.Message == "a daily export" {
				found = true
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("the late event is not in the store")
	}
	// A tail of one in a thousand is not reached by the 99.9th percentile
	// either — the 999th of a thousand ordered samples is still prompt. Only
	// the whole distribution reaches it, and that is the honest shape of the
	// trade rather than a rounding detail.
	if lat := s.Lateness(1); lat < 6*time.Hour {
		t.Errorf("the whole distribution does not reach the tail: %s", lat)
	}
}

func TestAClockRunningFastIsCountedRatherThanAveragedIn(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	// Happened "later" than it arrived: the source's clock is ahead.
	if _, err := s.Append(event(base.Add(10*time.Minute), base,
		"fast clock")); err != nil {
		t.Fatal(err)
	}
	if s.Ahead() != 1 {
		t.Errorf("a source running fast was not counted: %d", s.Ahead())
	}
	if lat := s.Lateness(0.99); lat != 0 {
		t.Errorf("a negative delay was folded into the arrival delay: %s",
			lat)
	}
}

func TestASpoolReopensWithEverythingItKnew(t *testing.T) {
	c := &clock{at: base}
	dir := t.TempDir()
	s, err := Open(dir, Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, aerr := s.Append(event(base, base,
			fmt.Sprintf("event %d", i))); aerr != nil {
			t.Fatal(aerr)
		}
	}
	if err := s.Hold(Hold{Name: "audit", By: "rashik",
		Why: "evidence for the SOC 2 period"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir, Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if again.Events() != 5 {
		t.Errorf("reopened with %d events", again.Events())
	}
	if len(again.Holds()) != 1 {
		t.Error("the hold did not survive a restart, so retention would run")
	}
	if bad, verr := again.Verify(); verr != nil || len(bad) != 0 {
		t.Errorf("reopened spool does not verify: %v %v", bad, verr)
	}
	var seen int
	if err := again.Range(time.Time{}, time.Time{},
		func(telemetry.Event) error { seen++; return nil }); err != nil {
		t.Fatal(err)
	}
	if seen != 5 {
		t.Errorf("read back %d events", seen)
	}
}

func TestAnIndexedSegmentThatIsNotOnDiskIsAnError(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	if _, err := s.Append(event(base, base, "login")); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, s.Segments()[0].Name)); err != nil {
		t.Fatal(err)
	}
	err := s.Range(time.Time{}, time.Time{},
		func(telemetry.Event) error { return nil })
	if err == nil {
		t.Fatal("a query over a spool missing a file reported nothing wrong, " +
			"which reads exactly like a quiet period")
	}
	if !strings.Contains(err.Error(), "coverage it does not have") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

func TestAnUnusableEventIsRefusedAtTheDoor(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	if _, err := s.Append(telemetry.Event{Received: base}); err == nil {
		t.Fatal("an event with no time was stored, and nothing can window it")
	}
	if s.Events() != 0 {
		t.Error("the refused event was counted")
	}
}

func TestReceivedIsStampedWhenTheCallerLeavesItOut(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	e := event(base.Add(-time.Minute), time.Time{}, "no arrival time")
	if _, err := s.Append(e); err != nil {
		t.Fatal(err)
	}
	var got telemetry.Event
	if err := s.Range(time.Time{}, time.Time{},
		func(e telemetry.Event) error { got = e; return nil }); err != nil {
		t.Fatal(err)
	}
	if !got.Received.Equal(base) {
		t.Errorf("arrival stamped as %s, want the spool's clock", got.Received)
	}
}

// Dropping everything is a real plan and a zero date is the one line in the
// output somebody would skim past.
func TestAPlanThatEmptiesTheSpoolSaysSoInWords(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{SegmentBytes: 200, Keep: time.Second})
	defer s.Close()
	if _, err := s.Append(event(base, base, "login")); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	c.at = base.Add(time.Hour)
	p := s.Retain()
	if len(p.Drop) != 1 {
		t.Fatalf("planned to drop %d", len(p.Drop))
	}
	if strings.Contains(p.Why(), "0001") {
		t.Errorf("the plan prints a zero date: %q", p.Why())
	}
	if !strings.Contains(p.Why(), "no period at all") {
		t.Errorf("the plan does not say the spool would be empty: %q",
			p.Why())
	}
}
