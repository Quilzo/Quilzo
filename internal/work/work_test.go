// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package work

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)

func aBoard(t *testing.T) *Board {
	t.Helper()
	b, err := NewBoard("eng",
		Kind{Name: "change", Requires: []string{"reviewed", "tested"}},
		Kind{Name: "chore"},
	)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func added(t *testing.T, b *Board, title, kind, owner string) *Item {
	t.Helper()
	it, err := b.Add(title, kind, owner,
		Origin{Kind: FromPerson, Who: "ada", At: t0}, t0)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

// TestThereIsNoFifthState, and the refusal says what to use instead.
func TestThereIsNoFifthState(t *testing.T) {
	b := aBoard(t)
	it := added(t, b, "write the migration", "change", "grace")
	err := b.Move(it.ID, "in review", "grace", "", t0)
	if err == nil {
		t.Fatal("a fifth state was accepted")
	}
	if !strings.Contains(err.Error(), "waiting on") {
		t.Fatalf("the refusal does not say what to use instead: %v", err)
	}
}

// TestWhatWasAStatusIsNowAWait: "in review" becomes doing + waiting on alan.
func TestWhatWasAStatusIsNowAWait(t *testing.T) {
	b := aBoard(t)
	it := added(t, b, "write the migration", "change", "grace")
	if err := b.Move(it.ID, Doing, "grace", "", t0); err != nil {
		t.Fatal(err)
	}
	if err := b.Wait(it.ID, Waiting{Kind: OnPerson, On: "alan",
		For: "a review"}, t0); err != nil {
		t.Fatal(err)
	}
	if it.State != Doing || it.Waiting == nil {
		t.Fatalf("state %s, waiting %+v", it.State, it.Waiting)
	}
	// And the question a status cannot answer.
	got := b.Blocking("alan")
	if len(got) != 1 || got[0].ID != it.ID {
		t.Fatalf("blocking alan = %d items", len(got))
	}
	if len(b.Blocking("grace")) != 0 {
		t.Fatal("the owner is not the blocker")
	}
}

func TestAWaitHasToNameSomebodyAndSomething(t *testing.T) {
	b := aBoard(t)
	it := added(t, b, "write the migration", "change", "grace")
	if err := b.Move(it.ID, Doing, "grace", "", t0); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		w    Waiting
	}{
		{"nobody named", Waiting{Kind: OnPerson, For: "a review"}},
		{"nothing named", Waiting{Kind: OnPerson, On: "alan"}},
		{"no such kind", Waiting{Kind: "vibes", On: "alan", For: "x"}},
		{"a date with no date", Waiting{Kind: OnTime, For: "the release"}},
	} {
		if err := b.Wait(it.ID, c.w, t0); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	if err := b.Wait(it.ID, Waiting{Kind: OnTime, For: "the release",
		Until: t0.Add(48 * time.Hour)}, t0); err != nil {
		t.Fatalf("a dated wait was refused: %v", err)
	}
}

// TestDoneMeansTheDefinitionIsMet.
func TestDoneMeansTheDefinitionIsMet(t *testing.T) {
	b := aBoard(t)
	it := added(t, b, "write the migration", "change", "grace")
	if err := b.Move(it.ID, Doing, "grace", "", t0); err != nil {
		t.Fatal(err)
	}
	err := b.Move(it.ID, Done, "grace", "", t0)
	if err == nil {
		t.Fatal("it was done without meeting its definition")
	}
	if !strings.Contains(err.Error(), "reviewed") ||
		!strings.Contains(err.Error(), "tested") {
		t.Fatalf("the refusal does not name what is missing: %v", err)
	}
	if err := b.Meet(it.ID, "reviewed"); err != nil {
		t.Fatal(err)
	}
	if err := b.Move(it.ID, Done, "grace", "", t0); err == nil {
		t.Fatal("one of two was enough")
	}
	// Excusing the other, on the record.
	if err := b.Excuse(it.ID, "tested", "", "no time"); err == nil {
		t.Fatal("an anonymous exception was accepted")
	}
	if err := b.Excuse(it.ID, "tested", "ada",
		"covered by the integration suite"); err != nil {
		t.Fatal(err)
	}
	if err := b.Move(it.ID, Done, "grace", "", t0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(it.Excused["tested"], "ada") {
		t.Fatalf("the exception does not say who: %v", it.Excused)
	}
	// A kind with no definition needs nothing.
	c := added(t, b, "tidy the logs", "chore", "alan")
	if err := b.Move(c.ID, Done, "alan", "", t0); err != nil {
		t.Fatalf("a chore could not be finished: %v", err)
	}
}

// TestGoingBackwardsNeedsAReason.
func TestGoingBackwardsNeedsAReason(t *testing.T) {
	b := aBoard(t)
	it := added(t, b, "tidy the logs", "chore", "alan")
	if err := b.Move(it.ID, Doing, "alan", "", t0); err != nil {
		t.Fatal(err)
	}
	if err := b.Move(it.ID, Done, "alan", "", t0); err != nil {
		t.Fatal(err)
	}
	if err := b.Move(it.ID, Doing, "ada", "", t0); err == nil {
		t.Fatal("it was reopened silently")
	}
	if err := b.Move(it.ID, Doing, "ada", "the logs still rotate wrong",
		t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	last := it.Log[len(it.Log)-1]
	if !last.From.Backward(last.To) || last.Why == "" {
		t.Fatalf("the reopening is not recorded as one: %+v", last)
	}
	if s := b.Look(time.Hour, t0); s.Reopened != 1 {
		t.Fatalf("reopened = %d", s.Reopened)
	}
}

func TestDroppingNeedsAReason(t *testing.T) {
	b := aBoard(t)
	it := added(t, b, "tidy the logs", "chore", "alan")
	if err := b.Move(it.ID, Dropped, "ada", "", t0); err == nil {
		t.Fatal("work was abandoned silently")
	}
	if err := b.Move(it.ID, Dropped, "ada", "the service is being retired",
		t0); err != nil {
		t.Fatal(err)
	}
	if it.State != Dropped {
		t.Fatalf("state = %s", it.State)
	}
}

// TestFinishingClearsTheWait.
func TestFinishingClearsTheWait(t *testing.T) {
	b := aBoard(t)
	it := added(t, b, "tidy the logs", "chore", "alan")
	if err := b.Move(it.ID, Doing, "alan", "", t0); err != nil {
		t.Fatal(err)
	}
	if err := b.Wait(it.ID, Waiting{Kind: OnTeam, On: "platform",
		For: "a deploy slot"}, t0); err != nil {
		t.Fatal(err)
	}
	if err := b.Move(it.ID, Done, "alan", "", t0); err != nil {
		t.Fatal(err)
	}
	if it.Waiting != nil {
		t.Fatal("finished work is still waiting on somebody")
	}
	if len(b.Blocking("platform")) != 0 {
		t.Fatal("platform is still shown as blocking something finished")
	}
}

// TestTheQueueSaysWhoTheBoardIsWaitingOn.
func TestTheQueueSaysWhoTheBoardIsWaitingOn(t *testing.T) {
	b := aBoard(t)
	for i, title := range []string{"one", "two", "three"} {
		it := added(t, b, title, "chore", "grace")
		if err := b.Move(it.ID, Doing, "grace", "", t0); err != nil {
			t.Fatal(err)
		}
		on, kind := "alan", OnPerson
		if i == 2 {
			on, kind = "platform", OnTeam
		}
		if err := b.Wait(it.ID, Waiting{Kind: kind, On: on,
			For:   "a review",
			Since: t0.Add(-time.Duration(i+1) * 24 * time.Hour)},
			t0); err != nil {
			t.Fatal(err)
		}
	}
	q := b.Queue(t0)
	if len(q) != 2 {
		t.Fatalf("%d in the queue", len(q))
	}
	if q[0].On != "alan" || q[0].Items != 2 {
		t.Fatalf("worst = %+v", q[0])
	}
	if q[0].Worst != 48*time.Hour {
		t.Fatalf("worst wait = %s", q[0].Worst)
	}
	if q[1].Kind != OnTeam {
		t.Fatalf("second = %+v", q[1])
	}
}

// TestStuckTellsTheTwoKindsApart.
func TestStuckTellsTheTwoKindsApart(t *testing.T) {
	b := aBoard(t)
	waiting := added(t, b, "one", "chore", "grace")
	if err := b.Move(waiting.ID, Doing, "grace", "", t0); err != nil {
		t.Fatal(err)
	}
	if err := b.Wait(waiting.ID, Waiting{Kind: OnPerson, On: "alan",
		For: "a review", Since: t0.Add(-10 * 24 * time.Hour)},
		t0); err != nil {
		t.Fatal(err)
	}
	idle := added(t, b, "two", "chore", "grace")
	if err := b.Move(idle.ID, Doing, "grace", "",
		t0.Add(-20*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A dated wait that has not arrived is not stuck.
	soon := added(t, b, "three", "chore", "grace")
	if err := b.Move(soon.ID, Doing, "grace", "", t0); err != nil {
		t.Fatal(err)
	}
	if err := b.Wait(soon.ID, Waiting{Kind: OnTime, For: "the release",
		Until: t0.Add(72 * time.Hour),
		Since: t0.Add(-30 * 24 * time.Hour)}, t0); err != nil {
		t.Fatal(err)
	}

	got := b.Stuck(7*24*time.Hour, t0)
	if len(got) != 2 {
		t.Fatalf("%d stuck: %+v", len(got), got)
	}
	if got[0].Item.ID != idle.ID {
		t.Fatal("the worst should be first")
	}
	if !strings.Contains(got[0].Why, "nobody is") {
		t.Fatalf("idle why = %q", got[0].Why)
	}
	if !strings.Contains(got[1].Why, "alan") {
		t.Fatalf("waiting why = %q", got[1].Why)
	}
}

// TestTheSameWorkTwiceIsReportedNotMerged.
func TestTheSameWorkTwiceIsReportedNotMerged(t *testing.T) {
	b := aBoard(t)
	added(t, b, "Write the migration", "change", "grace")
	added(t, b, "write migration", "change", "alan")
	added(t, b, "tidy the logs", "chore", "alan")
	got := b.Twice()
	if len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("%d group(s)", len(got))
	}
	if len(b.Items) != 3 {
		t.Fatal("it merged them, which would be worse than the duplication")
	}
	// Finished work does not count as a duplicate of live work.
	if err := b.Move(got[0][0].ID, Dropped, "ada", "the other one",
		t0); err != nil {
		t.Fatal(err)
	}
	if len(b.Twice()) != 0 {
		t.Fatal("a dropped duplicate is still reported")
	}
}

// TestWorkNeedsAnOrigin.
func TestWorkNeedsAnOrigin(t *testing.T) {
	b := aBoard(t)
	if _, err := b.Add("something", "chore", "ada",
		Origin{Kind: FromPerson}, t0); err == nil {
		t.Fatal("work with no origin at all was accepted")
	}
	if _, err := b.Add("something", "chore", "ada",
		Origin{Kind: "vibes", Who: "ada"}, t0); err == nil {
		t.Fatal("an origin that is not one was accepted")
	}
	it, err := b.Add("write the migration", "change", "grace",
		Origin{Kind: FromCall, Ref: "standup", Who: "grace",
			Said: "i will write the migration today", At: t0}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if it.Origin.Said == "" {
		t.Fatal("the sentence did not survive")
	}
}

func TestADefinitionOfDoneIsShort(t *testing.T) {
	long := Kind{Name: "change"}
	for i := range MaxRequires + 1 {
		long.Requires = append(long.Requires, string(rune('a'+i)))
	}
	if err := long.Validate(); err == nil {
		t.Fatal("a process document was accepted as a definition of done")
	}
	if err := (Kind{Name: "x", Requires: []string{"a", "A"}}).
		Validate(); err == nil {
		t.Fatal("the same requirement twice was accepted")
	}
}

func TestShapeSaysWhatIsWrong(t *testing.T) {
	b := aBoard(t)
	added(t, b, "one", "chore", "")
	added(t, b, "one", "chore", "grace")
	s := b.Look(7*24*time.Hour, t0)
	if s.Unowned != 1 || s.Twice != 1 {
		t.Fatalf("%+v", s)
	}
	why := s.Why()
	if !strings.Contains(why, "no owner") || !strings.Contains(why, "once") {
		t.Fatalf("why = %q", why)
	}
	clean, err := NewBoard("clean", Kind{Name: "chore"})
	if err != nil {
		t.Fatal(err)
	}
	if clean.Look(time.Hour, t0).Why() != "" {
		t.Fatal("an empty board has something to complain about")
	}
}
