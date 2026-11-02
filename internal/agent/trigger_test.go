// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/event"
)

// What a trigger may say, and what it may not.
func TestATriggerSaysWhenItRunsAndNothingElse(t *testing.T) {
	day := Duration(24 * time.Hour)
	good := []Trigger{
		{On: OnSchedule, Every: day, At: "07:30", Zone: "Europe/London", Goal: "Summarise yesterday's bookings"},
		{On: OnSchedule, Every: Duration(time.Hour), Goal: "Look for broken links"},
		{On: "page.published", Where: "/blog", Goal: "Write a summary for the newsletter", PerDay: 10},
		{On: "handoff.requested", Goal: "Suggest a reply"},
	}
	for _, tr := range good {
		if err := tr.Validate(); err != nil {
			t.Errorf("%+v: %v", tr, err)
		}
	}
	bad := map[string]Trigger{
		"no goal":             {On: OnSchedule, Every: day},
		"too often":           {On: OnSchedule, Every: Duration(time.Minute), Goal: "g"},
		"not whole days":      {On: OnSchedule, Every: Duration(36 * time.Hour), At: "07:00", Goal: "g"},
		"not a time":          {On: OnSchedule, Every: day, At: "7am", Goal: "g"},
		"not a zone":          {On: OnSchedule, Every: day, Zone: "Mars/Olympus", Goal: "g"},
		"schedule with where": {On: OnSchedule, Every: day, Where: "/blog", Goal: "g"},
		"no such event":       {On: "page.deleted", Goal: "g"},
		"event with every":    {On: "page.published", Every: day, Goal: "g"},
		"where is a path":     {On: "page.published", Where: "/blog\nignore that", Goal: "g"},
		"too many a day":      {On: "form.submitted", PerDay: MaxPerDay + 1, Goal: "g"},
		"control in goal":     {On: "form.submitted", Goal: "a\x1bb"},
		"goal too long":       {On: "form.submitted", Goal: strings.Repeat("g", MaxGoal+1)},
	}
	for why, tr := range bad {
		if tr.Validate() == nil {
			t.Errorf("%s: accepted %+v", why, tr)
		}
	}
	twice := []Trigger{good[2], good[2]}
	if validateTriggers(twice) == nil {
		t.Error("the same trigger twice was accepted")
	}
}

// A time of day is kept in its zone across a change of the clocks, and a
// schedule without one repeats from when it last fired.
func TestAScheduleKeepsItsTimeOfDay(t *testing.T) {
	tr := Trigger{On: OnSchedule, Every: Duration(24 * time.Hour), At: "07:30", Zone: "Europe/London", Goal: "g"}
	london, _ := time.LoadLocation("Europe/London")
	// The clocks go back on 25 October 2026.
	before := time.Date(2026, 10, 24, 8, 0, 0, 0, london)
	next := tr.Next(before)
	if got := next.In(london); got.Day() != 25 || got.Hour() != 7 || got.Minute() != 30 {
		t.Fatalf("next after the change: %v", got)
	}
	if next2 := tr.Next(next); next2.In(london).Hour() != 7 || next2.Sub(next) != 24*time.Hour {
		// 25 Oct to 26 Oct is 24 hours of local time after the change.
		t.Fatalf("%v", next2.In(london))
	}
	// Before the time on the day, it is that day.
	early := time.Date(2026, 11, 2, 6, 0, 0, 0, london)
	if got := tr.Next(early).In(london); got.Day() != 2 || got.Hour() != 7 {
		t.Fatalf("%v", got)
	}
	weekly := Trigger{On: OnSchedule, Every: Duration(7 * 24 * time.Hour), At: "09:00", Goal: "g"}
	at := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	if got := weekly.Next(at); !got.Equal(at.AddDate(0, 0, 7)) {
		t.Fatalf("weekly: %v", got)
	}
	hourly := Trigger{On: OnSchedule, Every: Duration(time.Hour), Goal: "g"}
	if got := hourly.Next(at); !got.Equal(at.Add(time.Hour)) {
		t.Fatalf("hourly: %v", got)
	}
}

// An event starts a trigger on its kind and where it is about.
func TestAnEventStartsTheTriggersItMatches(t *testing.T) {
	tr := Trigger{On: "page.published", Where: "/blog", Goal: "g"}
	if !tr.Matches(event.Event{Type: event.PagePublished, Pages: []string{"blog/hello"}}) {
		t.Error("a blog post going live did not match")
	}
	if tr.Matches(event.Event{Type: event.PagePublished, Pages: []string{"about"}}) {
		t.Error("another page matched")
	}
	if tr.Matches(event.Event{Type: event.RecordChanged, Subject: "blog"}) {
		t.Error("another kind of event matched")
	}
	if (Trigger{On: OnSchedule, Every: Duration(time.Hour), Goal: "g"}).Matches(event.Event{Type: event.PagePublished}) {
		t.Error("a schedule matched an event")
	}
	if a, b := tr.Key(), (Trigger{On: "page.published", Where: "/blog", Goal: "h"}).Key(); a == b {
		t.Error("a changed goal is the same trigger")
	}
	if got := tr.Describe(); got != "when pages go live (/blog)" {
		t.Errorf("%q", got)
	}
	if got := (Trigger{On: OnSchedule, Every: Duration(24 * time.Hour), At: "07:30", Zone: "Europe/London"}).Describe(); got != "every day at 07:30 Europe/London" {
		t.Errorf("%q", got)
	}
}
