// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ical

import (
	"strings"
	"testing"
	"time"
)

func TestACalendarSaysWhenWhereAndWhetherItIsOn(t *testing.T) {
	london, err := time.LoadLocation("Europe/London")
	if err != nil {
		t.Skip("no zone database")
	}
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	cal := string(Write("Crumb events", "Events", []Event{
		{UID: "a@crumb.example", Start: time.Date(2026, 11, 14, 19, 30, 0, 0, london),
			End: time.Date(2026, 11, 14, 21, 0, 0, 0, london), Summary: "Rye night; bring, a loaf",
			Location: "The bakery, 1 High Street", Description: "Two lines\nof it"},
		{UID: "b@crumb.example", Start: time.Date(2026, 11, 20, 0, 0, 0, 0, london),
			End: time.Date(2026, 11, 22, 0, 0, 0, 0, london), AllDay: true, Summary: "Market", Status: Cancelled},
		{UID: "c@crumb.example", Start: time.Date(2026, 12, 1, 10, 0, 0, 0, london), Summary: "Open day"},
	}, now))
	for _, want := range []string{
		"DTSTART:20261114T193000Z", "DTEND:20261114T210000Z",
		`SUMMARY:Rye night\; bring\, a loaf`, `LOCATION:The bakery\, 1 High Street`, `DESCRIPTION:Two lines\nof it`,
		"DTSTART;VALUE=DATE:20261120", "DTEND;VALUE=DATE:20261122", "STATUS:CANCELLED",
		"DTSTART:20261201T100000Z", "PRODID:-//Quilzo//Events//EN",
	} {
		if !strings.Contains(cal, want+"\r\n") {
			t.Errorf("the calendar lacks %q:\n%s", want, cal)
		}
	}
	// An event with no end is a moment, not one ending in the year 1.
	open := cal[strings.Index(cal, "UID:c@"):]
	if strings.Contains(open[:strings.Index(open, "END:VEVENT")], "DTEND") {
		t.Error("an event with no end was given one")
	}
	for _, line := range strings.Split(cal, "\r\n") {
		if len(line) > 75 {
			t.Errorf("a line longer than 75 octets: %q", line)
		}
	}
}
