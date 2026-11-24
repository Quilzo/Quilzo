// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ical

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func cal(events ...string) []byte {
	return []byte("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nX-WR-CALNAME:Crumb\r\n" +
		strings.Join(events, "") + "END:VCALENDAR\r\n")
}

func vevent(lines ...string) string {
	return "BEGIN:VEVENT\r\n" + strings.Join(lines, "\r\n") + "\r\nEND:VEVENT\r\n"
}

func mustParse(t *testing.T, body []byte, floating *time.Location) *Read {
	t.Helper()
	c, err := Parse(body, floating)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestACalendarIsReadAsItsEventsSay(t *testing.T) {
	london, _ := time.LoadLocation("Europe/London")
	c := mustParse(t, cal(vevent(
		"UID:a@x", "DTSTART;TZID=Europe/London:20261114T193000", "DTEND;TZID=Europe/London:20261114T210000",
		`SUMMARY:Rye night\; bring\, a loaf`,
		"DESCRIPTION:A long description that a calendar folded over more than one line because it",
		"  is long",
		`LOCATION:The bakery\, 1 High Street`, "STATUS:CANCELLED",
		"BEGIN:VALARM", "ACTION:DISPLAY", "DESCRIPTION:Reminder", "TRIGGER:-PT15M", "END:VALARM",
	), vevent("UID:b@x", "DTSTART;VALUE=DATE:20261120", "DTEND;VALUE=DATE:20261122", "SUMMARY:Market")), time.UTC)
	if c.Name != "Crumb" || len(c.Events) != 2 {
		t.Fatalf("read %q with %d events", c.Name, len(c.Events))
	}
	a := c.Events[0]
	if a.Summary != "Rye night; bring, a loaf" || a.Location != "The bakery, 1 High Street" {
		t.Errorf("escapes were not undone: %q, %q", a.Summary, a.Location)
	}
	if a.Description != "A long description that a calendar folded over more than one line because it is long" {
		t.Errorf("an alarm's description, or the folding, changed the event's: %q", a.Description)
	}
	if !a.Start.Equal(time.Date(2026, 11, 14, 19, 30, 0, 0, london)) || !a.End.Equal(time.Date(2026, 11, 14, 21, 0, 0, 0, london)) {
		t.Errorf("times %v to %v", a.Start, a.End)
	}
	if a.Status != "CANCELLED" {
		t.Errorf("status %q", a.Status)
	}
	b := c.Events[1]
	if !b.AllDay || b.Start.Format("2006-01-02") != "2026-11-20" || b.End.Format("2006-01-02") != "2026-11-22" {
		t.Errorf("an all-day event was read as %v to %v (all day %v)", b.Start, b.End, b.AllDay)
	}
}

func TestEveryZoneACalendarNamesResolves(t *testing.T) {
	kathmandu, _ := time.LoadLocation("Asia/Kathmandu")
	ny, _ := time.LoadLocation("America/New_York")
	c := mustParse(t, cal(
		"BEGIN:VTIMEZONE\r\nTZID:Made Up Time\r\nBEGIN:STANDARD\r\nDTSTART:19700101T000000\r\n"+
			"TZOFFSETFROM:+0300\r\nTZOFFSETTO:+0300\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n",
		vevent("UID:1", "DTSTART;TZID=Eastern Standard Time:20261201T100000", "SUMMARY:Outlook"),
		vevent("UID:2", "DTSTART;TZID=/mozilla.org/20050126_1/Asia/Kathmandu:20261201T100000", "SUMMARY:Thunderbird"),
		vevent("UID:3", "DTSTART;TZID=\"Made Up Time\":20261201T100000", "SUMMARY:Its own"),
		vevent("UID:4", "DTSTART;TZID=Nowhere/Atall:20261201T100000", "SUMMARY:Unknown"),
		vevent("UID:5", "DTSTART:20261201T100000Z", "DURATION:PT1H30M", "SUMMARY:UTC"),
		vevent("UID:6", "DTSTART:20261201T100000", "SUMMARY:Floating"),
	), kathmandu)
	want := []time.Time{
		time.Date(2026, 12, 1, 10, 0, 0, 0, ny),
		time.Date(2026, 12, 1, 10, 0, 0, 0, kathmandu),
		time.Date(2026, 12, 1, 7, 0, 0, 0, time.UTC),
		time.Date(2026, 12, 1, 10, 0, 0, 0, kathmandu),
		time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 12, 1, 10, 0, 0, 0, kathmandu),
	}
	for i, w := range want {
		if !c.Events[i].Start.Equal(w) {
			t.Errorf("%s: %v, want %v", c.Events[i].Summary, c.Events[i].Start, w)
		}
	}
	if e := c.Events[4]; !e.HasEnd || e.End.Sub(e.Start) != 90*time.Minute {
		t.Errorf("a length was not an end: %v", e.End)
	}
	notes := strings.Join(c.Notes, "\n")
	if !strings.Contains(notes, "Made Up Time") || !strings.Contains(notes, "Nowhere/Atall") {
		t.Errorf("the zones read differently were not said:\n%s", notes)
	}
}

func TestWhatIsNotACalendarIsRefused(t *testing.T) {
	for _, body := range []string{"", "hello", "BEGIN:VCARD\r\nEND:VCARD\r\n"} {
		if _, err := Parse([]byte(body), nil); err == nil {
			t.Errorf("%q was read as a calendar", body)
		}
	}
}

func dates(os []Occurrence, layout string) string {
	var out []string
	for _, o := range os {
		out = append(out, o.Start.Format(layout))
	}
	return strings.Join(out, " ")
}

func TestARepeatingEventIsEachTimeItHappens(t *testing.T) {
	london, _ := time.LoadLocation("Europe/London")
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, start, rule string
		extra             []string
		want              string
	}{
		{"weekly on two days, six times", "20261005T190000", "FREQ=WEEKLY;BYDAY=MO,WE;COUNT=6", nil,
			"2026-10-05 2026-10-07 2026-10-12 2026-10-14 2026-10-19 2026-10-21"},
		{"fortnightly until a day", "20261006T190000", "FREQ=WEEKLY;INTERVAL=2;UNTIL=20261117", nil,
			"2026-10-06 2026-10-20 2026-11-03 2026-11-17"},
		{"the second Tuesday of each month", "20261013T190000", "FREQ=MONTHLY;BYDAY=2TU;COUNT=4", nil,
			"2026-10-13 2026-11-10 2026-12-08 2027-01-12"},
		{"the last Friday", "20261030T190000", "FREQ=MONTHLY;BYDAY=-1FR;COUNT=3", nil,
			"2026-10-30 2026-11-27 2026-12-25"},
		{"the last day of the month", "20261031T190000", "FREQ=MONTHLY;BYMONTHDAY=-1;COUNT=4", nil,
			"2026-10-31 2026-11-30 2026-12-31 2027-01-31"},
		{"the 31st, skipping months without one", "20261031T190000", "FREQ=MONTHLY;COUNT=3", nil,
			"2026-10-31 2026-12-31 2027-01-31"},
		{"every year", "20261105T190000", "FREQ=YEARLY", nil, "2026-11-05 2027-11-05"},
		{"Thanksgiving", "20261126T120000", "FREQ=YEARLY;BYMONTH=11;BYDAY=4TH", nil, "2026-11-26 2027-11-25"},
		{"daily but not on one day, and once more", "20261201T080000", "FREQ=DAILY;COUNT=4",
			[]string{"EXDATE;TZID=Europe/London:20261202T080000", "RDATE;TZID=Europe/London:20261225T080000"},
			"2026-12-01 2026-12-03 2026-12-04 2026-12-25"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := append([]string{"UID:r@x", "SUMMARY:" + tc.name, "DTSTART;TZID=Europe/London:" + tc.start,
				"RRULE:" + tc.rule}, tc.extra...)
			c := mustParse(t, cal(vevent(lines...)), london)
			got, notes := c.Occurrences(from, to, 400)
			if d := dates(got, "2006-01-02"); d != tc.want {
				t.Errorf("got  %s\nwant %s\nnotes %v", d, tc.want, notes)
			}
		})
	}
}

func TestATimeOfDayStaysThroughSummerTime(t *testing.T) {
	london, _ := time.LoadLocation("Europe/London")
	c := mustParse(t, cal(vevent("UID:w@x", "SUMMARY:Class", "DTSTART;TZID=Europe/London:20261019T190000",
		"DTEND;TZID=Europe/London:20261019T200000", "RRULE:FREQ=WEEKLY;COUNT=3")), london)
	got, _ := c.Occurrences(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), 10)
	for _, o := range got {
		if o.Start.In(london).Format("15:04") != "19:00" || o.End.In(london).Format("15:04") != "20:00" {
			t.Errorf("%v to %v is not 19:00 to 20:00 in London", o.Start, o.End)
		}
	}
	if len(got) != 3 || got[1].Start.UTC().Hour() != 19 || got[0].Start.UTC().Hour() != 18 {
		t.Errorf("the clocks going back did not move UTC: %v", dates(got, time.RFC3339))
	}
}

func TestOneTimeChangedOrCancelledReplacesTheTimeItChanges(t *testing.T) {
	c := mustParse(t, cal(
		vevent("UID:s@x", "SUMMARY:Choir", "DTSTART:20261102T180000Z", "DTEND:20261102T190000Z",
			"RRULE:FREQ=WEEKLY;COUNT=3"),
		vevent("UID:s@x", "RECURRENCE-ID:20261109T180000Z", "SUMMARY:Choir, in the hall",
			"DTSTART:20261109T183000Z", "DTEND:20261109T193000Z"),
		vevent("UID:s@x", "RECURRENCE-ID:20261116T180000Z", "SUMMARY:Choir", "STATUS:CANCELLED",
			"DTSTART:20261116T180000Z"),
	), time.UTC)
	got, _ := c.Occurrences(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), 10)
	if len(got) != 3 {
		t.Fatalf("%d times: %s", len(got), dates(got, time.RFC3339))
	}
	if got[1].Summary != "Choir, in the hall" || got[1].Start.Format("15:04") != "18:30" || got[1].Key != "20261109T180000Z" {
		t.Errorf("the moved time was %q at %v, key %q", got[1].Summary, got[1].Start, got[1].Key)
	}
	if got[2].Status != "CANCELLED" {
		t.Errorf("the cancelled time is %q", got[2].Status)
	}
}

func TestARuleThatIsNotReadBringsItsFirstTimeAndSaysSo(t *testing.T) {
	c := mustParse(t, cal(vevent("UID:p@x", "SUMMARY:Odd", "DTSTART:20261102T180000Z",
		"RRULE:FREQ=MONTHLY;BYDAY=MO,TU,WE,TH,FR;BYSETPOS=-1")), time.UTC)
	got, notes := c.Occurrences(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), 10)
	if len(got) != 1 || len(notes) != 1 || !strings.Contains(notes[0], "first time") {
		t.Errorf("%d times, notes %v", len(got), notes)
	}
}

func TestAnEndlessRuleStopsAtTheWindowAndTheCap(t *testing.T) {
	c := mustParse(t, cal(vevent("UID:d@x", "SUMMARY:Daily", "DTSTART:19900101T090000Z", "RRULE:FREQ=DAILY")), time.UTC)
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	got, _ := c.Occurrences(from, from.AddDate(0, 0, 10), 400)
	if len(got) != 10 || got[0].Start.Format("2006-01-02") != "2026-10-01" {
		t.Errorf("%d times from %s", len(got), dates(got, "2006-01-02"))
	}
	got, notes := c.Occurrences(from, from.AddDate(1, 0, 0), 30)
	if len(got) != 30 || len(notes) == 0 {
		t.Errorf("the cap was not kept, or not said: %d, %v", len(got), notes)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(string(cal(vevent("UID:a", "DTSTART:20261102T180000Z", "RRULE:FREQ=WEEKLY;BYDAY=MO,2TU;COUNT=5",
		"DURATION:P1DT2H"))))
	f.Add("BEGIN:VCALENDAR\nBEGIN:VEVENT\nDTSTART;TZID=\"a:b\";VALUE=DATE:20260101\nRRULE:FREQ=YEARLY;BYMONTH=2;BYMONTHDAY=-1\nEND:VEVENT\n")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := Parse([]byte(s), time.UTC)
		if err != nil {
			return
		}
		from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		got, _ := c.Occurrences(from, from.AddDate(1, 0, 0), 50)
		if len(got) > 50*(len(c.Events)+1) {
			t.Fatalf("%d times from %d events", len(got), len(c.Events))
		}
	})
}

// raceSlowdown is how many times its budget a timed test is given: once,
// and ten times when it is built with the race detector (race_test.go).
var raceSlowdown time.Duration = 1

func TestManyOldRulesAreQuickToWorkOut(t *testing.T) {
	var evs []string
	for i := 0; i < 3000; i++ {
		evs = append(evs, vevent("UID:"+strings.Repeat("x", i%7)+string(rune('a'+i%26)), "SUMMARY:Old",
			"DTSTART:19000101T090000Z", "RRULE:FREQ=DAILY"))
	}
	c := mustParse(t, cal(evs...), time.UTC)
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	start := time.Now()
	got, notes := c.Occurrences(from, from.AddDate(1, 0, 0), 400)
	if time.Since(start) > 5*time.Second*raceSlowdown {
		t.Errorf("took %v", time.Since(start))
	}
	if len(got) == 0 || len(notes) == 0 {
		t.Errorf("%d times, notes %v", len(got), notes)
	}
}

// A property folded over many lines is unfolded in time and memory that
// grow with its length. Each continuation was added to the line before it,
// copying all of it each time: a calendar of 960 KB took 18 seconds, and
// one at MaxBytes would take over an hour of a server's CPU.
func TestALongFoldedLineIsQuickToUnfold(t *testing.T) {
	const n = 20000
	lines := []string{"UID:a@x", "DTSTART:20261114T193000Z", "SUMMARY:Long", "DESCRIPTION:start"}
	for i := 0; i < n; i++ {
		lines = append(lines, " xxxxxxxxx")
	}
	body := cal(vevent(lines...))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	c := mustParse(t, body, time.UTC)
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	if len(c.Events) != 1 || c.Events[0].Description != "start"+strings.Repeat("xxxxxxxxx", n) {
		t.Fatalf("unfolded wrongly: %d events", len(c.Events))
	}
	if spent := after.TotalAlloc - before.TotalAlloc; spent > 64<<20 || took > 2*time.Second {
		t.Fatalf("%d KB took %v and %d MB to read", len(body)>>10, took, spent>>20)
	}
}
