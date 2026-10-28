// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package booking

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func salon() *Setup {
	return &Setup{Zone: "Europe/London", NoticeHours: 2,
		Week:   map[string][]Span{"tue": {{"09:00", "12:00"}, {"13:00", "17:00"}}, "sat": {{"09:00", "13:00"}}},
		Closed: []string{"2026-11-07"},
		Services: []Service{{Name: "cut", Title: "Haircut", Minutes: 45, Buffer: 15, Price: "£30"},
			{Name: "colour", Title: "Colour", Minutes: 120}}}
}

// Monday 2 November 2026, 08:00 in London (GMT).
var monday = time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)

func TestASetupSaysWhatIsWrongAtOnce(t *testing.T) {
	if err := salon().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := &Setup{Zone: "Mars/Olympus", Week: map[string][]Span{"funday": {{"09:00", "10:00"}},
		"mon": {{"09:00", "12:00"}, {"11:00", "13:00"}}}, Closed: []string{"tomorrow"},
		Services: []Service{{Name: "Cut!", Title: "", Minutes: 7}, {Name: "a", Title: "A", Minutes: 30, Buffer: 3}}}
	err := bad.Validate()
	for _, want := range []string{"not a time zone", "not a day", "overlaps", "not a date", "not a service name",
		"needs a title", "takes 7 minutes", "leaves 3 minutes"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("not said: %s\n%v", want, err)
		}
	}
	var sp Span
	if err := json.Unmarshal([]byte(`"17:00-09:00"`), &sp); err == nil {
		t.Error("a span that ends before it starts was read")
	}
	b, _ := json.Marshal(salon())
	var back Setup
	if err := json.Unmarshal(b, &back); err != nil || back.Week["tue"][1].String() != "13:00-17:00" {
		t.Fatalf("round trip: %v %+v", err, back.Week)
	}
}

// Free times are within the hours, after the notice, clear of bookings
// and their buffers whatever the service, and never on a closed day.
func TestFreeTimesKeepToTheHours(t *testing.T) {
	s := salon()
	cut, _ := s.Service("cut")
	days, err := Free(s, cut, nil, monday)
	if err != nil {
		t.Fatal(err)
	}
	if days[0].Date != "2026-11-03" || days[0].Label != "Tuesday 3 November" {
		t.Fatalf("first day %+v", days[0])
	}
	var labels []string
	for _, sl := range days[0].Slots {
		labels = append(labels, sl.Label)
	}
	// 45 minutes and 15 after: on the hour. 11:00 ends at 11:45, inside
	// noon, its buffer running past closing; 16:00 ends at 16:45.
	if got := strings.Join(labels, " "); got != "09:00 10:00 11:00 13:00 14:00 15:00 16:00" {
		t.Fatalf("Tuesday offers %s", got)
	}
	for _, d := range days {
		if d.Date == "2026-11-07" {
			t.Fatal("a closed Saturday was offered")
		}
	}
	// A colour from 10:00 to 12:00 on Tuesday leaves 09:00, whose 45
	// minutes and 15 after end at 10:00, meeting it without overlapping.
	busy := []Busy{{ID: "x", Service: "colour", Start: time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC),
		Until: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC), Minutes: 120}}
	days, _ = Free(s, cut, busy, monday)
	labels = nil
	for _, sl := range days[0].Slots {
		labels = append(labels, sl.Label)
	}
	if got := strings.Join(labels, " "); got != "09:00 13:00 14:00 15:00 16:00" {
		t.Fatalf("around a booking, Tuesday offers %s", got)
	}
	// Two hours' notice: at 09:30 on Tuesday, 11:00 is an hour and a half
	// away, so 13:00 is the first offered.
	days, _ = Free(s, cut, nil, time.Date(2026, 11, 3, 9, 30, 0, 0, time.UTC))
	if days[0].Slots[0].Label != "13:00" {
		t.Fatalf("with two hours' notice at 09:30, the first is %s", days[0].Slots[0].Label)
	}
	if s.Paused = true; !Offered(s, cut, nil, monday, days[0].Slots[0].Start) {
		t.Fatal("pausing changes what is free; it only stops new bookings")
	}
}

// A day the clocks change offers ten o'clock at ten, and nothing at a time
// that did not exist.
func TestFreeTimesFollowTheClockOnTheWall(t *testing.T) {
	s := &Setup{Zone: "Europe/London", Week: map[string][]Span{"sun": {{"00:30", "03:30"}, {"10:00", "11:00"}}},
		Services: []Service{{Name: "s", Title: "S", Minutes: 60}}}
	svc := s.Services[0]
	// Sunday 29 March 2026: 01:00 GMT becomes 02:00 BST.
	days, err := Free(s, svc, nil, time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var labels []string
	for _, sl := range days[0].Slots {
		labels = append(labels, sl.Label)
	}
	if days[0].Date != "2026-03-29" || strings.Contains(strings.Join(labels, " "), "01:30") ||
		!strings.Contains(strings.Join(labels, " "), "10:00") {
		t.Fatalf("on the night the clocks change: %s %v", days[0].Date, labels)
	}
	for _, sl := range days[0].Slots {
		if sl.Label == "10:00" && sl.Start.UTC().Hour() != 9 {
			t.Fatalf("10:00 BST is %v", sl.Start.UTC())
		}
	}
}

// Two visitors who saw the same free time: one is booked, the other told.
func TestOnlyOneVisitorGetsATime(t *testing.T) {
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := salon()
	cut, _ := s.Service("cut")
	at := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := b.Reserve(s, cut, at, monday, Details{Name: "Ann", Email: "ann@example.com"})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	won := 0
	for err := range results {
		if err == nil {
			won++
		} else if !errors.Is(err, ErrTaken) {
			t.Fatal(err)
		}
	}
	if won != 1 {
		t.Fatalf("%d visitors got 10:00", won)
	}
	// And a time not offered at all is refused.
	if _, _, err := b.Reserve(s, cut, at.Add(7*time.Minute), monday, Details{Name: "Bo", Email: "bo@example.com"}); !errors.Is(err, ErrTaken) {
		t.Fatalf("10:07: %v", err)
	}
}

// The calendar says when, never who; who is kept apart, read by the admin,
// and forgotten after the appointment.
func TestTheCalendarHoldsNoName(t *testing.T) {
	dir := t.TempDir()
	b, _ := Open(dir)
	s := salon()
	cut, _ := s.Service("cut")
	at := time.Date(2026, 11, 3, 13, 0, 0, 0, time.UTC)
	x, token, err := b.Reserve(s, cut, at, monday, Details{Name: "Ann Example", Email: "ann@example.com",
		Phone: "+44 113 496 0000", Note: "first time\nplease"})
	if err != nil {
		t.Fatal(err)
	}
	cal, _ := os.ReadFile(filepath.Join(dir, "calendar", "2026-11.json"))
	if strings.Contains(string(cal), "Ann") || strings.Contains(string(cal), "example.com") || strings.Contains(string(cal), token) {
		t.Fatalf("the calendar holds who, or the token: %s", cal)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "details", x.ID+".json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("details are %v", fi.Mode())
	}
	list, err := b.List(monday, monday.AddDate(0, 0, 7))
	if err != nil || len(list) != 1 || list[0].Who.Name != "Ann Example" || list[0].Who.Note != "first time\nplease" {
		t.Fatalf("the admin's list: %+v %v", list, err)
	}

	// Cancelled with the token, and only with it; the time is free again.
	if _, err := b.Cancel(x.ID, "wrong", "visitor", monday); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a wrong token: %v", err)
	}
	if c, err := b.Cancel(x.ID, token, "visitor", monday); err != nil || c.Live() || c.By != "visitor" {
		t.Fatalf("cancelled: %+v %v", c, err)
	}
	busy, _ := b.Window(s, monday)
	if !Offered(s, cut, busy, monday, at) {
		t.Fatal("a cancelled time is not free again")
	}

	// Forgotten a month after the appointment.
	if n, err := b.Expire(s.Keep(), at.Add(s.Keep()+2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("expired %d: %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "details", x.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("who booked outlived the keep")
	}
}

func TestWhatAVisitorSendsIsChecked(t *testing.T) {
	for _, d := range []Details{{Name: "", Email: "a@b.co"}, {Name: "A", Email: "not an address"},
		{Name: "A", Email: "a@b.co", Phone: "call me"}, {Name: strings.Repeat("a", 101), Email: "a@b.co"}} {
		if err := d.Clean(); err == nil {
			t.Errorf("accepted %+v", d)
		}
	}
	d := Details{Name: "Ann\x00\r\nEvil: header", Email: " ann@example.com ", Note: "line one\nline\x07two"}
	if err := d.Clean(); err != nil || d.Name != "AnnEvil: header" || d.Email != "ann@example.com" || d.Note != "line one\nlinetwo" {
		t.Fatalf("cleaned %+v %v", d, err)
	}
}

func TestACalendarFileIsWhatCalendarsRead(t *testing.T) {
	start := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	ics := string(ICS("Hart's Salon", []Event{{UID: "20261103-abc@site", Start: start, End: start.Add(45 * time.Minute),
		Summary: "Haircut, Hart's; with Ann", Description: strings.Repeat("A long line with an é in it. ", 6) + "\nCancel at https://x/y"}},
		monday))
	for _, want := range []string{"BEGIN:VCALENDAR\r\n", "DTSTART:20261103T100000Z\r\n", "DTEND:20261103T104500Z\r\n",
		`SUMMARY:Haircut\, Hart's\; with Ann` + "\r\n", "STATUS:CONFIRMED", "END:VCALENDAR\r\n"} {
		if !strings.Contains(ics, want) {
			t.Errorf("missing %q in\n%s", want, ics)
		}
	}
	for _, l := range strings.Split(ics, "\r\n") {
		if len(l) > 75 {
			t.Errorf("a line of %d octets: %q", len(l), l)
		}
	}
	if !strings.Contains(strings.ReplaceAll(ics, "\r\n ", ""), `\nCancel at https://x/y`) {
		t.Error("a folded description does not unfold to what was written")
	}
}
