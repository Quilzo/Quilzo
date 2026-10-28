// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package booking takes appointments on a published site: a plumber's
// visit, a haircut, a consultation.
//
// # What it is, and is not
//
// One calendar: one person or one room, taking one booking at a time. The
// site says its hours each week in its own time zone, the days it is
// closed, and the services it offers, each with how long it takes and how
// long to leave after it. A visitor picks a free time, says who they are,
// and is booked; they can add it to their calendar and cancel it from the
// page they were given. Several staff with calendars of their own, rooms,
// deposits and recurring appointments are not here: each is a product of
// its own, and a site that needs one needs a booking system, not a page.
//
// # Who reads what
//
// The public site may only ever add what a visitor sent, never read it
// back (internal/public's forms say why). A booking cannot keep to that
// entirely, because offering free times means knowing the busy ones. So a
// booking is two things kept apart:
//
//	the calendar   when, for how long, which service, and a hash of the
//	               visitor's token. No name, no address. The site reads and
//	               writes it.
//	the details    who: name, email, telephone, a note. Written once by the
//	               site, read only by the admin, erased after the
//	               appointment.
//
// A flaw in the internet-facing process can therefore learn that somebody
// booked a haircut at ten on Tuesday, and not who.
package booking

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	_ "time/tzdata" // a site's zone resolves the same on every host
	"unicode/utf8"
)

// Setup is how a site takes bookings.
type Setup struct {
	// Zone is the IANA time zone the hours are in, such as Europe/London.
	Zone string `json:"zone"`
	// Week is the hours each day: "mon" to "sun", each a list of spans.
	// A day with none is closed.
	Week map[string][]Span `json:"week"`
	// Closed are dates, YYYY-MM-DD, with no bookings at all.
	Closed []string `json:"closed,omitempty"`
	// NoticeHours is how soon a booking may start: a time less than this
	// many hours away is not offered.
	NoticeHours int `json:"notice_hours,omitempty"`
	// AheadDays is how far ahead bookings are taken; 0 is DefaultAhead.
	AheadDays int `json:"ahead_days,omitempty"`
	// KeepDays is how long after the appointment who booked it is kept;
	// 0 is DefaultKeep.
	KeepDays int `json:"keep_days,omitempty"`
	// Services are what can be booked.
	Services []Service `json:"services"`
	// Paused takes no new bookings; those made stand.
	Paused bool `json:"paused,omitempty"`
	// Feed is the hash of the owner's calendar feed token, empty for no
	// feed. See FeedHash.
	Feed string `json:"feed,omitempty"`
}

// Service is one thing that can be booked.
type Service struct {
	// Name is how it is addressed: lower case letters, digits and dashes.
	Name  string `json:"name"`
	Title string `json:"title"`
	// Minutes is how long it takes; Buffer is how long to leave after it
	// before the next.
	Minutes int `json:"minutes"`
	Buffer  int `json:"buffer,omitempty"`
	// Price is shown, never charged: paying is the provider's checkout's.
	Price string `json:"price,omitempty"`
	About string `json:"about,omitempty"`
}

// Bounds.
const (
	DefaultAhead = 60
	MaxAhead     = 365
	DefaultKeep  = 30
	MaxKeep      = 3650
	MaxServices  = 20
	MaxSpans     = 4
	MaxClosed    = 400
	MaxMinutes   = 8 * 60
)

var (
	reName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	reDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reTime = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
	// Days are the week's keys, Monday first as people write a week.
	Days = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
)

// Span is a stretch of open hours, written "09:00-12:30".
type Span struct{ From, To string }

func (s Span) String() string { return s.From + "-" + s.To }

// MarshalJSON writes a span as people write one.
func (s Span) MarshalJSON() ([]byte, error) { return []byte(`"` + s.String() + `"`), nil }

// UnmarshalJSON reads "09:00-12:30".
func (s *Span) UnmarshalJSON(b []byte) error {
	v := strings.Trim(string(b), `"`)
	sp, err := ParseSpan(v)
	if err != nil {
		return err
	}
	*s = sp
	return nil
}

// ParseSpan reads "09:00-12:30".
func ParseSpan(v string) (Span, error) {
	from, to, ok := strings.Cut(strings.TrimSpace(v), "-")
	from, to = strings.TrimSpace(from), strings.TrimSpace(to)
	if !ok || !reTime.MatchString(from) || !reTime.MatchString(to) {
		return Span{}, fmt.Errorf("%q is not a span of hours, such as 09:00-12:30", v)
	}
	if minutesOf(to) <= minutesOf(from) {
		return Span{}, fmt.Errorf("%q ends before it starts", v)
	}
	return Span{From: from, To: to}, nil
}

func minutesOf(hhmm string) int {
	var h, m int
	_, _ = fmt.Sscanf(hhmm, "%d:%d", &h, &m)
	return h*60 + m
}

// Location is the setup's time zone.
func (s *Setup) Location() (*time.Location, error) {
	if strings.TrimSpace(s.Zone) == "" {
		return nil, errors.New("say which time zone the hours are in, such as Europe/London")
	}
	loc, err := time.LoadLocation(s.Zone)
	if err != nil {
		return nil, fmt.Errorf("%q is not a time zone; use a name such as Europe/London", s.Zone)
	}
	return loc, nil
}

// Ahead is how many days ahead bookings are taken.
func (s *Setup) Ahead() int {
	if s.AheadDays <= 0 {
		return DefaultAhead
	}
	return s.AheadDays
}

// Keep is how long after an appointment who booked it is kept.
func (s *Setup) Keep() time.Duration {
	days := s.KeepDays
	if days <= 0 {
		days = DefaultKeep
	}
	return time.Duration(days) * 24 * time.Hour
}

// Service finds a service by name.
func (s *Setup) Service(name string) (Service, bool) {
	for _, sv := range s.Services {
		if sv.Name == name {
			return sv, true
		}
	}
	return Service{}, false
}

// Validate says everything wrong with a setup at once.
func (s *Setup) Validate() error {
	var errs []string
	bad := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if _, err := s.Location(); err != nil {
		bad("%v", err)
	}
	open := false
	for day, spans := range s.Week {
		if !known(day) {
			bad("%q is not a day; use mon, tue, wed, thu, fri, sat or sun", day)
			continue
		}
		if len(spans) > MaxSpans {
			bad("%s has %d spans; at most %d", day, len(spans), MaxSpans)
		}
		sorted := append([]Span(nil), spans...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].From < sorted[j].From })
		for i, sp := range sorted {
			if _, err := ParseSpan(sp.String()); err != nil {
				bad("%s: %v", day, err)
			}
			if i > 0 && minutesOf(sp.From) < minutesOf(sorted[i-1].To) {
				bad("%s: %s overlaps %s", day, sp, sorted[i-1])
			}
		}
		if len(spans) > 0 {
			open = true
		}
	}
	if !open && len(s.Services) > 0 {
		bad("no day has opening hours, so nothing could be booked")
	}
	if len(s.Closed) > MaxClosed {
		bad("%d closed dates; at most %d", len(s.Closed), MaxClosed)
	}
	for _, d := range s.Closed {
		if _, err := time.Parse("2006-01-02", d); err != nil || !reDate.MatchString(d) {
			bad("%q is not a date, such as 2026-12-25", d)
		}
	}
	if s.NoticeHours < 0 || s.NoticeHours > 24*30 {
		bad("notice is 0 to %d hours", 24*30)
	}
	if s.AheadDays < 0 || s.AheadDays > MaxAhead {
		bad("bookings are taken up to %d days ahead", MaxAhead)
	}
	if s.KeepDays < 0 || s.KeepDays > MaxKeep {
		bad("who booked is kept for at most %d days", MaxKeep)
	}
	if len(s.Services) > MaxServices {
		bad("%d services; at most %d", len(s.Services), MaxServices)
	}
	seen := map[string]bool{}
	for _, sv := range s.Services {
		if !reName.MatchString(sv.Name) {
			bad("%q is not a service name: lower case letters, digits and dashes", sv.Name)
		}
		if seen[sv.Name] {
			bad("two services are called %s", sv.Name)
		}
		seen[sv.Name] = true
		if t := strings.TrimSpace(sv.Title); t == "" || utf8.RuneCountInString(t) > 80 {
			bad("service %s needs a title of at most 80 characters", sv.Name)
		}
		if sv.Minutes < 5 || sv.Minutes > MaxMinutes || sv.Minutes%5 != 0 {
			bad("service %s takes %d minutes; it takes 5 to %d, in fives", sv.Name, sv.Minutes, MaxMinutes)
		}
		if sv.Buffer < 0 || sv.Buffer > 240 || sv.Buffer%5 != 0 {
			bad("service %s leaves %d minutes after it; 0 to 240, in fives", sv.Name, sv.Buffer)
		}
		if utf8.RuneCountInString(sv.Price) > 40 || utf8.RuneCountInString(sv.About) > 300 {
			bad("service %s: a price is at most 40 characters and a description 300", sv.Name)
		}
		for _, v := range []string{sv.Title, sv.Price, sv.About} {
			if strings.ContainsAny(v, "\r\n\x00") {
				bad("service %s: one line each, please", sv.Name)
			}
		}
	}
	if s.Feed != "" && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s.Feed) {
		bad("the feed is a hash, set by quilzo booking feed")
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("the bookings setup is not usable:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

func known(day string) bool {
	for _, d := range Days {
		if d == day {
			return true
		}
	}
	return false
}

// dayKey is the week's key for a date.
func dayKey(t time.Time) string { return Days[(int(t.Weekday())+6)%7] }

// Busy is one booking as the calendar holds it: when, for how long, and
// nothing about who.
type Busy struct {
	ID      string    `json:"id"`
	Service string    `json:"service"`
	Start   time.Time `json:"start"`
	// Minutes is the appointment; Until is when the next may start, the
	// buffer included.
	Minutes int       `json:"minutes"`
	Until   time.Time `json:"until"`
	// Token is the hash of what the visitor holds to see and cancel it.
	Token string `json:"token"`
	// Cancelled is when it was cancelled, and By whether by the visitor or
	// the site.
	Cancelled *time.Time `json:"cancelled,omitempty"`
	By        string     `json:"by,omitempty"`
}

// End is when the appointment itself ends.
func (b Busy) End() time.Time { return b.Start.Add(time.Duration(b.Minutes) * time.Minute) }

// Live is a booking that stands.
func (b Busy) Live() bool { return b.Cancelled == nil }

// Day is one date's free times.
type Day struct {
	Date  string // YYYY-MM-DD in the site's zone
	Label string // Tuesday 3 November
	Slots []Slot
}

// Slot is one free start time.
type Slot struct {
	Start time.Time
	Label string // 10:30
}

// Free is the times a service can start, day by day, from now to the end
// of what is booked ahead: within the hours, not on a closed date, not
// sooner than the notice, and clear of every standing booking and its
// buffer, whichever service it was for. Days with nothing free are left
// out.
func Free(s *Setup, svc Service, busy []Busy, now time.Time) ([]Day, error) {
	loc, err := s.Location()
	if err != nil {
		return nil, err
	}
	closed := map[string]bool{}
	for _, d := range s.Closed {
		closed[d] = true
	}
	earliest := now.Add(time.Duration(s.NoticeHours) * time.Hour)
	local := now.In(loc)
	first := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	need := time.Duration(svc.Minutes+svc.Buffer) * time.Minute
	var days []Day
	for i := 0; i <= s.Ahead(); i++ {
		date := first.AddDate(0, 0, i)
		key := date.Format("2006-01-02")
		if closed[key] {
			continue
		}
		var slots []Slot
		for _, sp := range s.Week[dayKey(date)] {
			// By the clock on the wall, not by adding durations, so a day
			// the clocks change still offers ten o'clock at ten.
			for m := minutesOf(sp.From); m+svc.Minutes <= minutesOf(sp.To); m += svc.Minutes + svc.Buffer {
				start := time.Date(date.Year(), date.Month(), date.Day(), m/60, m%60, 0, 0, loc)
				// A time the clocks skipped is not offered: 01:30 on the
				// night they go forward does not exist.
				if start.Hour()*60+start.Minute() != m {
					continue
				}
				if start.Before(earliest) || clash(busy, start, start.Add(need)) {
					continue
				}
				slots = append(slots, Slot{Start: start, Label: start.Format("15:04")})
			}
		}
		if len(slots) > 0 {
			days = append(days, Day{Date: key, Label: date.Format("Monday 2 January"), Slots: slots})
		}
	}
	return days, nil
}

// clash says whether [from, to) meets a standing booking, buffers included
// on both sides.
func clash(busy []Busy, from, to time.Time) bool {
	for _, b := range busy {
		if b.Live() && from.Before(b.Until) && b.Start.Before(to) {
			return true
		}
	}
	return false
}

// Offered says whether a start time is one Free offers for a service now:
// what a booking is checked against at the moment it is made, so a time
// that was free when the page was read and is not any more is refused.
func Offered(s *Setup, svc Service, busy []Busy, now, start time.Time) bool {
	days, err := Free(s, svc, busy, now)
	if err != nil {
		return false
	}
	for _, d := range days {
		for _, sl := range d.Slots {
			if sl.Start.Equal(start) {
				return true
			}
		}
	}
	return false
}
