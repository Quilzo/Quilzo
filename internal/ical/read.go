// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ical

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // a calendar's zones resolve the same on every host
	"unicode/utf8"
)

// Reading a calendar file, for bringing a site's events from wherever they
// were kept: Google Calendar, Outlook, Apple Calendar, Eventbrite, Meetup,
// or anything else that writes RFC 5545.
//
// What is read is what a page of events shows: what each one is called,
// when it starts and ends, where, and whether it is still on. A repeating
// event is each time it happens (rrule.go). Alarms, attendees and the
// organiser are not read: they are about the people in a calendar, not the
// event, and a site has no use for them.

// MaxBytes bounds a calendar file read whole.
const MaxBytes = 16 << 20

// MaxEvents bounds the events one file holds.
const MaxEvents = 50000

// maxDates bounds the dates one event lists to add (RDATE) or leave out
// (EXDATE), and maxListed those of all a file's events together. Each list
// is counted, and a file refused, before any of the list is read, because
// one RDATE of fifteen million commas was once split into as many strings
// and each tried as a time: seven seconds and 2.7 GB for a file under
// MaxBytes. The file has a bound of its own because many events, each
// listing fewer than maxDates, were together nearly as slow as one listing
// them all. Neither touches a real calendar: ten thousand dates are every
// day for twenty-seven years, and a million dates written as times fill
// nearly all of MaxBytes, leaving no room for much else.
const (
	maxDates  = 10000
	maxListed = 1000000
)

// Read is a calendar file, read.
type Read struct {
	// Name is what the calendar calls itself, when it says.
	Name   string
	Events []VEvent
	// Notes are what was read differently from how it was written.
	Notes []string
}

// VEvent is one event as the file says it.
type VEvent struct {
	UID         string
	Summary     string
	Description string
	Location    string
	URL         string
	// Conference is where to join, for an event held online.
	Conference string
	// Class is PUBLIC, PRIVATE or CONFIDENTIAL; empty is public.
	Class string
	// Status is CONFIRMED, TENTATIVE or CANCELLED; empty is confirmed.
	Status string
	// Start and End are in the event's own zone; an all-day event's are
	// dates, at midnight UTC, and End is the day after the last.
	Start, End time.Time
	AllDay     bool
	// HasEnd says whether the file gave an end or a length.
	HasEnd bool
	// RRule is the rule it repeats by, as written.
	RRule   string
	RDates  []time.Time
	ExDates []time.Time
	// RecurrenceID, on an event changing one time of a repeating one, is
	// the time it changes.
	RecurrenceID time.Time

	// length is a DURATION, which becomes End once the start is known.
	length    time.Duration
	hasLength bool
}

// Parse reads a calendar file. Floating times, which name no zone, are
// read in floating, which is the zone of the site they are brought to.
func Parse(body []byte, floating *time.Location) (*Read, error) {
	if len(body) > MaxBytes {
		return nil, fmt.Errorf("larger than %d MB", MaxBytes>>20)
	}
	if floating == nil {
		floating = time.UTC
	}
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(body) {
		body = []byte(strings.ToValidUTF8(string(body), "�"))
	}
	lines := unfold(string(body))
	if len(lines) == 0 || !strings.EqualFold(strings.TrimSpace(lines[0]), "BEGIN:VCALENDAR") {
		return nil, errors.New("not a calendar file: it does not begin BEGIN:VCALENDAR")
	}
	cal := &Read{}
	zones := newZones(floating)
	// The first pass finds each zone the file defines, which events named
	// before it in the file may use.
	var stack []string
	var tzid string
	for _, raw := range lines {
		p, ok := parseLine(raw)
		if !ok {
			continue
		}
		switch p.name {
		case "BEGIN":
			stack = append(stack, strings.ToUpper(p.value))
		case "END":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case "TZID":
			if top(stack) == "VTIMEZONE" {
				tzid = p.value
			}
		case "TZOFFSETTO":
			if top(stack) == "STANDARD" && tzid != "" {
				zones.standard[tzid] = p.value
			}
		}
	}

	stack = stack[:0]
	var ev *VEvent
	bad, listed, evListed := 0, 0, 0
	for _, raw := range lines {
		p, ok := parseLine(raw)
		if !ok {
			continue
		}
		switch p.name {
		case "BEGIN":
			stack = append(stack, strings.ToUpper(p.value))
			if top(stack) == "VEVENT" {
				if len(cal.Events) >= MaxEvents {
					return nil, fmt.Errorf("more than %d events", MaxEvents)
				}
				ev, evListed = &VEvent{}, 0
			}
			continue
		case "END":
			if top(stack) == "VEVENT" && ev != nil {
				if ev.Start.IsZero() {
					bad++
				} else {
					finish(ev)
					cal.Events = append(cal.Events, *ev)
				}
				ev = nil
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top(stack) == "VCALENDAR" && p.name == "X-WR-CALNAME" {
			cal.Name = unescape(p.value)
		}
		// Only the event's own lines: an alarm inside it has a description
		// of its own, which is not the event's.
		if ev == nil || top(stack) != "VEVENT" {
			continue
		}
		switch p.name {
		case "UID":
			ev.UID = strings.TrimSpace(p.value)
		case "SUMMARY":
			ev.Summary = unescape(p.value)
		case "DESCRIPTION":
			ev.Description = unescape(p.value)
		case "LOCATION":
			ev.Location = unescape(p.value)
		case "URL":
			ev.URL = strings.TrimSpace(p.value)
		case "CONFERENCE", "X-GOOGLE-CONFERENCE", "X-MICROSOFT-SKYPETEAMSMEETINGURL":
			if ev.Conference == "" {
				ev.Conference = strings.TrimSpace(p.value)
			}
		case "CLASS":
			ev.Class = strings.ToUpper(strings.TrimSpace(p.value))
		case "STATUS":
			ev.Status = strings.ToUpper(strings.TrimSpace(p.value))
		case "DTSTART":
			t, allDay, err := zones.when(p)
			if err == nil {
				ev.Start, ev.AllDay = t, allDay
			}
		case "DTEND":
			if t, _, err := zones.when(p); err == nil {
				ev.End, ev.HasEnd = t, true
			}
		case "DURATION":
			if d, err := duration(p.value); err == nil && d >= 0 {
				// Applied once the start is known, which may come later.
				ev.length, ev.hasLength = d, true
			}
		case "RRULE":
			ev.RRule = strings.TrimSpace(p.value)
		case "RDATE", "EXDATE":
			// Every piece counts, read or not, since a list of nothing but
			// commas holds no dates and was the most work of all.
			n := strings.Count(p.value, ",") + 1
			evListed, listed = evListed+n, listed+n
			if evListed > maxDates {
				return nil, fmt.Errorf("an event lists more than %d dates to add or leave out", maxDates)
			}
			if listed > maxListed {
				return nil, fmt.Errorf("more than %d dates to add or leave out", maxListed)
			}
			if p.name == "RDATE" {
				ev.RDates = append(ev.RDates, zones.list(p)...)
			} else {
				ev.ExDates = append(ev.ExDates, zones.list(p)...)
			}
		case "RECURRENCE-ID":
			if t, _, err := zones.when(p); err == nil {
				ev.RecurrenceID = t
			}
		}
	}
	if bad > 0 {
		cal.Notes = append(cal.Notes, fmt.Sprintf("%d event(s) with no start were left out", bad))
	}
	cal.Notes = append(cal.Notes, zones.notes()...)
	return cal, nil
}

// finish settles an event's end: a length becomes an end, and an end
// before the start is none.
func finish(ev *VEvent) {
	if !ev.HasEnd && ev.hasLength {
		ev.End, ev.HasEnd = ev.Start.Add(ev.length), true
	}
	if ev.HasEnd && ev.End.Before(ev.Start) {
		ev.End, ev.HasEnd = time.Time{}, false
	}
	if ev.AllDay && !ev.HasEnd {
		ev.End, ev.HasEnd = ev.Start.AddDate(0, 0, 1), true
	}
}

func top(stack []string) string {
	if len(stack) == 0 {
		return ""
	}
	return stack[len(stack)-1]
}

// unfold joins continued lines: a line break followed by a space or a tab
// is not there. Both CRLF and a bare LF end a line, as files in the wild
// use either.
func unfold(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l != "" && (l[0] == ' ' || l[0] == '\t') && len(out) > 0 {
			out[len(out)-1] += l[1:]
			continue
		}
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// prop is one content line: NAME;PARAM=VALUE:value.
type prop struct {
	name   string
	params map[string]string
	value  string
}

func parseLine(l string) (prop, bool) {
	p := prop{params: map[string]string{}}
	quoted := false
	colon := -1
	for i := 0; i < len(l); i++ {
		switch l[i] {
		case '"':
			quoted = !quoted
		case ':':
			if !quoted {
				colon = i
			}
		}
		if colon >= 0 {
			break
		}
	}
	if colon < 0 {
		return p, false
	}
	head, value := l[:colon], l[colon+1:]
	parts := splitUnquoted(head, ';')
	p.name = strings.ToUpper(strings.TrimSpace(parts[0]))
	for _, kv := range parts[1:] {
		if k, v, ok := strings.Cut(kv, "="); ok {
			p.params[strings.ToUpper(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	p.value = value
	return p, p.name != ""
}

func splitUnquoted(s string, sep byte) []string {
	var out []string
	quoted := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '"':
			quoted = !quoted
		case s[i] == sep && !quoted:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// unescape is Text, undone.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return strings.TrimSpace(s)
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n', 'N':
			b.WriteByte('\n')
		default:
			b.WriteByte(s[i])
		}
	}
	return strings.TrimSpace(b.String())
}

// duration reads a length: P1W, P1DT2H, PT90M.
func duration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimLeft(s, "+-")
	if !strings.HasPrefix(s, "P") || len(s) < 3 {
		return 0, fmt.Errorf("%q is not a length", s)
	}
	var d time.Duration
	inTime := false
	n := 0
	digits := false
	for _, r := range s[1:] {
		switch {
		case r >= '0' && r <= '9':
			n = n*10 + int(r-'0')
			digits = true
			if n > 1e6 {
				return 0, fmt.Errorf("%q is too long a length", s)
			}
			continue
		case r == 'T':
			inTime = true
			continue
		}
		if !digits {
			return 0, fmt.Errorf("%q is not a length", s)
		}
		unit := map[rune]time.Duration{'W': 7 * 24 * time.Hour, 'D': 24 * time.Hour}
		if inTime {
			unit = map[rune]time.Duration{'H': time.Hour, 'M': time.Minute, 'S': time.Second}
		}
		u, ok := unit[r]
		if !ok {
			return 0, fmt.Errorf("%q is not a length", s)
		}
		d += time.Duration(n) * u
		n, digits = 0, false
	}
	if neg {
		d = -d
	}
	return d, nil
}

// -- Times and their zones ------------------------------------------------------

// zones resolves the zones a file names, remembering which it could not.
type zones struct {
	floating *time.Location
	standard map[string]string // TZID → its standard offset, from VTIMEZONE
	cache    map[string]*time.Location
	fixed    map[string]bool
	unknown  map[string]bool
}

func newZones(floating *time.Location) *zones {
	return &zones{floating: floating, standard: map[string]string{}, cache: map[string]*time.Location{},
		fixed: map[string]bool{}, unknown: map[string]bool{}}
}

func (z *zones) notes() []string {
	var out []string
	for id := range z.fixed {
		out = append(out, fmt.Sprintf("times in %q were read at its standard offset, without summer time", id))
	}
	for id := range z.unknown {
		out = append(out, fmt.Sprintf("times in %q, a zone this does not know, were read as the site's own", id))
	}
	return out
}

// zone is the location a TZID names: an IANA name, which nearly every
// calendar writes, possibly behind a prefix; a Windows name, which Outlook
// writes; or the standard offset the file itself gives for it.
func (z *zones) zone(id string) *time.Location {
	id = strings.TrimSpace(id)
	if loc, ok := z.cache[id]; ok {
		return loc
	}
	loc := lookupZone(id)
	if loc == nil {
		if off, ok := offset(z.standard[id]); ok {
			loc = time.FixedZone(id, off)
			z.fixed[id] = true
		} else {
			loc = z.floating
			z.unknown[id] = true
		}
	}
	z.cache[id] = loc
	return loc
}

func lookupZone(id string) *time.Location {
	if id == "" {
		return nil
	}
	if w, ok := windowsZones[id]; ok {
		id = w
	}
	if loc, err := time.LoadLocation(id); err == nil && id != "Local" {
		return loc
	}
	// "/mozilla.org/20050126_1/Europe/London" and the like: the name is
	// the end of it.
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for n := 3; n >= 1; n-- {
		if len(parts) > n {
			if loc, err := time.LoadLocation(strings.Join(parts[len(parts)-n:], "/")); err == nil {
				return loc
			}
		}
	}
	return nil
}

// offset reads +0100 or -0530 as seconds east of UTC.
func offset(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if len(s) != 5 && len(s) != 7 || (s[0] != '+' && s[0] != '-') {
		return 0, false
	}
	h, err1 := strconv.Atoi(s[1:3])
	m, err2 := strconv.Atoi(s[3:5])
	if err1 != nil || err2 != nil || h > 14 || m > 59 {
		return 0, false
	}
	secs := h*3600 + m*60
	if s[0] == '-' {
		secs = -secs
	}
	return secs, true
}

// when reads a DTSTART, DTEND, RECURRENCE-ID or the like: a date, which is
// all day; a time in UTC; a time in a named zone; or a floating time.
func (z *zones) when(p prop) (time.Time, bool, error) {
	v := strings.TrimSpace(p.value)
	if strings.EqualFold(p.params["VALUE"], "DATE") || len(v) == 8 {
		t, err := time.Parse("20060102", v)
		return t, true, err
	}
	if strings.EqualFold(p.params["VALUE"], "PERIOD") {
		v, _, _ = strings.Cut(v, "/")
	}
	if strings.HasSuffix(v, "Z") || strings.HasSuffix(v, "z") {
		t, err := time.Parse("20060102T150405", v[:len(v)-1])
		return t.UTC(), false, err
	}
	loc := z.floating
	if id := p.params["TZID"]; id != "" {
		loc = z.zone(id)
	}
	t, err := time.ParseInLocation("20060102T150405", v, loc)
	if err != nil {
		// Some writers leave out the seconds.
		t, err = time.ParseInLocation("20060102T1504", v, loc)
	}
	return t, false, err
}

// list reads an RDATE or EXDATE, which may hold several, comma separated.
// The commas are walked one at a time rather than split at, because a
// split makes a string of every piece before the first is read.
func (z *zones) list(p prop) []time.Time {
	var out []time.Time
	for rest, more := p.value, true; more; {
		var v string
		v, rest, more = strings.Cut(rest, ",")
		q := prop{name: p.name, params: p.params, value: v}
		if t, _, err := z.when(q); err == nil {
			out = append(out, t)
		}
	}
	return out
}

// windowsZones are the zone names Outlook and Exchange write, as the IANA
// names everything else uses (Unicode CLDR's windowsZones, for the world).
var windowsZones = map[string]string{
	"Dateline Standard Time":          "Etc/GMT+12",
	"UTC-11":                          "Etc/GMT+11",
	"Hawaiian Standard Time":          "Pacific/Honolulu",
	"Alaskan Standard Time":           "America/Anchorage",
	"Pacific Standard Time (Mexico)":  "America/Tijuana",
	"Pacific Standard Time":           "America/Los_Angeles",
	"US Mountain Standard Time":       "America/Phoenix",
	"Mountain Standard Time (Mexico)": "America/Mazatlan",
	"Mountain Standard Time":          "America/Denver",
	"Central America Standard Time":   "America/Guatemala",
	"Central Standard Time":           "America/Chicago",
	"Central Standard Time (Mexico)":  "America/Mexico_City",
	"Canada Central Standard Time":    "America/Regina",
	"SA Pacific Standard Time":        "America/Bogota",
	"Eastern Standard Time":           "America/New_York",
	"Eastern Standard Time (Mexico)":  "America/Cancun",
	"US Eastern Standard Time":        "America/Indiana/Indianapolis",
	"Venezuela Standard Time":         "America/Caracas",
	"Atlantic Standard Time":          "America/Halifax",
	"SA Western Standard Time":        "America/La_Paz",
	"Pacific SA Standard Time":        "America/Santiago",
	"Newfoundland Standard Time":      "America/St_Johns",
	"E. South America Standard Time":  "America/Sao_Paulo",
	"Argentina Standard Time":         "America/Argentina/Buenos_Aires",
	"SA Eastern Standard Time":        "America/Cayenne",
	"Greenland Standard Time":         "America/Nuuk",
	"Montevideo Standard Time":        "America/Montevideo",
	"UTC-02":                          "Etc/GMT+2",
	"Azores Standard Time":            "Atlantic/Azores",
	"Cape Verde Standard Time":        "Atlantic/Cape_Verde",
	"UTC":                             "Etc/UTC",
	"Coordinated Universal Time":      "Etc/UTC",
	"GMT Standard Time":               "Europe/London",
	"Greenwich Standard Time":         "Atlantic/Reykjavik",
	"W. Europe Standard Time":         "Europe/Berlin",
	"Central Europe Standard Time":    "Europe/Budapest",
	"Romance Standard Time":           "Europe/Paris",
	"Central European Standard Time":  "Europe/Warsaw",
	"W. Central Africa Standard Time": "Africa/Lagos",
	"GTB Standard Time":               "Europe/Bucharest",
	"Middle East Standard Time":       "Asia/Beirut",
	"Egypt Standard Time":             "Africa/Cairo",
	"E. Europe Standard Time":         "Europe/Chisinau",
	"South Africa Standard Time":      "Africa/Johannesburg",
	"FLE Standard Time":               "Europe/Kyiv",
	"Israel Standard Time":            "Asia/Jerusalem",
	"Arabic Standard Time":            "Asia/Baghdad",
	"Turkey Standard Time":            "Europe/Istanbul",
	"Arab Standard Time":              "Asia/Riyadh",
	"Russian Standard Time":           "Europe/Moscow",
	"E. Africa Standard Time":         "Africa/Nairobi",
	"Iran Standard Time":              "Asia/Tehran",
	"Arabian Standard Time":           "Asia/Dubai",
	"Azerbaijan Standard Time":        "Asia/Baku",
	"Afghanistan Standard Time":       "Asia/Kabul",
	"Pakistan Standard Time":          "Asia/Karachi",
	"West Asia Standard Time":         "Asia/Tashkent",
	"India Standard Time":             "Asia/Kolkata",
	"Sri Lanka Standard Time":         "Asia/Colombo",
	"Nepal Standard Time":             "Asia/Kathmandu",
	"Central Asia Standard Time":      "Asia/Almaty",
	"Bangladesh Standard Time":        "Asia/Dhaka",
	"Myanmar Standard Time":           "Asia/Yangon",
	"SE Asia Standard Time":           "Asia/Bangkok",
	"North Asia Standard Time":        "Asia/Krasnoyarsk",
	"China Standard Time":             "Asia/Shanghai",
	"Singapore Standard Time":         "Asia/Singapore",
	"W. Australia Standard Time":      "Australia/Perth",
	"Taipei Standard Time":            "Asia/Taipei",
	"Tokyo Standard Time":             "Asia/Tokyo",
	"Korea Standard Time":             "Asia/Seoul",
	"Cen. Australia Standard Time":    "Australia/Adelaide",
	"AUS Central Standard Time":       "Australia/Darwin",
	"E. Australia Standard Time":      "Australia/Brisbane",
	"AUS Eastern Standard Time":       "Australia/Sydney",
	"West Pacific Standard Time":      "Pacific/Port_Moresby",
	"Tasmania Standard Time":          "Australia/Hobart",
	"New Zealand Standard Time":       "Pacific/Auckland",
	"Fiji Standard Time":              "Pacific/Fiji",
	"Tonga Standard Time":             "Pacific/Tongatapu",
	"Samoa Standard Time":             "Pacific/Apia",
}
