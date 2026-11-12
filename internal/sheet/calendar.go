// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sheet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/ical"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/schema"
)

// A calendar brought into the events collection: each event, and each time
// a repeating one happens, as a row of the ready-made event type
// (cmd/quilzo/eventscmd.go), on the site's own clock.
//
// A calendar is often somebody's own as well as the venue's, so an event
// it marks private or confidential is left out: a site's events are
// public once published, and the file said that one was not.

// CalendarOptions says how a calendar is read into events.
type CalendarOptions struct {
	// Collection is the events collection, which names each record's id.
	Collection string
	// Type is its type: only the fields it declares are filled.
	Type *schema.Type
	// Zone is the site's clock, which an event's date and time are on.
	Zone *time.Location
	// Now is when it is brought in. A repeating event is each time it
	// happens from a year before to a year after.
	Now time.Time
}

// MaxRepeats is how many times of one repeating event are brought.
const MaxRepeats = 400

// The fields a calendar fills, in the ready-made event type; an update
// from a calendar sets each, or clears it when the calendar has nothing.
var calendarFields = []string{"title", "date", "time", "end_date", "until", "location", "online", "summary",
	"tickets", "status"}

// FromCalendar is a calendar's events as rows, and what was read
// differently from how it was written.
func FromCalendar(body []byte, opts CalendarOptions) ([]Row, []string, error) {
	zone := opts.Zone
	if zone == nil {
		zone = time.UTC
	}
	cal, err := ical.Parse(body, zone)
	if err != nil {
		return nil, nil, err
	}
	notes := cal.Notes
	occ, more := cal.Occurrences(opts.Now.AddDate(-1, 0, 0), opts.Now.AddDate(1, 0, 0), MaxRepeats)
	notes = append(notes, more...)
	declared := map[string]bool{}
	if opts.Type != nil {
		for _, f := range opts.Type.Fields {
			declared[f.Name] = true
		}
	}
	var rows []Row
	index := map[string]int{}
	private, untitled := 0, 0
	for i, o := range occ {
		if o.Class == "PRIVATE" || o.Class == "CONFIDENTIAL" {
			private++
			continue
		}
		title := strings.Join(strings.Fields(o.Summary), " ")
		if title == "" {
			untitled++
			continue
		}
		if len(rows) == MaxRows {
			return nil, nil, fmt.Errorf("it has more than %d events: bring it in parts", MaxRows)
		}
		f := eventFields(o, title, zone)
		row := Row{Line: i + 1, Where: fmt.Sprintf("%q on %s", plaintext.Clip(title, maxQuoted, "…"), f["date"]),
			ID: occurrenceID(opts.Collection, o), Fields: map[string]any{}}
		for _, k := range calendarFields {
			if !declared[k] {
				continue
			}
			if v, ok := f[k]; ok && v != "" {
				row.Fields[k] = v
			} else {
				row.Clear = append(row.Clear, k)
			}
		}
		// Each time of a repeating event has its own page, at a link with
		// its date in it.
		if o.Repeats && declared["slug"] {
			row.Suggest = map[string]any{"slug": Slug(title) + "-" + f["date"]}
		}
		// The same event twice in one file is one event, as it was last
		// written.
		if at, dup := index[row.ID]; dup {
			rows[at] = row
			continue
		}
		index[row.ID] = len(rows)
		rows = append(rows, row)
	}
	if private > 0 {
		notes = append(notes, fmt.Sprintf("%d event(s) the calendar marks private were left out", private))
	}
	if untitled > 0 {
		notes = append(notes, fmt.Sprintf("%d event(s) with no title were left out", untitled))
	}
	if len(rows) == 0 {
		return nil, notes, fmt.Errorf("it has no events to bring")
	}
	return rows, notes, nil
}

// occurrenceID is the record an event, or one time of a repeating one,
// always is: a calendar brought in again changes its events rather than
// adding them twice.
func occurrenceID(coll string, o ical.Occurrence) string {
	key := o.UID
	if key == "" {
		key = o.Summary + "\x00" + o.Start.UTC().Format(time.RFC3339)
	}
	sum := sha256.Sum256([]byte("ical\x00" + coll + "\x00" + key + "\x00" + o.Key))
	return hex.EncodeToString(sum[:16])
}

var meetingHosts = []string{"zoom.us", "meet.google.com", "teams.microsoft.com", "teams.live.com", "whereby.com",
	"webex.com", "gotomeeting.com", "meet.jit.si", "chime.aws"}

// eventFields is one occurrence as the event type's fields, as text.
func eventFields(o ical.Occurrence, title string, zone *time.Location) map[string]string {
	f := map[string]string{"title": title}
	if o.AllDay {
		f["date"] = o.Start.Format("2006-01-02")
		if o.HasEnd {
			if last := o.End.AddDate(0, 0, -1); last.After(o.Start) {
				f["end_date"] = last.Format("2006-01-02")
			}
		}
	} else {
		start := o.Start.In(zone)
		f["date"], f["time"] = start.Format("2006-01-02"), start.Format("15:04")
		if o.HasEnd && o.End.After(o.Start) {
			end := o.End.In(zone)
			f["until"] = end.Format("15:04")
			// Past midnight and before it began is the night it began, as
			// the site reads a time it finishes before it starts.
			nextDay := start.AddDate(0, 0, 1).Format("2006-01-02")
			sameNight := end.Format("2006-01-02") == nextDay && end.Format("15:04") <= start.Format("15:04")
			if end.Format("2006-01-02") != f["date"] && !sameNight {
				f["end_date"] = end.Format("2006-01-02")
			}
		}
	}
	loc := strings.TrimSpace(o.Location)
	online := web(o.Conference)
	if u := web(loc); u != "" {
		// A location that is an address on the web is where to join.
		if online == "" {
			online = u
		}
		loc = ""
	}
	tickets := web(o.URL)
	if tickets != "" && online == "" && meeting(tickets) {
		online, tickets = tickets, ""
	}
	f["location"], f["online"], f["tickets"] = oneLine(loc), online, tickets
	f["summary"] = plainDescription(o.Description)
	if o.Status == "CANCELLED" {
		f["status"] = "cancelled"
	}
	return f
}

// web is a value as an http or https address, or "".
func web(s string) string {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(s, " \n") {
		return ""
	}
	return s
}

func meeting(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, m := range meetingHosts {
		if h == m || strings.HasSuffix(h, "."+m) {
			return true
		}
	}
	return false
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return plaintext.Clip(s, schema.MaxTextLen, "")
}

var (
	reBreak = regexp.MustCompile(`(?i)<br\s*/?>|</p>|</div>|</li>`)
	reTag   = regexp.MustCompile(`<[^>]*>`)
)

// plainDescription is a description as words: Google Calendar writes some
// as HTML.
func plainDescription(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "<") && strings.Contains(s, ">") {
		s = reBreak.ReplaceAllString(s, "\n")
		s = reTag.ReplaceAllString(s, "")
		s = html.UnescapeString(s)
	}
	var lines []string
	blank := false
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			if !blank && len(lines) > 0 {
				lines = append(lines, "")
			}
			blank = true
			continue
		}
		lines = append(lines, l)
		blank = false
	}
	out := strings.TrimSpace(strings.Join(lines, "\n"))
	if r := []rune(out); len(r) > schema.MaxLongTextLen {
		out = string(r[:schema.MaxLongTextLen])
	}
	return out
}
