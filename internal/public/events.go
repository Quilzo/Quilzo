// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/ical"
	"github.com/quilzo/quilzo/internal/listing"
)

// The site's events.
//
// # Records that know they are events
//
// An events page was a listing like any other: the records were there and
// nothing knew they were events. So nobody could subscribe to them, a search
// engine's events and an assistant's answer could not tell when or where any
// of them was, and an event that had happened stayed on the page until
// somebody took it off.
//
// site.events names the listing whose records are the site's events, as
// site.feed names the feed's. Its fields are read by name — title, date,
// time, end_date, until, venue, location, online, summary, image, price,
// tickets and status — and
// from them come the calendar at /events.ics, one event's calendar file, the
// Event data on its page, and an events section on any page. The listing's
// own conditions say which events are shown: one keeping what is upcoming
// drops each event when it is over, by the site's clock, with nothing to
// publish.
//
// # Through the listing, like everything else
//
// Every row comes through the listing, so its field allow-list applies to the
// calendar and the structured data exactly as to the page, and an event the
// listing does not keep has no calendar entry to guess at either.

// eventStatus is what an event's status says, as a visitor reads it and as
// schema.org and a calendar say it.
var eventStatus = map[string]struct{ label, ld, cal string }{
	"cancelled":    {"Cancelled", "https://schema.org/EventCancelled", ical.Cancelled},
	"postponed":    {"Postponed", "https://schema.org/EventPostponed", ical.Tentative},
	"moved online": {"Moved online", "https://schema.org/EventMovedOnline", ical.Confirmed},
	"rescheduled":  {"Rescheduled", "https://schema.org/EventRescheduled", ical.Confirmed},
}

// eventTimes is when an event is, read from its fields on the site's clock:
// date, the day it begins; time, when on that day; end_date, its last day
// when it lasts more than one; and until, when it finishes. A date with no
// time is all day; an until before the time is past midnight.
type eventTimes struct {
	start, end time.Time
	allDay     bool
	hasEnd     bool
}

func readEventTimes(row listing.Row) (eventTimes, bool) {
	loc := listing.Zone()
	str := func(k string) string { v, _ := row[k].(string); return strings.TrimSpace(v) }
	day, err := time.ParseInLocation("2006-01-02", str("date"), loc)
	if err != nil {
		return eventTimes{}, false
	}
	last := day
	if e, err := time.ParseInLocation("2006-01-02", str("end_date"), loc); err == nil && !e.Before(day) {
		last = e
	}
	clock := func(on time.Time, hhmm string) (time.Time, bool) {
		c, err := time.Parse("15:04", hhmm)
		if err != nil {
			return time.Time{}, false
		}
		return time.Date(on.Year(), on.Month(), on.Day(), c.Hour(), c.Minute(), 0, 0, loc), true
	}
	start, timed := clock(day, str("time"))
	if !timed {
		t := eventTimes{start: day, allDay: true}
		if !last.Equal(day) {
			t.end, t.hasEnd = last, true
		}
		return t, true
	}
	t := eventTimes{start: start}
	if end, ok := clock(last, str("until")); ok {
		if !end.After(start) && last.Equal(day) {
			end = end.AddDate(0, 0, 1)
		}
		if end.After(start) {
			t.end, t.hasEnd = end, true
		}
	}
	return t, true
}

// say is when an event is, as people say it.
func (t eventTimes) say() string {
	const day = "Monday 2 January 2006"
	switch {
	case t.allDay && t.hasEnd && !t.end.Equal(t.start):
		return t.start.Format("Monday 2 January") + " to " + t.end.Format(day)
	case t.allDay:
		return t.start.Format(day)
	case !t.hasEnd:
		return t.start.Format(day + ", 15:04")
	case t.end.Format("2006-01-02") == t.start.Format("2006-01-02"):
		return t.start.Format(day+", 15:04") + "–" + t.end.Format("15:04")
	default:
		return t.start.Format(day+", 15:04") + " to " + t.end.Format("Monday 2 January, 15:04")
	}
}

// ld is a date or date and time as schema.org takes it: with the site's
// offset, so a search engine reads 19:30 as 19:30 there.
func (t eventTimes) ld(at time.Time) string {
	if t.allDay {
		return at.Format("2006-01-02")
	}
	return at.Format("2006-01-02T15:04:05-07:00")
}

// over says whether an event has finished by now, to the minute. A listing
// keeps an event until the end of its last day; an event with a time it
// finishes is over at that time, and is left out from then.
func (t eventTimes) over() bool {
	if t.allDay || !t.hasEnd {
		return false
	}
	now, err := time.ParseInLocation("2006-01-02T15:04", listing.Now(), listing.Zone())
	return err == nil && !t.end.After(now)
}

// eventsSection says whether a page has an events section.
func eventsSection(body any) bool {
	m, ok := body.(map[string]any)
	if !ok {
		return false
	}
	sections, _ := m["sections"].([]any)
	for _, s := range sections {
		if sec, _ := s.(map[string]any); sec["events"] != nil {
			return true
		}
	}
	return false
}

// eventsListing is the listing site.events names, when it exists.
func (st *Site) eventsListing() (*listing.Listing, bool) {
	if st.Events == "" || st.Listings == nil || st.Listings.Set == nil {
		return nil, false
	}
	return st.Listings.Set.Get(st.Events)
}

// eventRows is the events the listing keeps now, up to max.
func (st *Site) eventRows(max int) ([]listing.Row, bool) {
	l, ok := st.eventsListing()
	if !ok {
		return nil, false
	}
	idx, err := st.Listings.Index.For(st.Listings.Store, st.Listings.At(), l.Collection)
	if err != nil {
		return nil, false
	}
	rows, _, err := listing.Every(l, idx, nil, max)
	if err != nil {
		return nil, false
	}
	return rows, true
}

// eventPage is the published page that is each event's own, when one
// declares a detail route through the events listing: its name and key.
func (st *Site) eventPage() (string, string, bool) {
	pages, _, err := st.pages()
	if err != nil {
		return "", "", false
	}
	names := make([]string, 0, len(pages))
	for n := range pages {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if d, ok := detailOf(pages[n]); ok && d.Declared() && d.Listing == st.Events {
			return n, d.Key, true
		}
	}
	return "", "", false
}

// eventLink is where each event's own page is: found once, for all of them.
type eventLink struct{ page, key string }

func (st *Site) eventLinks() eventLink {
	page, key, _ := st.eventPage()
	return eventLink{page, key}
}

// eventHref is an event's own page, when there is one.
func (st *Site) eventHref(row listing.Row) string { return st.eventLinks().href(row) }

func (l eventLink) href(row listing.Row) string {
	page, key := l.page, l.key
	if page == "" {
		return ""
	}
	k, _ := row[key].(string)
	if k == "" || strings.ContainsAny(k, "/?#") {
		return ""
	}
	return "/" + page + "/" + url.PathEscape(k)
}

// eventView is an event as a page shows it.
func (st *Site) eventView(row listing.Row) map[string]any {
	return st.eventViewWith(row, st.eventLinks())
}

func (st *Site) eventViewWith(row listing.Row, links eventLink) map[string]any {
	t, ok := readEventTimes(row)
	if !ok {
		return nil
	}
	str := func(k string) string { v, _ := row[k].(string); return strings.TrimSpace(v) }
	id, _ := row["id"].(string)
	out := map[string]any{
		"name": str("title"), "when": t.say(), "day": t.start.Format("2"), "month": t.start.Format("Jan"),
		"weekday": t.start.Format("Monday"), "place": str("venue"), "address": str("location"),
		"summary": str("summary"), "price": str("price"),
		"ics": "/events.ics?" + url.Values{"event": {id}}.Encode(),
	}
	if href := links.href(row); href != "" {
		out["href"] = href
	} else {
		out["plain"] = true
	}
	for _, k := range []string{"online", "tickets"} {
		if u := str(k); strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
			out[k] = u
			if pu, err := url.Parse(u); err == nil {
				out[k+"_label"] = pu.Host
			}
		}
	}
	if s, ok := eventStatus[strings.ToLower(str("status"))]; ok {
		out["status"] = s.label
	}
	return out
}

// eventsData is what an events section shows: up to rows events.
func (st *Site) eventsData(rows int) map[string]any {
	if _, ok := st.eventsListing(); !ok {
		return map[string]any{"closed": true}
	}
	if rows <= 0 || rows > 50 {
		rows = 6
	}
	found, ok := st.eventRows(rows + 20)
	if !ok {
		return map[string]any{"closed": true}
	}
	var items []any
	links := st.eventLinks()
	for _, r := range found {
		if t, ok := readEventTimes(r); ok && t.over() {
			continue
		}
		if v := st.eventViewWith(r, links); v != nil {
			items = append(items, v)
		}
		if len(items) == rows {
			break
		}
	}
	out := map[string]any{"feed": "/events.ics", "none": len(items) == 0}
	if len(items) > 0 {
		out["items"] = items
	}
	return out
}

// eventLD is an event's schema.org data, from the row the page shows.
func (st *Site) eventLD(row listing.Row) string {
	t, ok := readEventTimes(row)
	name, _ := row["title"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		return ""
	}
	str := func(k string) string { v, _ := row[k].(string); return strings.TrimSpace(v) }
	doc := map[string]any{"@context": "https://schema.org", "@type": "Event", "name": name,
		"startDate": t.ld(t.start), "eventStatus": "https://schema.org/EventScheduled"}
	if t.hasEnd {
		doc["endDate"] = t.ld(t.end)
	}
	if s, ok := eventStatus[strings.ToLower(str("status"))]; ok {
		doc["eventStatus"] = s.ld
	}
	if d := str("summary"); d != "" {
		doc["description"] = d
	}
	var where []any
	if p := str("venue"); p != "" || str("location") != "" {
		place := map[string]any{"@type": "Place", "name": p}
		if p == "" {
			place["name"] = str("location")
		}
		if a := str("location"); a != "" {
			place["address"] = a
		}
		where = append(where, place)
	}
	online := str("online")
	if strings.HasPrefix(online, "https://") || strings.HasPrefix(online, "http://") {
		where = append(where, map[string]any{"@type": "VirtualLocation", "url": online})
	}
	switch {
	case len(where) == 2:
		doc["eventAttendanceMode"] = "https://schema.org/MixedEventAttendanceMode"
	case len(where) == 1 && online != "":
		doc["eventAttendanceMode"] = "https://schema.org/OnlineEventAttendanceMode"
	case len(where) == 1:
		doc["eventAttendanceMode"] = "https://schema.org/OfflineEventAttendanceMode"
	}
	if len(where) == 1 {
		doc["location"] = where[0]
	} else if len(where) > 1 {
		doc["location"] = where
	}
	if img := str("image"); img != "" && !strings.ContainsAny(img, "/:") {
		doc["image"] = st.absoluteURL("/media/" + img)
	}
	if tickets := str("tickets"); strings.HasPrefix(tickets, "https://") || strings.HasPrefix(tickets, "http://") {
		offer := map[string]any{"@type": "Offer", "url": tickets}
		if strings.EqualFold(str("price"), "free") {
			offer["price"] = "0"
		}
		doc["offers"] = offer
	} else if strings.EqualFold(str("price"), "free") {
		doc["isAccessibleForFree"] = true
	}
	if st.Name != "" {
		org := map[string]any{"@type": "Organization", "name": st.Name}
		if st.BaseURL != "" {
			org["url"] = strings.TrimSuffix(st.BaseURL, "/") + "/"
		}
		doc["organizer"] = org
	}
	if href := st.eventHref(row); href != "" {
		doc["url"] = st.absoluteURL(href)
	}
	b, err := json.Marshal(doc)
	if err != nil || strings.Contains(strings.ToLower(string(b)), "</script") {
		return ""
	}
	return `<script type="application/ld+json">` + string(b) + `</script>`
}

// eventsCalendar is GET /events.ics: every event the listing keeps, as a
// calendar a visitor subscribes to, or one with ?event=ID, to add.
func (st *Site) eventsCalendar(w http.ResponseWriter, r *http.Request) {
	if _, ok := st.eventsListing(); !ok {
		st.notFound(w, r)
		return
	}
	rows, ok := st.eventRows(listing.MaxRows)
	if !ok {
		http.Error(w, "the events could not be read", http.StatusInternalServerError)
		return
	}
	only := r.URL.Query().Get("event")
	host := "quilzo"
	if u, err := url.Parse(st.BaseURL); err == nil && u.Host != "" {
		host = u.Host
	}
	var events []ical.Event
	links := st.eventLinks()
	for _, row := range rows {
		id, _ := row["id"].(string)
		if only != "" && id != only {
			continue
		}
		t, ok := readEventTimes(row)
		name, _ := row["title"].(string)
		if !ok || name == "" || t.over() {
			continue
		}
		str := func(k string) string { v, _ := row[k].(string); return strings.TrimSpace(v) }
		e := ical.Event{UID: id + "@" + host, Start: t.start, End: t.end, AllDay: t.allDay, Summary: name,
			Description: str("summary")}
		if t.allDay && !t.hasEnd {
			e.End = t.start.AddDate(0, 0, 1)
		} else if t.allDay {
			e.End = t.end.AddDate(0, 0, 1)
		}
		var where []string
		for _, k := range []string{"venue", "location", "online"} {
			if v := str(k); v != "" {
				where = append(where, v)
			}
		}
		e.Location = strings.Join(where, ", ")
		if href := links.href(row); href != "" && st.BaseURL != "" {
			e.URL = st.absoluteURL(href)
		}
		if s, ok := eventStatus[strings.ToLower(str("status"))]; ok {
			e.Status = s.cal
			if s.cal != ical.Confirmed {
				e.Summary = s.label + ": " + name
			}
		}
		events = append(events, e)
	}
	if only != "" && len(events) == 0 {
		st.notFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/calendar; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	if only != "" {
		h.Set("Content-Disposition", `attachment; filename="event.ics"`)
	}
	_, _ = w.Write(ical.Write(st.siteLabel()+" events", "Events", events, time.Now()))
}
