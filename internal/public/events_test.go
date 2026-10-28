// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/starter"
)

// eventsSite is a bakery whose "events" page lists what is on, with a page
// for each event, on London's clock at 18:00 on Friday 13 November 2026.
func eventsSite(t *testing.T) (*Site, func(string)) {
	t.Helper()
	st := published(t, map[string]any{
		"index":  map[string]any{"title": "Crumb"},
		"events": map[string]any{"title": "What's on", "sections": []any{map[string]any{"events": map[string]any{"title": "What's on"}}}},
		"event":  map[string]any{"detail": "upcoming_events", "detail_key": "slug"},
	})
	tpl, _ := starter.Get("sections")
	html, err := tpl.HTML()
	if err != nil {
		t.Fatal(err)
	}
	st.Layouts = render.OneLayout(html)
	st.Name, st.Index, st.BaseURL = "Crumb", "index", "https://crumb.example"
	recs := []collection.Record{
		{ID: "11111111111111111111111111111111", Fields: map[string]any{"title": "Rye night", "slug": "rye-night",
			"date": "2026-11-14", "time": "19:30", "until": "21:00", "venue": "The bakery",
			"location": "1 High Street, Leeds", "price": "£5", "tickets": "https://tickets.example/rye",
			"summary": "Four ryes, tasted.", "secret": "do not publish"}},
		{ID: "22222222222222222222222222222222", Fields: map[string]any{"title": "Christmas market", "slug": "market",
			"date": "2026-12-12", "end_date": "2026-12-13", "venue": "The square", "status": "postponed"}},
		{ID: "33333333333333333333333333333333", Fields: map[string]any{"title": "Online class", "slug": "class",
			"date": "2026-11-20", "time": "10:00", "online": "https://meet.example/class", "price": "Free"}},
		{ID: "44444444444444444444444444444444", Fields: map[string]any{"title": "Last week's tasting",
			"slug": "gone", "date": "2026-11-06", "time": "19:00"}},
		{ID: "55555555555555555555555555555555", Fields: map[string]any{"title": "This afternoon", "slug": "today",
			"date": "2026-11-13", "time": "14:00", "until": "17:00"}},
	}
	tree, _, err := collection.PutMany(st.Store, "", "events", recs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	set := &listing.Set{}
	if err := set.Add(listing.Listing{Name: "upcoming_events", Collection: "events", Sort: "date", Rows: 50,
		Fields: []string{"title", "slug", "date", "time", "end_date", "until", "venue", "location", "online", "summary",
			"price", "tickets", "status"},
		Where: []listing.Condition{{Field: "end_date", Else: "date", Match: listing.Upcoming}}}); err != nil {
		t.Fatal(err)
	}
	st.Listings = &listing.Resolver{Store: st.Store, Set: set, Live: func() string { return tree }}
	st.Events = "upcoming_events"
	london, err := time.LoadLocation("Europe/London")
	if err != nil {
		t.Skip("no zone database")
	}
	listing.SetZone(func() *time.Location { return london })
	now := "2026-11-13T18:00"
	oldNow := listing.Now
	listing.Now = func() string { return now }
	t.Cleanup(func() { listing.Now = oldNow; listing.SetZone(nil) })
	return st, func(at string) { now = at }
}

// What is on: in date order, each with when and where in words, a link to
// its own page and its own calendar entry; what is over is not there.
func TestTheEventsSectionListsWhatIsStillToCome(t *testing.T) {
	st, _ := eventsSite(t)
	res := getPage(st, "/events")
	body := res.Body.String()
	if res.Code != 200 {
		t.Fatalf("the events page: %d", res.Code)
	}
	names := regexp.MustCompile(`<h3 class="event-name">(?:<a href="([^"]+)">)?([^<]+)`).FindAllStringSubmatch(body, -1)
	var got []string
	for _, n := range names {
		got = append(got, n[2])
	}
	if strings.Join(got, ", ") != "Rye night, Online class, Christmas market" {
		t.Fatalf("listed: %v", got)
	}
	if names[0][1] != "/event/rye-night" {
		t.Errorf("an event's own page: %q", names[0][1])
	}
	for _, want := range []string{"Saturday 14 November 2026, 19:30–21:00 · The bakery · £5",
		"Saturday 12 December to Sunday 13 December 2026", "Postponed", `href="/events.ics?event=11111111111111111111111111111111"`,
		`href="/events.ics">Subscribe`} {
		if !strings.Contains(body, want) {
			t.Errorf("the section lacks %q", want)
		}
	}
	if strings.Contains(body, "do not publish") {
		t.Error("a field the listing keeps private is on the page")
	}
	if rep := a11y.Check("events", body); rep.Blocks() {
		t.Fatalf("the events section is not usable by everybody: %+v", rep)
	}
}

// A page listing what is to come changes when an event ends, with nothing
// published: it is not answered "not modified" with an event that is over.
// This afternoon's, over at 17:00, was already left out at 18:00.
func TestAnEventThatEndsLeavesWithNothingPublished(t *testing.T) {
	st, at := eventsSite(t)
	first := getPage(st, "/events")
	at("2026-11-14T21:00")
	r := httptest.NewRequest(http.MethodGet, "/events", nil)
	r.Header.Set("If-None-Match", first.Header().Get("ETag"))
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusNotModified {
		t.Fatal("the page was not modified after an event on it ended")
	}
	if strings.Contains(w.Body.String(), "Rye night") {
		t.Fatal("an event that has ended is still listed")
	}
}

// Each event's page says when and where to people and to machines, as an
// Event and never as a Product.
func TestAnEventsPageSaysWhenAndWhereToMachines(t *testing.T) {
	st, _ := eventsSite(t)
	res := getPage(st, "/event/rye-night")
	body := res.Body.String()
	if res.Code != 200 || !strings.Contains(body, "<h1>Rye night</h1>") || !strings.Contains(body, "Add to your calendar") {
		t.Fatalf("the event's page: %d\n%s", res.Code, body)
	}
	if rep := a11y.Check("event", body); rep.Blocks() {
		t.Fatalf("an event's page is not usable by everybody: %+v", rep)
	}
	m := regexp.MustCompile(`<script type="application/ld\+json">(\{"@context":"https://schema.org","@type":"Event".*?)</script>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no Event data:\n%s", body)
	}
	if strings.Contains(body, `"@type":"Product"`) {
		t.Error("an event was described as a product")
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(m[1]), &ev); err != nil {
		t.Fatal(err)
	}
	loc, _ := ev["location"].(map[string]any)
	offers, _ := ev["offers"].(map[string]any)
	if ev["startDate"] != "2026-11-14T19:30:00+00:00" || ev["endDate"] != "2026-11-14T21:00:00+00:00" ||
		loc["name"] != "The bakery" || loc["address"] != "1 High Street, Leeds" ||
		ev["eventAttendanceMode"] != "https://schema.org/OfflineEventAttendanceMode" ||
		ev["eventStatus"] != "https://schema.org/EventScheduled" || offers["url"] != "https://tickets.example/rye" ||
		ev["url"] != "https://crumb.example/event/rye-night" {
		t.Fatalf("the Event: %v", ev)
	}
	online := getPage(st, "/event/class").Body.String()
	if !strings.Contains(online, `"eventAttendanceMode":"https://schema.org/OnlineEventAttendanceMode"`) ||
		!strings.Contains(online, `"isAccessibleForFree":true`) || !strings.Contains(online, `"@type":"VirtualLocation"`) {
		t.Errorf("an online event's data:\n%s", online)
	}
	market := getPage(st, "/event/market").Body.String()
	if !strings.Contains(market, `"startDate":"2026-12-12"`) || !strings.Contains(market, `"endDate":"2026-12-13"`) ||
		!strings.Contains(market, "EventPostponed") || !strings.Contains(market, `role="status">Postponed`) {
		t.Errorf("a postponed market over two days:\n%s", market)
	}
	if getPage(st, "/event/gone").Code != http.StatusNotFound {
		t.Error("an event that is over still has a page")
	}
}

// The calendar a visitor subscribes to, and one event to add.
func TestTheSitesEventsAreACalendar(t *testing.T) {
	st, _ := eventsSite(t)
	res := getPage(st, "/events.ics")
	cal := res.Body.String()
	if res.Code != 200 || res.Header().Get("Content-Type") != "text/calendar; charset=utf-8" {
		t.Fatalf("the calendar: %d %q", res.Code, res.Header().Get("Content-Type"))
	}
	for _, want := range []string{"X-WR-CALNAME:Crumb events", "SUMMARY:Rye night", "DTSTART:20261114T193000Z",
		`LOCATION:The bakery\, 1 High Street\, Leeds`, "URL:https://crumb.example/event/rye-night",
		"UID:11111111111111111111111111111111@crumb.example", "DTSTART;VALUE=DATE:20261212",
		"DTEND;VALUE=DATE:20261214", "SUMMARY:Postponed: Christmas market", "STATUS:TENTATIVE"} {
		if !strings.Contains(cal, want+"\r\n") {
			t.Errorf("the calendar lacks %q", want)
		}
	}
	if strings.Contains(cal, "Last week") || strings.Contains(cal, "This afternoon") {
		t.Error("the calendar carries events that are over")
	}
	one := getPage(st, "/events.ics?event=33333333333333333333333333333333")
	if one.Code != 200 || strings.Count(one.Body.String(), "BEGIN:VEVENT") != 1 ||
		!strings.Contains(one.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("one event: %d %s", one.Code, one.Body.String())
	}
	if getPage(st, "/events.ics?event=44444444444444444444444444444444").Code != http.StatusNotFound {
		t.Error("an event that is over can still be added")
	}
	if !strings.Contains(getPage(st, "/").Body.String(), `href="/events.ics" title="Events"`) ||
		!strings.Contains(getPage(st, "/llms.txt").Body.String(), "/events.ics") {
		t.Error("the calendar is not where a reader's software or an agent looks for it")
	}
	st.Events = ""
	if getPage(st, "/events.ics").Code != http.StatusNotFound {
		t.Error("a site with no events serves a calendar")
	}
}
