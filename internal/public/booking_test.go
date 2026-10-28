// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/booking"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/starter"
)

// bookingSite is a salon whose "book" page takes haircuts, on the sections
// starter's own layout, at a fixed time: Monday 2 November 2026, 08:00.
func bookingSite(t *testing.T) (*Site, *booking.Book, string, *time.Time) {
	t.Helper()
	st := published(t, map[string]any{
		"index": map[string]any{"title": "Hart's Salon"},
		"book": map[string]any{"title": "Book", "sections": []any{
			map[string]any{"booking": map[string]any{"title": "Book a cut", "service": "cut"}}}},
	})
	tpl, _ := starter.Get("sections")
	html, err := tpl.HTML()
	if err != nil {
		t.Fatal(err)
	}
	st.Layouts = render.OneLayout(html)
	st.Name, st.Index = "Hart's Salon", "index"
	dir := filepath.Join(t.TempDir(), "bookings")
	book, err := booking.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	setup := &booking.Setup{Zone: "Europe/London", NoticeHours: 2,
		Week:     map[string][]booking.Span{"tue": {{From: "09:00", To: "12:00"}}},
		Services: []booking.Service{{Name: "cut", Title: "Haircut", Minutes: 45, Buffer: 15, Price: "£30"}}}
	now := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	var audited []string
	st.Bookings = &Bookings{Setup: func() (*booking.Setup, error) { return setup, nil }, Book: book,
		Now:   func() time.Time { return now },
		Audit: func(action, service, _ string, ok bool) { audited = append(audited, action) }}
	t.Cleanup(func() {
		for _, a := range audited {
			if strings.Contains(a, "@") {
				t.Errorf("an audit record names somebody: %s", a)
			}
		}
	})
	return st, book, dir, &now
}

func getPage(st *Site, target string) *httptest.ResponseRecorder {
	// What a browser sends: never the fragment.
	target, _, _ = strings.Cut(target, "#")
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return w
}

func postTo(st *Site, target string, v url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "203.0.113.9:4000"
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, r)
	return w
}

var reSlot = regexp.MustCompile(`name="slot" id="slot-[^"]+" value="(\d+)"`)

// A visitor sees the free times, books one, is shown it on the same page,
// can add it to their calendar and cancel it; nothing the site shows or
// stores in its calendar names them.
func TestAVisitorBooksSeesAndCancelsATime(t *testing.T) {
	st, book, dir, now := bookingSite(t)
	page := getPage(st, "/book")
	body := page.Body.String()
	if page.Code != 200 || page.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("the booking page: %d, %q", page.Code, page.Header().Get("Cache-Control"))
	}
	m := reSlot.FindAllStringSubmatch(body, -1)
	// Seven days with free times at once: only Tuesdays open, three each.
	if len(m) != 21 || !strings.Contains(body, "Tuesday 3 November") || !strings.Contains(body, "London time") ||
		!strings.Contains(body, "Haircut, 45 minutes · £30") {
		t.Fatalf("offered %d times:\n%s", len(m), body)
	}
	// The times, the fields and the button pass the same checks the
	// publish gate runs, which sees this section only without its times.
	if rep := a11y.Check("book", body); rep.Blocks() {
		t.Fatalf("the booking form is not usable by everybody: %+v", rep)
	}
	stamp := regexp.MustCompile(`name="form_started" value="(\d+)"`).FindStringSubmatch(body)
	if stamp == nil {
		t.Fatal("the form carries no stamp")
	}
	// The page's stamp is the real clock's; this site's clock is fixed, so
	// the visitor read the page a minute before booking by that one.
	read := fmt.Sprint(now.Unix())
	*now = now.Add(time.Minute)
	slot := m[1][1]
	res := postTo(st, "/book/cut", url.Values{"page": {"book"}, "slot": {slot}, "name": {"Ann Example"},
		"email": {"ann@example.com"}, "form_started": {read}})
	loc := res.Header().Get("Location")
	if res.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/book?booking=") {
		t.Fatalf("booking: %d %s %s", res.Code, loc, res.Body.String())
	}

	// The same page, now showing the booking, to whoever has the address.
	mine := getPage(st, loc)
	mb := mine.Body.String()
	if rep := a11y.Check("book", mb); rep.Blocks() {
		t.Fatalf("the confirmation is not usable by everybody: %+v", rep)
	}
	if !strings.Contains(mb, "You are booked") || !strings.Contains(mb, "Tuesday 3 November 2026 at 10:00") ||
		strings.Contains(mb, "Ann Example") || mine.Header().Get("X-Robots-Tag") != "noindex" {
		t.Fatalf("the confirmation:\n%s", mb)
	}
	// And the time is no longer offered to anybody else.
	if strings.Count(getPage(st, "/book").Body.String(), `name="slot"`) != 20 {
		t.Fatal("a booked time is still offered")
	}
	cal, _ := os.ReadFile(filepath.Join(dir, "calendar", "2026-11.json"))
	if strings.Contains(string(cal), "Ann") || strings.Contains(string(cal), "example.com") {
		t.Fatalf("the calendar names the visitor: %s", cal)
	}

	ics := regexp.MustCompile(`href="(/book/[^"]+\.ics\?[^"]+)"`).FindStringSubmatch(mb)
	if ics == nil {
		t.Fatal("no calendar file offered")
	}
	file := getPage(st, strings.ReplaceAll(ics[1], "&amp;", "&"))
	if file.Code != 200 || file.Header().Get("Content-Type") != "text/calendar; charset=utf-8" ||
		!strings.Contains(file.Body.String(), "DTSTART:20261103T100000Z") ||
		!strings.Contains(strings.ReplaceAll(file.Body.String(), "\r\n ", ""), "https://example.org/book?booking=") {
		t.Fatalf("the calendar file: %d\n%s", file.Code, file.Body.String())
	}
	if wrong := getPage(st, strings.SplitN(ics[1], "?", 2)[0]+"?k=nope"); wrong.Code != 404 {
		t.Fatalf("a calendar file without its token: %d", wrong.Code)
	}

	id := regexp.MustCompile(`name="id" value="([^"]+)"`).FindStringSubmatch(mb)
	token := regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(mb)
	if res := postTo(st, "/book/cancel", url.Values{"page": {"book"}, "id": {id[1]}, "token": {"guess"}}); res.Code != 404 {
		t.Fatalf("cancelled without the token: %d", res.Code)
	}
	res = postTo(st, "/book/cancel", url.Values{"page": {"book"}, "id": {id[1]}, "token": {token[1]}})
	if res.Code != http.StatusSeeOther {
		t.Fatalf("cancelling: %d", res.Code)
	}
	if !strings.Contains(getPage(st, res.Header().Get("Location")).Body.String(), "Cancelled.") {
		t.Fatal("the page does not say it was cancelled")
	}
	if strings.Count(getPage(st, "/book").Body.String(), `name="slot"`) != 21 {
		t.Fatal("a cancelled time is not offered again")
	}
	if list, _ := book.List(*now, now.AddDate(0, 0, 7)); len(list) != 1 || list[0].Who.Name != "Ann Example" {
		t.Fatalf("the admin's list: %+v", list)
	}
}

// A script that did not read the page, a time nobody offered, and details
// that are not enough are all refused, and the page says which in its own
// words, never the request's.
func TestABookingThatShouldNotGoThroughDoesNot(t *testing.T) {
	st, _, _, now := bookingSite(t)
	body := getPage(st, "/book").Body.String()
	slot := reSlot.FindStringSubmatch(body)[1]
	stamp := fmt.Sprint(now.Unix())
	*now = now.Add(time.Minute)
	cases := []struct {
		v    url.Values
		code string
	}{
		{url.Values{"page": {"book"}, "slot": {slot}, "name": {"A"}, "email": {"a@b.co"}, "form_started": {stamp},
			"website_url": {"http://spam"}}, "refused"},
		{url.Values{"page": {"book"}, "slot": {slot}, "name": {"A"}, "email": {"a@b.co"}}, "refused"},
		{url.Values{"page": {"book"}, "slot": {"1"}, "name": {"A"}, "email": {"a@b.co"}, "form_started": {stamp}}, "taken"},
		{url.Values{"page": {"book"}, "slot": {slot}, "name": {"A"}, "email": {"<script>"}, "form_started": {stamp}}, "details"},
	}
	for _, c := range cases {
		res := postTo(st, "/book/cut", c.v)
		if res.Code != http.StatusSeeOther || !strings.Contains(res.Header().Get("Location"), "booking_error="+c.code) {
			t.Errorf("%v: %d %s", c.v, res.Code, res.Header().Get("Location"))
		}
	}
	if got := getPage(st, "/book?booking_error=%3Cscript%3E").Body.String(); strings.Contains(got, "<script>") {
		t.Fatal("an error code was written back into the page")
	}
	// A page that offers no bookings, and a service nobody offers, take none.
	for _, v := range []url.Values{{"page": {"index"}, "slot": {slot}}, {"page": {"book"}, "slot": {slot}}} {
		target := "/book/cut"
		if v.Get("page") == "book" {
			target = "/book/colour"
		}
		if res := postTo(st, target, v); res.Code != 404 {
			t.Errorf("%s from %s: %d", target, v.Get("page"), res.Code)
		}
	}
}

// The owner's feed is every booking's time and service, never who, and
// only for whoever holds its token.
func TestTheOwnersFeedShowsTimesNotNames(t *testing.T) {
	st, book, _, now := bookingSite(t)
	setup, _ := st.Bookings.Setup()
	setup.Feed = booking.FeedHash("secret-feed-token")
	cut, _ := setup.Service("cut")
	if _, _, err := book.Reserve(setup, cut, time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC), *now,
		booking.Details{Name: "Ann Example", Email: "ann@example.com"}); err != nil {
		t.Fatal(err)
	}
	feed := getPage(st, "/book/feed/secret-feed-token.ics")
	body, _ := io.ReadAll(feed.Body)
	if feed.Code != 200 || !strings.Contains(string(body), "SUMMARY:Booked: Haircut") || strings.Contains(string(body), "Ann") {
		t.Fatalf("the feed: %d\n%s", feed.Code, body)
	}
	if getPage(st, "/book/feed/wrong.ics").Code != 404 {
		t.Fatal("a feed for a wrong token")
	}
	setup.Feed = ""
	if getPage(st, "/book/feed/secret-feed-token.ics").Code != 404 {
		t.Fatal("a feed that was turned off still answers")
	}
}

// Paused, a page offers nothing, and a booking is refused.
func TestPausedBookingsTakeNone(t *testing.T) {
	st, _, _, _ := bookingSite(t)
	setup, _ := st.Bookings.Setup()
	slot := reSlot.FindStringSubmatch(getPage(st, "/book").Body.String())[1]
	setup.Paused = true
	if body := getPage(st, "/book").Body.String(); strings.Contains(body, `name="slot"`) || !strings.Contains(body, "not being taken") {
		t.Fatal("a paused site offers times")
	}
	if res := postTo(st, "/book/cut", url.Values{"page": {"book"}, "slot": {slot}}); res.Code != http.StatusSeeOther {
		t.Fatalf("booking while paused: %d", res.Code)
	}
}

// A visitor's browser agent is offered the booking form as a tool, said in
// the setup's own words, which the visitor still submits; never the
// cancel button, and nothing while bookings are paused.
func TestABookingFormIsAToolForAVisitorsAgent(t *testing.T) {
	st, _, _, _ := bookingSite(t)
	body := getPage(st, "/book").Body.String()
	if !strings.Contains(body, `toolname="book-cut"`) || strings.Contains(body, "toolautosubmit") ||
		!strings.Contains(body, "Book Haircut, 45 minutes, £30") ||
		!strings.Contains(body, `toolparamdescription="The time to book`) {
		t.Fatalf("the booking form is not offered as a tool:\n%s", body)
	}
	setup, _ := st.Bookings.Setup()
	setup.Paused = true
	if strings.Contains(getPage(st, "/book").Body.String(), `toolname="book-cut"`) {
		t.Fatal("a paused site offers a booking tool")
	}
}
