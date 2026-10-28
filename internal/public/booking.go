// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/booking"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/throttle"
)

// Bookings, on the public site.
//
// A page carries a booking section naming a service; its free times are
// read from the calendar when the page is asked for, and a visitor books
// one with a plain form. What they booked is shown on that same page, from
// an address only they were given, with the calendar file and the button
// that cancels it.
//
// What this process may touch is the calendar, which says when and not
// who, and who booked, which it writes once and never reads (see
// internal/booking). The owner's calendar feed shows the times and the
// service, never a name: the names are in the admin.

// Bookings gives the site the setup and the book. Nil means /book/
// answers 404 and a booking section says no bookings are taken.
type Bookings struct {
	Setup func() (*booking.Setup, error)
	Book  *booking.Book
	// Limit bounds bookings from one address.
	Limit *throttle.Limiter
	// Audit records that a booking was made or cancelled, never by whom.
	Audit func(action, service, source string, ok bool)
	// Notify tells another system a booking was made or cancelled.
	Notify func(action, service string)
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

func (st *Site) bookingsOn() bool {
	return st.Bookings != nil && st.Bookings.Setup != nil && st.Bookings.Book != nil
}

func (st *Site) bookingNow() time.Time {
	if st.Bookings != nil && st.Bookings.Now != nil {
		return st.Bookings.Now()
	}
	return time.Now()
}

// bookingDays is how many days with free times a page shows at once.
const bookingDays = 7

// bookingErrors are what a visitor is told after a booking did not go
// through, by code, so nothing a request sent is ever written back.
var bookingErrors = map[string]string{
	"taken":   "That time has just been taken, or is no longer offered. Choose another.",
	"details": "Say your name and an email address we can reach you at.",
	"paused":  "Bookings are not being taken just now.",
	"old":     "This page was opened more than a day ago. Choose a time again.",
	"refused": "That booking was not accepted.",
	"past":    "That booking has already started, so it cannot be cancelled here.",
}

// bookingData is a service's free times on a page, or what a visitor
// booked there.
func (st *Site) bookingData(service, page string, args map[string]string) map[string]any {
	if !st.bookingsOn() {
		return nil
	}
	setup, err := st.Bookings.Setup()
	if err != nil || setup == nil {
		return nil
	}
	svc, ok := setup.Service(service)
	if !ok {
		return nil
	}
	loc, err := setup.Location()
	if err != nil {
		return nil
	}
	out := map[string]any{"service_title": svc.Title, "minutes": float64(svc.Minutes),
		"price": svc.Price, "about": svc.About, "zone": zoneLabel(setup.Zone),
		"keep": float64(setup.Keep() / (24 * time.Hour))}
	if msg, ok := bookingErrors[args["booking_error"]]; ok {
		out["problem"] = msg
	}
	// What a visitor booked, from the address they were given.
	if id, token, ok := strings.Cut(args["booking"], "."); ok {
		if x, err := st.Bookings.Book.Find(id); err == nil && x.Matches(token) {
			out["booked"] = map[string]any{
				"when":      x.Start.In(loc).Format("Monday 2 January 2006 at 15:04"),
				"id":        x.ID,
				"token":     token,
				"ics":       "/book/" + x.ID + ".ics?" + url.Values{"k": {token}, "p": {page}}.Encode(),
				"cancelled": !x.Live(),
				"upcoming":  x.Live() && st.bookingNow().Before(x.Start),
			}
			return out
		}
		out["problem"] = "That booking could not be found. The address may be incomplete."
	}
	if setup.Paused {
		out["paused"] = true
		return out
	}
	now := st.bookingNow()
	busy, err := st.Bookings.Book.Window(setup, now)
	if err != nil {
		return nil
	}
	days, err := booking.Free(setup, svc, busy, now)
	if err != nil {
		return nil
	}
	// A page of days at a time, from the date asked for.
	if from := args["from"]; from != "" {
		for i, d := range days {
			if d.Date >= from {
				days = days[i:]
				break
			}
		}
	}
	var shown []any
	for i, d := range days {
		if i == bookingDays {
			out["later"] = "?from=" + d.Date + "#book"
			break
		}
		var slots []any
		for _, sl := range d.Slots {
			slots = append(slots, map[string]any{"value": strconv.FormatInt(sl.Start.Unix(), 10),
				"label": sl.Label, "id": d.Date + "-" + strings.ReplaceAll(sl.Label, ":", "")})
		}
		shown = append(shown, map[string]any{"date": d.Date, "label": d.Label, "slots": slots})
	}
	out["days"] = shown
	out["none"] = len(shown) == 0
	out["open"] = len(shown) > 0
	return out
}

// zoneLabel says which clock the times are on, as people say it.
func zoneLabel(zone string) string {
	city := zone
	if i := strings.LastIndex(zone, "/"); i >= 0 {
		city = zone[i+1:]
	}
	return strings.ReplaceAll(city, "_", " ") + " time"
}

// bookingsOnPage names the services a page takes bookings for.
func bookingsOnPage(body any) []string {
	m, ok := body.(map[string]any)
	if !ok {
		return nil
	}
	sections, _ := m["sections"].([]any)
	var out []string
	for _, s := range sections {
		sec, _ := s.(map[string]any)
		if b, ok := sec["booking"].(map[string]any); ok {
			if name, _ := b["service"].(string); name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}

// pagePath is where a page is served.
func (st *Site) pagePath(name string) string {
	if name == st.Index {
		return "/"
	}
	return "/" + name
}

// book routes /book/: a booking posted to /book/SERVICE, a cancellation
// to /book/cancel, a visitor's calendar file at /book/ID.ics, and the
// owner's feed at /book/feed/TOKEN.ics.
func (st *Site) book(w http.ResponseWriter, r *http.Request) {
	if !st.bookingsOn() {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/book/")
	switch {
	case strings.HasPrefix(rest, "feed/") && strings.HasSuffix(rest, ".ics") && r.Method == http.MethodGet:
		st.bookingFeed(w, r, strings.TrimSuffix(strings.TrimPrefix(rest, "feed/"), ".ics"))
	case strings.HasSuffix(rest, ".ics") && r.Method == http.MethodGet:
		st.bookingFile(w, r, strings.TrimSuffix(rest, ".ics"))
	case rest == "cancel" && r.Method == http.MethodPost:
		st.bookingCancel(w, r)
	case r.Method == http.MethodPost:
		st.bookingMake(w, r, rest)
	default:
		http.NotFound(w, r)
	}
}

// bookingPage is the published page a form says it was on, when that page
// carries a booking section for the service.
func (st *Site) bookingPage(name, service string) (string, bool) {
	pages, _, err := st.pages()
	if err != nil {
		return "", false
	}
	body, ok := pages[name]
	if !ok {
		return "", false
	}
	for _, s := range bookingsOnPage(body) {
		if s == service || service == "" {
			return st.pagePath(name), true
		}
	}
	return "", false
}

// back sends a visitor to the page they booked on, with what to show.
func back(w http.ResponseWriter, r *http.Request, path string, q url.Values) {
	http.Redirect(w, r, path+"?"+q.Encode()+"#book", http.StatusSeeOther)
}

// bookingMake books a time: POST /book/SERVICE with the page, the time,
// who, and the form's honeypot and stamp.
func (st *Site) bookingMake(w http.ResponseWriter, r *http.Request, service string) {
	setup, err := st.Bookings.Setup()
	if err != nil || setup == nil {
		http.NotFound(w, r)
		return
	}
	svc, ok := setup.Service(service)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, until, off := st.shielded("bookings"); off {
		st.resting(w, r, "Booking", until)
		return
	}
	source := sourceOf(r)
	if st.Bookings.Limit != nil {
		if d := st.Bookings.Limit.Check(throttle.Subject{Source: source}); !d.Allowed {
			w.Header().Set("Retry-After", fmt.Sprint(max(1, int(d.RetryAfter.Seconds()))))
			http.Error(w, "too many bookings from here, try again shortly", http.StatusTooManyRequests)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that booking could not be read", http.StatusBadRequest)
		return
	}
	path, ok := st.bookingPage(r.PostFormValue("page"), svc.Name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Every attempt counts, as a form's does: a script that read the page
	// once and books in a loop is what this bounds.
	if st.Bookings.Limit != nil {
		st.Bookings.Limit.Spend(throttle.Subject{Source: source})
	}
	fail := func(code string) {
		if st.Bookings.Audit != nil {
			st.Bookings.Audit("booking.refused", svc.Name, source, false)
		}
		back(w, r, path, url.Values{"booking_error": {code}})
	}
	now := st.bookingNow()
	// The same two checks a form makes: a field nobody sees, and a page
	// that was read by a person for at least two seconds.
	if strings.TrimSpace(r.PostFormValue(form.Honeypot)) != "" {
		st.signal(FormSpam, "booking:"+svc.Name, r)
		fail("refused")
		return
	}
	started, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue(form.StampField)), 10, 64)
	switch {
	case err != nil || now.Unix()-started < form.MinFillSeconds:
		st.signal(FormSpam, "booking:"+svc.Name, r)
		fail("refused")
		return
	case now.Unix()-started > int64((24 * time.Hour).Seconds()):
		fail("old")
		return
	}
	at, err := strconv.ParseInt(r.PostFormValue("slot"), 10, 64)
	if err != nil {
		fail("taken")
		return
	}
	x, token, err := st.Bookings.Book.Reserve(setup, svc, time.Unix(at, 0), now, booking.Details{
		Name: r.PostFormValue("name"), Email: r.PostFormValue("email"), Phone: r.PostFormValue("phone"),
		Note: r.PostFormValue("note"), Source: "web"})
	switch {
	case errors.Is(err, booking.ErrTaken):
		fail("taken")
		return
	case errors.Is(err, booking.ErrPaused):
		fail("paused")
		return
	case errors.Is(err, booking.ErrDetails):
		fail("details")
		return
	case err != nil:
		http.Error(w, "that booking could not be kept", http.StatusInternalServerError)
		return
	}
	if st.Bookings.Audit != nil {
		st.Bookings.Audit("booking.made", svc.Name, source, true)
	}
	st.convert(r, "booking:"+svc.Name)
	if st.Bookings.Notify != nil {
		st.Bookings.Notify("booking.made", svc.Name)
	}
	back(w, r, path, url.Values{"booking": {x.ID + "." + token}})
}

// bookingCancel cancels for whoever holds the booking's token.
func (st *Site) bookingCancel(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that could not be read", http.StatusBadRequest)
		return
	}
	path, ok := st.bookingPage(r.PostFormValue("page"), "")
	if !ok {
		http.NotFound(w, r)
		return
	}
	id, token := r.PostFormValue("id"), r.PostFormValue("token")
	x, err := st.Bookings.Book.Cancel(id, token, "visitor", st.bookingNow())
	switch {
	case errors.Is(err, booking.ErrPast):
		back(w, r, path, url.Values{"booking": {id + "." + token}, "booking_error": {"past"}})
		return
	case err != nil:
		http.NotFound(w, r)
		return
	}
	if st.Bookings.Audit != nil {
		st.Bookings.Audit("booking.cancelled", x.Service, sourceOf(r), true)
	}
	if st.Bookings.Notify != nil {
		st.Bookings.Notify("booking.cancelled", x.Service)
	}
	back(w, r, path, url.Values{"booking": {id + "." + token}})
}

// bookingFile is one booking as a calendar file, for whoever holds its
// token.
func (st *Site) bookingFile(w http.ResponseWriter, r *http.Request, id string) {
	x, err := st.Bookings.Book.Find(id)
	if err != nil || !x.Matches(r.URL.Query().Get("k")) {
		http.NotFound(w, r)
		return
	}
	setup, err := st.Bookings.Setup()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	title := x.Service
	if svc, ok := setup.Service(x.Service); ok {
		title = svc.Title
	}
	summary := title
	if st.Name != "" {
		summary += ", " + st.Name
	}
	about, link := "Booked on "+st.siteLabel()+".", ""
	// The way back to it, when the site knows its own address and the page
	// it was booked on still takes it.
	if path, ok := st.bookingPage(r.URL.Query().Get("p"), x.Service); ok && st.BaseURL != "" {
		link = strings.TrimSuffix(st.BaseURL, "/") + path + "?" +
			url.Values{"booking": {x.ID + "." + r.URL.Query().Get("k")}}.Encode() + "#book"
		about += " To see or cancel it: " + link
	}
	st.calendarFile(w, x.ID+".ics", booking.ICS(st.Name, []booking.Event{{UID: x.ID + "@quilzo",
		Start: x.Start, End: x.End(), Summary: summary, Description: about, URL: link, Cancelled: !x.Live()}},
		st.bookingNow()))
}

func (st *Site) siteLabel() string {
	if st.Name != "" {
		return st.Name
	}
	return "this site"
}

// bookingFeed is the owner's calendar: every booking's time and service,
// and never who made it, for whoever holds the feed's token.
func (st *Site) bookingFeed(w http.ResponseWriter, r *http.Request, token string) {
	setup, err := st.Bookings.Setup()
	if err != nil || setup == nil || setup.Feed == "" ||
		subtle.ConstantTimeCompare([]byte(booking.FeedHash(token)), []byte(setup.Feed)) != 1 {
		http.NotFound(w, r)
		return
	}
	now := st.bookingNow()
	busy, err := st.Bookings.Book.Busy(now.AddDate(0, 0, -30), now.AddDate(0, 0, setup.Ahead()+1))
	if err != nil {
		http.Error(w, "the calendar could not be read", http.StatusInternalServerError)
		return
	}
	var events []booking.Event
	for _, x := range busy {
		title := x.Service
		if svc, ok := setup.Service(x.Service); ok {
			title = svc.Title
		}
		events = append(events, booking.Event{UID: x.ID + "@quilzo", Start: x.Start, End: x.End(),
			Summary: "Booked: " + title, Description: "Who booked it is in the admin, under Bookings.",
			Cancelled: !x.Live()})
	}
	st.calendarFile(w, "bookings.ics", booking.ICS(st.siteLabel()+" bookings", events, now))
}

func (st *Site) calendarFile(w http.ResponseWriter, name string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", "text/calendar; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}

// bookingTool is a booking form as a tool a visitor's browser agent can
// fill in (WebMCP; see webmcp.go). Everything it says comes from the
// setup: the service's title, length and price, and the clock the times
// are on.
func (st *Site) bookingTool(service string) (toolSpec, bool) {
	if !st.bookingsOn() {
		return toolSpec{}, false
	}
	setup, err := st.Bookings.Setup()
	if err != nil || setup == nil || setup.Paused {
		return toolSpec{}, false
	}
	svc, ok := setup.Service(service)
	if !ok {
		return toolSpec{}, false
	}
	desc := fmt.Sprintf("Book %s, %d minutes", svc.Title, svc.Minutes)
	if svc.Price != "" {
		desc += ", " + svc.Price
	}
	desc += ", at one of the free times shown. The visitor reviews the booking and makes it themselves; " +
		"it can be cancelled from the page shown afterwards."
	return toolSpec{name: "book-" + svc.Name, description: desc, trap: form.Honeypot,
		params: map[string]string{
			"slot":  "The time to book: one of the free times offered, which are on " + zoneLabel(setup.Zone) + ". Required",
			"name":  "The visitor's name. Required",
			"email": "An email address the business can reach the visitor at. Required",
			"phone": "A telephone number, if the visitor wants to give one",
			"note":  "Anything the business should know, in the visitor's words",
		}}, true
}
