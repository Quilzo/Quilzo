// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/booking"
)

// Bookings: who booked what, and how the site takes bookings
// (internal/booking). Who booked is read here and nowhere else: the
// public site writes it once and cannot read it back.

// BookingHooks are what the screen asks of the bookings.
type BookingHooks struct {
	// Setup is how the site takes bookings; nil when it takes none.
	Setup func() (*booking.Setup, error)
	// List is the bookings from days back to days ahead, with who made
	// each.
	List func(back, ahead int) ([]booking.Booking, error)
	// Cancel cancels for the site; erase forgets who booked as well.
	Cancel func(id string, erase bool, by Actor) error
	// Save keeps a changed setup; what names the change for the record.
	Save func(s *booking.Setup, what string, by Actor) error
	// Feed makes the owner's calendar address, shown once, or turns it off.
	Feed func(off bool, by Actor) (string, error)
	// Calendar is the bookings ahead as a calendar file, names and all,
	// for the person signed in to take into their own calendar.
	Calendar func() ([]byte, error)
}

// bookingRow is one booking as the screen lists it.
type bookingRow struct {
	ID, When, Day, Service, Name, Email, Phone, Note, CancelledBy string
	Cancelled, Past                                               bool
}

type weekRow struct{ Key, Label, Spans string }

var dayLabels = map[string]string{"mon": "Monday", "tue": "Tuesday", "wed": "Wednesday", "thu": "Thursday",
	"fri": "Friday", "sat": "Saturday", "sun": "Sunday"}

func (s *Server) handleBookings(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	// Names, addresses and telephone numbers: never kept by a browser.
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Title": "Bookings", "Nav": "bookings", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Bookings == nil {
		data["Unavailable"] = "This build was started without bookings wired in."
		s.render(w, r, "bookings.html", data)
		return
	}
	s.bookingsPage(w, r, p, data, "")
}

// bookingsPage fills and renders the screen; feed is a calendar address
// to show once.
func (s *Server) bookingsPage(w http.ResponseWriter, r *http.Request, p principal, data map[string]any, feed string) {
	setup, err := s.Bookings.Setup()
	if err != nil {
		data["Error"] = err.Error()
	}
	data["CanSetup"] = s.Policy.Evaluate(p.Name, auth.ActPublish, "/").Allowed
	data["FeedURL"] = feed
	shown := setup
	if shown == nil {
		data["Unset"] = true
		shown = &booking.Setup{Zone: "Europe/London", NoticeHours: 2, Week: map[string][]booking.Span{
			"mon": {{From: "09:00", To: "17:00"}}, "tue": {{From: "09:00", To: "17:00"}},
			"wed": {{From: "09:00", To: "17:00"}}, "thu": {{From: "09:00", To: "17:00"}},
			"fri": {{From: "09:00", To: "17:00"}}},
			Services: []booking.Service{{Name: "consultation", Title: "Consultation", Minutes: 30}}}
	}
	data["Setup"] = shown
	var week []weekRow
	for _, d := range booking.Days {
		var spans []string
		for _, sp := range shown.Week[d] {
			spans = append(spans, sp.String())
		}
		week = append(week, weekRow{Key: d, Label: dayLabels[d], Spans: strings.Join(spans, ", ")})
	}
	data["Week"] = week
	data["Closed"] = strings.Join(shown.Closed, "\n")
	data["Ahead"], data["Keep"] = shown.Ahead(), int(shown.Keep()/(24*time.Hour))
	services := append([]booking.Service(nil), shown.Services...)
	for len(services) < len(shown.Services)+2 {
		services = append(services, booking.Service{})
	}
	data["Services"] = services
	if setup != nil {
		loc, lerr := setup.Location()
		if lerr != nil {
			loc = time.UTC
		}
		list, lerr := s.Bookings.List(1, 60)
		if lerr != nil {
			data["Error"] = lerr.Error()
		}
		now := time.Now()
		var rows []bookingRow
		upcoming := 0
		for _, b := range list {
			title := b.When.Service
			if sv, ok := setup.Service(b.When.Service); ok {
				title = sv.Title
			}
			row := bookingRow{ID: b.When.ID, When: b.When.Start.In(loc).Format("15:04"),
				Day: b.When.Start.In(loc).Format("Monday 2 January"), Service: title, Name: b.Who.Name,
				Email: b.Who.Email, Phone: b.Who.Phone, Note: b.Who.Note, Cancelled: !b.When.Live(),
				CancelledBy: b.When.By, Past: b.When.End().Before(now)}
			if !row.Cancelled && !row.Past {
				upcoming++
			}
			rows = append(rows, row)
		}
		data["Rows"], data["Upcoming"] = rows, upcoming
	}
	s.render(w, r, "bookings.html", data)
}

// handleBookingsCalendar is the bookings ahead as a calendar file.
func (s *Server) handleBookingsCalendar(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.Bookings == nil || s.Bookings.Calendar == nil {
		http.NotFound(w, r)
		return
	}
	body, err := s.Bookings.Calendar()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/calendar; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="bookings.ics"`)
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// handleBookingsAct cancels a booking, or changes how the site takes them.
func (s *Server) handleBookingsAct(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.Bookings == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	back := func(msg string, err error) {
		v := "m=" + url.QueryEscape(msg)
		if err != nil {
			v = "e=" + url.QueryEscape(err.Error())
		}
		http.Redirect(w, r, "/bookings?"+v, http.StatusSeeOther)
	}
	do := r.FormValue("do")
	if do == "cancel" {
		erase := r.FormValue("erase") == "1"
		err := s.Bookings.Cancel(r.FormValue("id"), erase, p.actor())
		msg := "Cancelled. The time is free again."
		if erase {
			msg = "Cancelled, and who booked it is forgotten."
		}
		back(msg, err)
		return
	}
	// Everything else changes what the site offers, at once.
	if !s.can(w, r, p, auth.ActPublish, "/") {
		return
	}
	switch do {
	case "pause", "resume":
		setup, err := s.Bookings.Setup()
		if err == nil && setup == nil {
			err = errors.New("this site takes no bookings yet")
		}
		if err != nil {
			back("", err)
			return
		}
		setup.Paused = do == "pause"
		err = s.Bookings.Save(setup, do, p.actor())
		back(map[bool]string{true: "Paused: no new bookings are taken, and those made stand.",
			false: "Bookings are taken again."}[setup.Paused], err)
	case "setup":
		setup, err := setupFromForm(r)
		if err == nil {
			if prior, perr := s.Bookings.Setup(); perr == nil && prior != nil {
				setup.Feed, setup.Paused = prior.Feed, prior.Paused
			}
			err = s.Bookings.Save(setup, "setup", p.actor())
		}
		back("Saved. A page offers these times with a booking section naming a service.", err)
	case "feed", "feed-off":
		if s.Bookings.Feed == nil {
			http.NotFound(w, r)
			return
		}
		addr, err := s.Bookings.Feed(do == "feed-off", p.actor())
		if err != nil || do == "feed-off" {
			back("The calendar feed is off; its address answers nothing now.", err)
			return
		}
		// Shown on this response and nowhere else: not in a redirect, which
		// a browser keeps in its history.
		data := map[string]any{"Title": "Bookings", "Nav": "bookings", "Principal": p}
		s.bookingsPage(w, r, p, data, addr)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

// setupFromForm reads the setup form: the zone, a line of spans a day,
// closed dates a line each, the limits, and a row a service.
func setupFromForm(r *http.Request) (*booking.Setup, error) {
	s := &booking.Setup{Zone: strings.TrimSpace(r.FormValue("zone")), Week: map[string][]booking.Span{}}
	for _, d := range booking.Days {
		for _, part := range strings.Split(r.FormValue("week_"+d), ",") {
			if part = strings.TrimSpace(part); part == "" {
				continue
			}
			sp, err := booking.ParseSpan(part)
			if err != nil {
				return nil, errors.New(dayLabels[d] + ": " + err.Error())
			}
			s.Week[d] = append(s.Week[d], sp)
		}
	}
	for _, line := range strings.Split(r.FormValue("closed"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			s.Closed = append(s.Closed, line)
		}
	}
	num := func(name string) int { n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(name))); return n }
	s.NoticeHours, s.AheadDays, s.KeepDays = num("notice"), num("ahead"), num("keep")
	names, titles := r.Form["svc_name"], r.Form["svc_title"]
	minutes, buffers := r.Form["svc_minutes"], r.Form["svc_buffer"]
	prices, abouts := r.Form["svc_price"], r.Form["svc_about"]
	at := func(list []string, i int) string {
		if i < len(list) {
			return strings.TrimSpace(list[i])
		}
		return ""
	}
	for i := range names {
		name := strings.ToLower(at(names, i))
		if name == "" && at(titles, i) == "" {
			continue
		}
		m, _ := strconv.Atoi(at(minutes, i))
		b, _ := strconv.Atoi(at(buffers, i))
		s.Services = append(s.Services, booking.Service{Name: name, Title: at(titles, i), Minutes: m, Buffer: b,
			Price: at(prices, i), About: at(abouts, i)})
	}
	return s, nil
}
