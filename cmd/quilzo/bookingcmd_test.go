// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/booking"
	"github.com/quilzo/quilzo/internal/feature"
)

// A setup is set from a file and checked, the feed it had stays its own,
// a reader cannot change it, and who booked is cancelled and forgotten for
// the site, and forgotten after the appointment by the housekeeping.
func TestBookingsFromTheCommandLine(t *testing.T) {
	root, _ := siteStore(t)
	file := filepath.Join(t.TempDir(), "bookings.json")
	body, _ := json.Marshal(bookingExample())
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bookingSetupCmd(root, []string{file}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	s, err := loadBookingSetup(root)
	if err != nil || s == nil || len(s.Services) != 2 {
		t.Fatalf("the setup: %+v %v", s, err)
	}
	if _, err := makeBookingFeed(root, s, false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	feed := s.Feed
	if err := bookingSetupCmd(root, []string{file}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if s, _ = loadBookingSetup(root); s.Feed != feed || feed == "" {
		t.Fatal("setting the hours from a file turned the feed off, or let a file set it")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte(`{"zone":"Europe/London","week":{"mon":["17:00-09:00"]},"services":[]}`), 0o600)
	if err := bookingSetupCmd(root, []string{bad}, asAdmin("dana")); err == nil {
		t.Fatal("a span that ends before it starts was kept")
	}
	reader := human("rae")
	reader.Role = "reader"
	if err := saveBookingSetup(root, s, reader, "setup"); err == nil {
		t.Fatal("a reader changed how the site takes bookings")
	}

	book, err := openBookings(root)
	if err != nil {
		t.Fatal(err)
	}
	visit, _ := s.Service("visit")
	now := time.Now()
	days, err := booking.Free(s, visit, nil, now)
	if err != nil || len(days) == 0 {
		t.Fatalf("no free times: %v", err)
	}
	x, _, err := book.Reserve(s, visit, days[0].Slots[0].Start, now, booking.Details{Name: "Ann Example", Email: "ann@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cancelBooking(root, x.ID, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if c, _ := book.Find(x.ID); c.Live() || c.By != "site" {
		t.Fatalf("cancelled for the site: %+v", c)
	}
	if _, err := book.ReadDetails(x.ID); !errors.Is(err, booking.ErrNotFound) {
		t.Fatal("erased, who booked is still kept")
	}
	ics, err := bookingCalendar(root)
	if err != nil || !strings.Contains(string(ics), "BEGIN:VCALENDAR") {
		t.Fatalf("the calendar file: %v", err)
	}

	// Housekeeping forgets who booked a while after the appointment.
	y, _, err := book.Reserve(s, visit, days[0].Slots[1].Start, now, booking.Details{Name: "Bo", Email: "bo@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	job, ok := retentionJob(root)
	if !ok {
		t.Fatal("no retention job")
	}
	if _, err := job.Do(y.End().Add(s.Keep() + time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := book.ReadDetails(y.ID); !errors.Is(err, booking.ErrNotFound) {
		t.Fatal("who booked outlived the site's keep")
	}
}

// A package can bring its bookings: the card says what it collects and two
// people approve it; it is the site's setup once installed; an upgrade
// keeps the owner's calendar address and their pause; taking it away stops
// new bookings; and a setup somebody made by hand is theirs.
func TestAPackageBringsItsBookings(t *testing.T) {
	root, _ := siteStore(t)
	pkgWith := func(version string, edit func(*feature.Package)) string {
		p := feature.Package{Format: feature.Format, Name: "salon-bookings", Version: version, Title: "Salon bookings",
			Purpose: "Haircuts booked on the site.", Bookings: bookingExample(),
			Pages: []feature.Page{{Name: "book", Body: map[string]any{"title": "Book", "sections": []any{
				map[string]any{"booking": map[string]any{"title": "Book", "service": "consultation"}}}}}}}
		if edit != nil {
			edit(&p)
		}
		b, _ := json.Marshal(p)
		path := filepath.Join(t.TempDir(), "pkg.json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	p, _, err := readFeature(root, pkgWith("1.0", nil), "")
	if err != nil {
		t.Fatal(err)
	}
	if c := p.MakeCard(); c.Approvers != 2 || len(c.Collects) != 1 || !strings.Contains(c.Collects[0].Text, "Takes bookings for Consultation (30 minutes)") {
		t.Fatalf("the card: %+v", c)
	}
	if _, _, err := readFeature(root, pkgWith("1.0", func(p *feature.Package) {
		p.Pages[0].Body["sections"] = []any{map[string]any{"booking": map[string]any{"service": "massage"}}}
	}), ""); err == nil || !strings.Contains(err.Error(), "does not offer") {
		t.Fatalf("a page booking a service the package does not offer: %v", err)
	}
	if _, _, err := readFeature(root, pkgWith("1.0", func(p *feature.Package) { p.Bookings.Feed = strings.Repeat("a", 64) }), ""); err == nil {
		t.Fatal("a package carried a calendar address")
	}

	if err := installFeatureFile(root, pkgWith("1.0", nil), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	approveWaiting(t, root, "sam")
	s, err := loadBookingSetup(root)
	if err != nil || s == nil || len(s.Services) != 2 {
		t.Fatalf("installed, the setup is %+v %v", s, err)
	}
	s.Paused = true
	if _, err := makeBookingFeed(root, s, false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	feed := s.Feed
	if err := installFeatureFile(root, pkgWith("1.1", func(p *feature.Package) { p.Bookings.NoticeHours = 24 }), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	approveWaiting(t, root, "sam")
	if s, _ = loadBookingSetup(root); s.NoticeHours != 24 || s.Feed != feed || !s.Paused {
		t.Fatalf("upgraded, the setup is %+v", s)
	}
	if err := removeFeature(root, "salon-bookings", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if s, _ = loadBookingSetup(root); s != nil {
		t.Fatal("removed, the package's setup stays")
	}

	// By hand first: the package does not take it over.
	if err := saveBookingSetup(root, bookingExample(), asAdmin("dana"), "setup"); err != nil {
		t.Fatal(err)
	}
	if err := installFeatureFile(root, pkgWith("2.0", nil), "", "", asAdmin("dana")); err == nil ||
		!strings.Contains(err.Error(), "made by a person") {
		t.Fatalf("over a setup made by hand: %v", err)
	}
}

// The site crew sees the free times visitors see, and never who booked.
func TestAnAgentSeesTheFreeTimes(t *testing.T) {
	root, _ := siteStore(t)
	call := siteCrew(t, root)
	if got := call("quilzo_read", "booking_times", nil); got["bookings"] != false {
		t.Fatalf("no setup: %v", got)
	}
	if err := saveBookingSetup(root, bookingExample(), asAdmin("dana"), "setup"); err != nil {
		t.Fatal(err)
	}
	got := call("quilzo_read", "booking_times", map[string]any{"days": 14})
	services, _ := got["services"].([]any)
	if got["zone"] != "Europe/London" || len(services) != 2 {
		t.Fatalf("the free times: %v", got)
	}
	first := services[0].(map[string]any)
	if free, _ := first["free"].([]any); len(free) == 0 {
		t.Fatalf("no free days in a fortnight: %v", first)
	}
}
