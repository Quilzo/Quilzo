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
