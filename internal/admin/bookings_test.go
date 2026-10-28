// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/booking"
)

// Bookings lists who booked, cancels for the site, keeps the setup from its
// form, pauses, and shows a calendar address once and never in a redirect.
func TestBookingsScreen(t *testing.T) {
	srv, token := setup(t)
	var saved *booking.Setup
	var cancelled string
	var erased bool
	at := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Minute)
	srv.Bookings = &BookingHooks{
		Setup: func() (*booking.Setup, error) { return saved, nil },
		List: func(back, ahead int) ([]booking.Booking, error) {
			return []booking.Booking{{When: booking.Busy{ID: "20261103-0123456789ab", Service: "cut", Start: at, Minutes: 45,
				Until: at.Add(time.Hour)}, Who: booking.Details{Name: "Ann Example", Email: "ann@example.com",
				Phone: "+44 113 496 0000", Note: "first time"}}}, nil
		},
		Cancel: func(id string, erase bool, _ Actor) error { cancelled, erased = id, erase; return nil },
		Save: func(s *booking.Setup, _ string, _ Actor) error {
			if err := s.Validate(); err != nil {
				return err
			}
			saved = s
			return nil
		},
		Feed: func(off bool, _ Actor) (string, error) { return "https://site.example/book/feed/SECRET.ics", nil },
	}

	page := get(t, srv, "/bookings", token).Body.String()
	if !strings.Contains(page, "takes no bookings yet") || !strings.Contains(page, `name="week_mon"`) {
		t.Fatal("a site with no bookings is not offered the setup")
	}
	whole(t, page)

	code, loc := postFormLoc(t, srv, token, "/bookings/act", url.Values{"do": {"setup"}, "zone": {"Europe/London"},
		"week_tue": {"09:00-12:00, 13:00-17:00"}, "closed": {"2026-12-25\n"}, "notice": {"2"}, "ahead": {"60"}, "keep": {"30"},
		"svc_name": {"cut", ""}, "svc_title": {"Haircut", ""}, "svc_minutes": {"45", ""}, "svc_buffer": {"15", ""},
		"svc_price": {"£30", ""}, "svc_about": {"", ""}})
	if code != http.StatusSeeOther || strings.Contains(loc, "e=") || saved == nil || len(saved.Week["tue"]) != 2 ||
		saved.Services[0].Buffer != 15 || saved.Closed[0] != "2026-12-25" {
		t.Fatalf("saving the setup: %d %s %+v", code, loc, saved)
	}
	if _, loc := postFormLoc(t, srv, token, "/bookings/act", url.Values{"do": {"setup"}, "zone": {"Nowhere/Here"},
		"week_tue": {"17:00-09:00"}}); !strings.Contains(loc, "e=") {
		t.Fatalf("a setup that is not usable was saved: %s", loc)
	}

	page = get(t, srv, "/bookings", token).Body.String()
	if !strings.Contains(page, "Ann Example") || !strings.Contains(page, "mailto:ann@example.com") ||
		!strings.Contains(page, "first time") {
		t.Fatal("who booked is not listed")
	}
	whole(t, page)

	if code, _ := postFormLoc(t, srv, token, "/bookings/act", url.Values{"do": {"cancel"},
		"id": {"20261103-0123456789ab"}, "erase": {"1"}}); code != http.StatusSeeOther || cancelled != "20261103-0123456789ab" || !erased {
		t.Fatalf("cancelling: %d %q %v", code, cancelled, erased)
	}
	if _, loc := postFormLoc(t, srv, token, "/bookings/act", url.Values{"do": {"pause"}}); !saved.Paused || strings.Contains(loc, "e=") {
		t.Fatalf("pausing: %s", loc)
	}

	feed := postForm(t, srv, "/bookings/act", token, url.Values{"do": {"feed"}}.Encode())
	if feed.Code != http.StatusOK || !strings.Contains(feed.Body.String(), "/book/feed/SECRET.ics") ||
		feed.Header().Get("Location") != "" || feed.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("the feed address: %d %q", feed.Code, feed.Header().Get("Location"))
	}
}
