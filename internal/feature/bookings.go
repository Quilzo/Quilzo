// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/booking"
)

// The bookings block: how the site takes appointments (internal/booking),
// declared by a package so a site built or proposed with its booking page
// arrives able to take bookings. One site has one setup, so one package
// owns it, and a setup somebody made by hand is theirs.

// BookingsRef is the bookings block's ref.
var BookingsRef = Ref{Kind: "bookings", Name: "bookings"}

func validateBookings(p *Package, bad func(string, ...any)) {
	if p.Bookings != nil {
		if err := p.Bookings.Validate(); err != nil {
			bad("bookings: %v", err)
		}
		if p.Bookings.Feed != "" {
			bad("bookings: a package does not carry the owner's calendar address; it is made after install")
		}
	}
	// A page's booking section names a service this package declares, when
	// it declares bookings at all; without the block it names one the site
	// has, which the section says plainly when it has not.
	for _, pg := range p.Pages {
		for _, name := range bookingServices(pg.Body) {
			if p.Bookings != nil {
				if _, ok := p.Bookings.Service(name); !ok {
					bad("page %q books %q, which the bookings block does not offer", pg.Name, name)
				}
			}
		}
	}
}

// bookingServices names the services a page's booking sections book.
func bookingServices(body map[string]any) []string {
	sections, _ := body["sections"].([]any)
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

// bookingsLine is what the card says the block collects.
func bookingsLine(s *booking.Setup) Line {
	var services []string
	for _, sv := range s.Services {
		services = append(services, fmt.Sprintf("%s (%d minutes)", sv.Title, sv.Minutes))
	}
	var open []string
	for _, d := range booking.Days {
		if len(s.Week[d]) > 0 {
			open = append(open, d)
		}
	}
	text := fmt.Sprintf("Takes bookings for %s, on %s time, open %s; asks for a name, an email address and "+
		"optionally a telephone number and a note, kept %d days after the appointment",
		strings.Join(services, ", "), s.Zone, strings.Join(open, ", "), int(s.Keep()/(24*time.Hour)))
	if s.Paused {
		text += "; paused until somebody resumes it"
	}
	return Line{Text: text, Flag: "personal"}
}
