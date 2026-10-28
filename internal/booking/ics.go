// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package booking

import (
	"time"

	"github.com/quilzo/quilzo/internal/ical"
)

// Event is one appointment as a calendar file says it.
type Event struct {
	UID         string
	Start, End  time.Time
	Summary     string
	Description string
	URL         string
	Cancelled   bool
}

// ICS writes events as an iCalendar file (internal/ical).
func ICS(name string, events []Event, now time.Time) []byte {
	out := make([]ical.Event, len(events))
	for i, e := range events {
		out[i] = ical.Event{UID: e.UID, Start: e.Start, End: e.End, Summary: e.Summary,
			Description: e.Description, URL: e.URL, Status: ical.Confirmed}
		if e.Cancelled {
			out[i].Status = ical.Cancelled
		}
	}
	return ical.Write(name, "Bookings", out, now)
}
