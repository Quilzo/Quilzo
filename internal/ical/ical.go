// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package ical writes calendar files (RFC 5545), which every calendar
// reads: a booking to add, the owner's bookings to subscribe to, a site's
// events.
//
// Times are written in UTC, so no zone table has to travel with the file;
// a day with no time is written as a date, which a calendar shows as all
// day. Text is escaped and long lines folded as the standard says, never
// inside a character.
package ical

import (
	"strings"
	"time"
	"unicode/utf8"
)

// Statuses an event may have.
const (
	Confirmed = "CONFIRMED"
	Tentative = "TENTATIVE"
	Cancelled = "CANCELLED"
)

// Event is one event as a calendar file says it.
type Event struct {
	UID        string
	Start, End time.Time
	// AllDay writes Start and End as dates: End is the day after the last,
	// as the standard counts it.
	AllDay      bool
	Summary     string
	Description string
	Location    string
	URL         string
	// Status is Confirmed when empty.
	Status string
}

// Write is a calendar named name, from product (such as "Bookings").
func Write(name, product string, events []Event, now time.Time) []byte {
	var b strings.Builder
	line := func(s string) { b.WriteString(fold(s)) }
	line("BEGIN:VCALENDAR")
	line("VERSION:2.0")
	line("PRODID:-//Quilzo//" + product + "//EN")
	line("CALSCALE:GREGORIAN")
	line("METHOD:PUBLISH")
	if name != "" {
		line("X-WR-CALNAME:" + Text(name))
	}
	stamp := now.UTC().Format("20060102T150405Z")
	for _, e := range events {
		line("BEGIN:VEVENT")
		line("UID:" + Text(e.UID))
		line("DTSTAMP:" + stamp)
		if e.AllDay {
			line("DTSTART;VALUE=DATE:" + e.Start.Format("20060102"))
			line("DTEND;VALUE=DATE:" + e.End.Format("20060102"))
		} else {
			line("DTSTART:" + e.Start.UTC().Format("20060102T150405Z"))
			// No end is a moment, which a calendar shows at its own
			// default length rather than one made up here.
			if !e.End.IsZero() {
				line("DTEND:" + e.End.UTC().Format("20060102T150405Z"))
			}
		}
		line("SUMMARY:" + Text(e.Summary))
		if e.Description != "" {
			line("DESCRIPTION:" + Text(e.Description))
		}
		if e.Location != "" {
			line("LOCATION:" + Text(e.Location))
		}
		if e.URL != "" {
			line("URL:" + e.URL)
		}
		status := e.Status
		if status == "" {
			status = Confirmed
		}
		line("STATUS:" + status)
		line("END:VEVENT")
	}
	line("END:VCALENDAR")
	return []byte(b.String())
}

// Text escapes a value: backslash, semicolon, comma and line breaks, and
// drops other control characters.
func Text(s string) string {
	s = strings.NewReplacer(`\`, `\\`, ";", `\;`, ",", `\,`, "\r\n", `\n`, "\n", `\n`, "\r", `\n`).Replace(s)
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// fold ends a line with CRLF, breaking it every 75 octets with a space at
// the start of each continuation, never inside a character.
func fold(s string) string {
	var b strings.Builder
	n := 0
	for len(s) > 0 {
		_, size := utf8.DecodeRuneInString(s)
		if n+size > 75 {
			b.WriteString("\r\n ")
			n = 1
		}
		b.WriteString(s[:size])
		n += size
		s = s[size:]
	}
	b.WriteString("\r\n")
	return b.String()
}
