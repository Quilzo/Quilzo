// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package booking

import (
	"strings"
	"time"
	"unicode/utf8"
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

// ICS writes events as an iCalendar file (RFC 5545), which every calendar
// reads: times in UTC, so no zone table has to travel with it, text escaped,
// and long lines folded as the standard says.
func ICS(name string, events []Event, now time.Time) []byte {
	var b strings.Builder
	line := func(s string) { b.WriteString(fold(s)) }
	line("BEGIN:VCALENDAR")
	line("VERSION:2.0")
	line("PRODID:-//Quilzo//Bookings//EN")
	line("CALSCALE:GREGORIAN")
	line("METHOD:PUBLISH")
	if name != "" {
		line("X-WR-CALNAME:" + text(name))
	}
	stamp := now.UTC().Format("20060102T150405Z")
	for _, e := range events {
		line("BEGIN:VEVENT")
		line("UID:" + text(e.UID))
		line("DTSTAMP:" + stamp)
		line("DTSTART:" + e.Start.UTC().Format("20060102T150405Z"))
		line("DTEND:" + e.End.UTC().Format("20060102T150405Z"))
		line("SUMMARY:" + text(e.Summary))
		if e.Description != "" {
			line("DESCRIPTION:" + text(e.Description))
		}
		if e.URL != "" {
			line("URL:" + e.URL)
		}
		if e.Cancelled {
			line("STATUS:CANCELLED")
		} else {
			line("STATUS:CONFIRMED")
		}
		line("END:VEVENT")
	}
	line("END:VCALENDAR")
	return []byte(b.String())
}

// text escapes a value: backslash, semicolon, comma and line breaks.
func text(s string) string {
	s = strings.NewReplacer(`\`, `\\`, ";", `\;`, ",", `\,`, "\r\n", `\n`, "\n", `\n`, "\r", `\n`).Replace(s)
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// fold ends a line with CRLF, breaking it every 75 octets with a space
// at the start of each continuation, never inside a character.
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
