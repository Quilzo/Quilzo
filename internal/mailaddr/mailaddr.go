// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package mailaddr is the one judgement of whether text is an email
// address a visitor could be written to.
//
// A public form, a booking, the newsletter's sign-up and a record's email
// field each had a rule, and no two agreed. The same visitor sent the
// wholesale form from an address the newsletter would not take (a local
// part of 70 characters), joined the newsletter from one no record could
// hold ("x4quote"@example.org), and put on the list an address nothing can
// deliver to that the form refused (x4dot@.example.org). Each surface
// keeps its own words for a refusal; what it refuses is this.
//
// It is a scan, not a pattern, and it is the strictest rule the four had
// in common rather than RFC 5322's: quoted local parts, comments and
// display names are things a person types into a mail client, not into a
// form, and every one of them is a way for an address that reads one way
// to be something else in a header.
package mailaddr

import (
	"strings"
	"unicode"
)

// Bounds from RFC 5321: a mailbox's local part is at most 64 octets and a
// path at most 256, which leaves 254 for the address.
const (
	MaxLocal = 64
	MaxLen   = 254
)

// Valid reports whether addr is an address: one @, a local part of 1 to
// 64 bytes, a domain whose first label is not empty and which has a dot
// with something after it, at most 254 bytes in all, and no space, control,
// angle bracket or double quote anywhere.
func Valid(addr string) bool {
	if len(addr) > MaxLen {
		return false
	}
	at := strings.IndexByte(addr, '@')
	if at < 1 || at > MaxLocal {
		return false
	}
	domain := addr[at+1:]
	if strings.IndexByte(domain, '@') >= 0 {
		return false
	}
	if dot := strings.IndexByte(domain, '.'); dot < 1 || dot == len(domain)-1 {
		return false
	}
	return !strings.ContainsFunc(addr, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || r == '<' || r == '>' || r == '"'
	})
}
