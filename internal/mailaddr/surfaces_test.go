// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mailaddr_test

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/booking"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/schema"
)

// A form, a booking, a sign-up and a record's email field take the same
// addresses and refuse the same ones.
//
// They had four rules. One visitor could send the wholesale form from an
// address the newsletter would not take (a local part of 70 characters),
// join the newsletter from one no record could hold ("x4quote"@example.org)
// and put on the list an address nothing can deliver to and the form
// refuses (x4dot@.example.org).
func TestAFormABookingASignUpAndARecordAcceptTheSameAddresses(t *testing.T) {
	long := "x4" + strings.Repeat("a", 70) + "@example.org"
	for _, c := range []struct {
		addr string
		ok   bool
	}{
		{"x4@example.org", true},
		{"first.last+tag@shop.example.co.uk", true},
		{strings.Repeat("a", 64) + "@example.org", true},
		{long, false},
		{`"x4quote"@example.org`, false},
		{"x4dot@.example.org", false},
		{"x4@example", false},
		{"x4@example.", false},
		{"two@at@example.org", false},
		{"<x4@example.org>", false},
		{"x4 @example.org", false},
		{"@example.org", false},
		{"x4@" + strings.Repeat("d", 250) + ".org", false},
	} {
		surfaces := map[string]bool{
			"a form":           acceptsForm(t, c.addr),
			"a booking":        acceptsBooking(c.addr),
			"the newsletter":   acceptsNewsletter(c.addr),
			"a record's field": acceptsRecord(c.addr),
		}
		for name, ok := range surfaces {
			if ok != c.ok {
				t.Errorf("%s: %q accepted %v, want %v", name, c.addr, ok, c.ok)
			}
		}
	}
}

func acceptsForm(t *testing.T, addr string) bool {
	f := &form.Form{Name: "wholesale", Fields: []form.Field{{Name: "email", Label: "Email", Kind: form.Email, Required: true}}}
	_, err := form.AcceptShare(f, map[string]string{"email": addr}, "test", time.Now())
	return err == nil
}

func acceptsBooking(addr string) bool {
	d := booking.Details{Name: "Visitor", Email: addr}
	return d.Clean() == nil
}

func acceptsNewsletter(addr string) bool {
	_, err := newsletter.Normalize(addr)
	return err == nil
}

func acceptsRecord(addr string) bool {
	lead := schema.Type{Name: "lead", Fields: []schema.Field{{Name: "email", Kind: schema.Email}}}
	return len(schema.Validate(lead, map[string]any{"email": addr})) == 0
}
