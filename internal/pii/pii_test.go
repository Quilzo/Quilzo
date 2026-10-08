// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package pii

import (
	"strings"
	"testing"
)

func kinds(hits []Hit) string {
	var out []string
	for _, h := range hits {
		out = append(out, string(h.Kind))
	}
	return strings.Join(out, ",")
}

func TestWhatNoPageShouldCarryIsFoundAndShownOnlyInPart(t *testing.T) {
	cases := map[string]string{
		"Card: 4539 1488 0343 6467 please charge it":   "card",
		"amex 3761-234567-89011 on file":               "card",
		"Mastercard 5425233430109903":                  "card",
		"Pay to GB33 BUKB 2020 1555 5555 55 by Friday": "iban",
		"DE75512108001245126199":                       "iban",
		"write to jane.doe@gmail.com about the refund": "email",
		"call +44 20 7946 0958 after six":              "phone",
	}
	for text, want := range cases {
		hits := Scan(text, nil)
		if kinds(hits) != want {
			t.Errorf("%q: %q, want %q", text, kinds(hits), want)
		}
		for _, h := range hits {
			if strings.Contains(text, h.Shown) || strings.Contains(h.Shown, "1488 0343") || strings.Contains(h.Shown, "jane.doe") {
				t.Errorf("%q shows too much: %q", text, h.Shown)
			}
		}
	}
}

func TestOrdinaryNumbersAndTheSitesOwnAddressesAreNot(t *testing.T) {
	for _, text := range []string{
		"Order 4111111111111112 shipped",        // fails Luhn
		"Our phone is 1234 5678 9012 3456",      // no network prefix
		"Price: 1,299.00, SKU 9780306406157",    // an ISBN
		"GB00 WEST 1234 5698 7654 32 is a typo", // fails mod-97
		"Write to hello@shop.example or press@acme.com",
		"Reference 2026-10-05-1234",
		"Test with 4242 4242 4242 4242 and any future date", // a processor's test card
		"The standard's example is GB82 WEST 1234 5698 7654 32",
	} {
		if hits := Scan(text, []string{"acme.com"}); len(hits) != 0 {
			t.Errorf("%q: %+v", text, hits)
		}
	}
	if !Card.Blocking() || IBAN.Blocking() || Email.Blocking() || Phone.Blocking() {
		t.Fatal("which kinds block")
	}
}

func FuzzScan(f *testing.F) {
	f.Add("4111 1111 1111 1111 GB82WEST12345698765432 a@b.co +44 20 7946 0958")
	f.Fuzz(func(t *testing.T, s string) {
		for _, h := range Scan(s, nil) {
			if h.Shown == "" {
				t.Fatal("a finding that says nothing")
			}
		}
	})
}
