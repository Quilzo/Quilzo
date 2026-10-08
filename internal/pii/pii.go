// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package pii finds personal data in text before it is published.
//
// Two kinds of finding, because a gate that refuses everything is a gate
// people switch off. What no published page should carry is blocking: a
// payment card number, the right length for its network and passing the
// Luhn check, so a price or an order number is not one. What a page often
// carries on purpose is advisory: a bank account as an IBAN (passing its
// mod-97 check), since a charity's donation page and a business's invoice
// details print their own; an email address and a telephone number, since a
// contact page lists them. A page pasted from a support ticket lists the
// customer's, and somebody should look before it goes out.
//
// Credentials are internal/codescan's, which the publish gate runs beside
// this: one list of what a key looks like, not two.
//
// The numbers payment and banking documentation publishes to be copied —
// the networks' test cards, the standard's example IBANs — are nobody's,
// the way example.com is nobody's, and pass.
//
// Nothing found is ever printed whole: a finding names the kind and the
// last few characters, so the report about the leak is not the leak.
package pii

import (
	"regexp"
	"strings"
	"unicode"
)

// Kind is what was found.
type Kind string

const (
	Card  Kind = "card"
	IBAN  Kind = "iban"
	Email Kind = "email"
	Phone Kind = "phone"
)

// Blocking says a kind no published page should carry.
func (k Kind) Blocking() bool { return k == Card }

// Hit is one finding.
type Hit struct {
	Kind Kind
	// Shown is the finding with all but its end masked.
	Shown string
}

var (
	reCardish = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
	reIBANish = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b`)
	reEmail   = regexp.MustCompile(`\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b`)
	rePhone   = regexp.MustCompile(`\+\d{1,3}[ .-]?\(?\d{1,4}\)?(?:[ .-]?\d{2,4}){2,4}\b`)
)

// Scan finds personal data and secrets in text. allowed are email domains
// that are the site's own, which a contact page is meant to show.
func Scan(text string, allowed []string) []Hit {
	var out []Hit
	for _, m := range reCardish.FindAllString(text, -1) {
		digits := onlyDigits(m)
		if isCard(digits) && !testCards[digits] {
			out = append(out, Hit{Kind: Card, Shown: "a card number ending " + digits[len(digits)-4:]})
		}
	}
	for _, m := range reIBANish.FindAllString(text, -1) {
		compact := strings.ReplaceAll(m, " ", "")
		if validIBAN(compact) && !exampleIBANs[compact] {
			out = append(out, Hit{Kind: IBAN, Shown: "a bank account (IBAN) ending " + compact[len(compact)-4:]})
		}
	}
	if locs, names := nationalIDs(text); len(locs) > 0 {
		for i, l := range locs {
			d := strings.Map(func(r rune) rune {
				if unicode.IsLetter(r) || unicode.IsDigit(r) {
					return r
				}
				return -1
			}, text[l[0]:l[1]])
			out = append(out, Hit{Kind: NationalID, Shown: names[i] + " ending " + d[len(d)-3:]})
		}
	}
	for _, m := range reEmail.FindAllString(text, -1) {
		domain := strings.ToLower(m[strings.LastIndexByte(m, '@')+1:])
		if ownDomain(domain, allowed) {
			continue
		}
		local := m[:strings.IndexByte(m, '@')]
		out = append(out, Hit{Kind: Email, Shown: "the email address " + local[:min(1, len(local))] + "…@" + domain})
	}
	for _, m := range rePhone.FindAllString(text, -1) {
		digits := onlyDigits(m)
		if len(digits) >= 9 && len(digits) <= 15 {
			out = append(out, Hit{Kind: Phone, Shown: "a telephone number ending " + digits[len(digits)-3:]})
		}
	}
	return out
}

func ownDomain(domain string, allowed []string) bool {
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" && (domain == a || strings.HasSuffix(domain, "."+a)) {
			return true
		}
	}
	// Addresses documentation and examples use, which are nobody's.
	return domain == "example.com" || domain == "example.org" || domain == "example.net" ||
		strings.HasSuffix(domain, ".example") || strings.HasSuffix(domain, ".test") || strings.HasSuffix(domain, ".invalid")
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isCard reports a number with a card network's prefix and length that
// passes the Luhn check.
func isCard(d string) bool {
	n := len(d)
	ok := false
	switch {
	case strings.HasPrefix(d, "4"):
		ok = n == 13 || n == 16 || n == 19 // Visa
	case prefixIn(d, 2, 51, 55) || prefixIn(d, 4, 2221, 2720):
		ok = n == 16 // Mastercard
	case strings.HasPrefix(d, "34") || strings.HasPrefix(d, "37"):
		ok = n == 15 // American Express
	case strings.HasPrefix(d, "6011") || strings.HasPrefix(d, "65") || prefixIn(d, 3, 644, 649):
		ok = n == 16 || n == 19 // Discover
	case prefixIn(d, 4, 3528, 3589):
		ok = n >= 16 && n <= 19 // JCB
	case strings.HasPrefix(d, "62"):
		ok = n >= 16 && n <= 19 // UnionPay
	}
	return ok && luhn(d)
}

func prefixIn(d string, width, lo, hi int) bool {
	if len(d) < width {
		return false
	}
	v := 0
	for _, c := range d[:width] {
		v = v*10 + int(c-'0')
	}
	return v >= lo && v <= hi
}

func luhn(d string) bool {
	sum, double := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		v := int(d[i] - '0')
		if double {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		double = !double
	}
	return sum%10 == 0
}

// validIBAN checks an IBAN's mod-97: the country and check digits moved to
// the end, letters as two digits, the whole number's remainder by 97 is 1.
func validIBAN(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rotated := s[4:] + s[:4]
	rem := 0
	for _, r := range rotated {
		switch {
		case r >= '0' && r <= '9':
			rem = (rem*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			v := int(r-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// testCards are the numbers the card networks and the payment processors
// publish for testing; documentation prints them so they can be copied.
var testCards = setOf(
	"4111111111111111", "4242424242424242", "4012888888881881", "4222222222222",
	"4000056655665556", "4000000000000002", "4000000000009995", "4000002500003155",
	"5555555555554444", "5105105105105100", "2223003122003222", "5200828282828210",
	"378282246310005", "371449635398431", "378734493671000",
	"6011111111111117", "6011000990139424", "6011000000000004",
	"3530111333300000", "3566002020360505", "3566111111111113",
	"6200000000000005",
)

// exampleIBANs are the ones the standard and the banks' guides print.
var exampleIBANs = setOf(
	"GB82WEST12345698765432", "GB29NWBK60161331926819", "DE89370400440532013000",
	"FR1420041010050500013M02606", "NL91ABNA0417164300", "ES9121000418450200051332",
	"IT60X0542811101000000123456", "BE68539007547034", "CH9300762011623852957",
)

func setOf(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}
