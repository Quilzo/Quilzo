// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package pii

import (
	"fmt"
	"sort"
	"strings"
)

// Secret is a credential, found by internal/codescan's rules.
const Secret Kind = "secret"

// Masker takes personal data out of text before it leaves for a model, and
// puts it back into what the model answers.
//
// Each value becomes a placeholder like <quilzo:email:1>, the same one
// every time the same value appears, so the model can still tell "the same
// customer" from "another customer" and refer to either; the placeholders
// are swapped back on this side, so the answer reads as if nothing had been
// taken out. The model never sees a value. What leaves is counted by kind
// and never named, so the record of what was masked is not the leak.
//
// A payment card number and a credential are masked for every route, a
// route that may receive personal data included: neither is anybody's
// business in a prompt. Bank accounts, email addresses and telephone
// numbers are masked for a route that may not.
type Masker struct {
	// Allowed are the site's own email domains, published on purpose.
	Allowed []string
	// Secrets finds credentials (codescan.SecretSpans).
	Secrets func(string) [][2]int

	values  map[string]string // placeholder → value
	byValue map[string]string // kind:value → placeholder
	next    map[Kind]int
	Counts  map[Kind]int
}

type span struct {
	start, end int
	kind       Kind
}

// Mask is text with what may not leave replaced. personal says the route
// may receive personal data.
func (m *Masker) Mask(text string, personal bool) string {
	var spans []span
	add := func(locs [][]int, kind Kind, ok func(string) bool) {
		for _, l := range locs {
			if ok == nil || ok(text[l[0]:l[1]]) {
				spans = append(spans, span{l[0], l[1], kind})
			}
		}
	}
	add(reCardish.FindAllStringIndex(text, -1), Card, func(s string) bool {
		d := onlyDigits(s)
		return isCard(d) && !testCards[d]
	})
	if m.Secrets != nil {
		for _, s := range m.Secrets(text) {
			spans = append(spans, span{s[0], s[1], Secret})
		}
	}
	if !personal {
		add(reIBANish.FindAllStringIndex(text, -1), IBAN, func(s string) bool {
			c := strings.ReplaceAll(s, " ", "")
			return validIBAN(c) && !exampleIBANs[c]
		})
		add(reEmail.FindAllStringIndex(text, -1), Email, func(s string) bool {
			return !ownDomain(strings.ToLower(s[strings.LastIndexByte(s, '@')+1:]), m.Allowed)
		})
		add(rePhone.FindAllStringIndex(text, -1), Phone, func(s string) bool {
			d := onlyDigits(s)
			return len(d) >= 9 && len(d) <= 15
		})
	}
	if len(spans) == 0 {
		return text
	}
	// The earliest first and, where two overlap, the longer: a credential
	// containing something shaped like a phone number is one credential.
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	var b strings.Builder
	at := 0
	for _, s := range spans {
		if s.start < at {
			continue
		}
		b.WriteString(text[at:s.start])
		b.WriteString(m.placeholder(s.kind, text[s.start:s.end]))
		at = s.end
	}
	b.WriteString(text[at:])
	return b.String()
}

func (m *Masker) placeholder(kind Kind, value string) string {
	if m.values == nil {
		m.values, m.byValue, m.next, m.Counts = map[string]string{}, map[string]string{}, map[Kind]int{}, map[Kind]int{}
	}
	key := string(kind) + ":" + value
	if p, ok := m.byValue[key]; ok {
		return p
	}
	m.next[kind]++
	m.Counts[kind]++
	p := fmt.Sprintf("<quilzo:%s:%d>", kind, m.next[kind])
	m.byValue[key], m.values[p] = p, value
	return p
}

// Restore puts the values back into what came back.
func (m *Masker) Restore(text string) string {
	if len(m.values) == 0 {
		return text
	}
	pairs := make([]string, 0, 2*len(m.values))
	for p, v := range m.values {
		pairs = append(pairs, p, v)
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

// Masked is how many of each kind were taken out, for a record that names
// no value.
func (m *Masker) Masked() map[string]int {
	out := map[string]int{}
	for k, n := range m.Counts {
		out[string(k)] = n
	}
	return out
}
