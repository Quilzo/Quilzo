// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package attest is the public attestation page: the reports and
// certificates an organisation holds, the periods they cover, who issued
// them, and the policies in force. Nothing else.
//
// # Attestations only
//
// A trust page is read by a prospective customer's security team, and what
// they can rely on is what somebody independent put their name to: a SOC 2
// report for a period, an ISO/IEC 27001 certificate from a certification
// body, the policies the organisation approved. A live figure -- controls
// passing, risks treated, a score -- is an operational metric, true for an
// afternoon and read as a promise, and it belongs behind a non-disclosure
// agreement with the context that makes it mean something. So the file this
// page is drawn from has no field that could hold one, refuses a field it
// does not know, and refuses a percentage or a count of controls written
// into a description, which is where a figure goes when there is no field
// for it.
//
// # Where the file comes from
//
// The admin publishes it: a small typed file (File), set from the command
// line or the admin's Public instance screen, published by two people
// (cmd/quilzo attestcmd.go) and sent to the public instance in a signed
// transfer (internal/outpost). It is written by people, never by a model:
// every value on the page is one a person typed and two people published.
//
// A later theme feeds it from the register, the security record's typed
// store, once that is in this tree: the reports held become its Evidence
// and Decision records, with their periods and issuers, and this file
// becomes their projection, made by code. The format is the contract between the two and
// is meant to stay as it is: a producer writes Format 1 and these fields,
// and Validate is the check every producer's output passes before it is
// published.
//
// # The words it will not say
//
// "Compliant" and "certified" are refused through internal/brand unless an
// attestation backs them (Claims): the page's own words never use either.
package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/brand"
	"github.com/quilzo/quilzo/internal/plaintext"
)

// The kinds of attestation.
const (
	// Report is an auditor's report on controls over a period: a SOC 2
	// Type II report, an ISAE 3402 report. It is an opinion, not a
	// certificate, and the page says it is held, not what it found.
	Report = "report"
	// Certificate is a certification body's certificate, with the period
	// it is valid for: ISO/IEC 27001, ISO/IEC 42001.
	Certificate = "certificate"
)

// MaxBytes bounds a file, which is a page's worth of facts and not a
// document store.
const MaxBytes = 64 << 10

// File is what the public attestation page is drawn from.
type File struct {
	// Format is this layout's version: 1.
	Format int `json:"format"`
	// Organisation is whose page it is.
	Organisation string `json:"organisation"`
	// Contact is where to ask for a report that is available on request:
	// an address or a page, as the organisation states it.
	Contact      string        `json:"contact,omitempty"`
	Attestations []Attestation `json:"attestations"`
	Policies     []Policy      `json:"policies"`
}

// Attestation is one report or certificate held.
type Attestation struct {
	// ID names it in the file, so a change to one is a change to that one.
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Title is what it is: "SOC 2 Type II report".
	Title string `json:"title"`
	// Framework is what it attests against, as its issuer names it.
	Framework string `json:"framework"`
	// PeriodStart and PeriodEnd are the period it covers (a report) or is
	// valid for (a certificate), as dates.
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`
	// Issuer is the auditor or the certification body.
	Issuer string `json:"issuer"`
	// Issued is the date of the report or the certificate.
	Issued string `json:"issued"`
	// Expires is a certificate's expiry, when it has one.
	Expires string `json:"expires,omitempty"`
	// Scope is what it covers, in a sentence.
	Scope string `json:"scope,omitempty"`
	// Available is how somebody obtains it: "on request, under a
	// non-disclosure agreement".
	Available string `json:"available,omitempty"`
}

// Policy is one policy in force.
type Policy struct {
	Title    string `json:"title"`
	Version  string `json:"version"`
	Approved string `json:"approved"`
}

// Parse reads a file strictly and checks it at now: a field it does not
// know is refused, because a field nobody checks is where a figure would go.
func Parse(body []byte, now time.Time) (*File, error) {
	if len(body) > MaxBytes {
		return nil, fmt.Errorf("the attestations are %d bytes, and a page of them is at most %d", len(body), MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	f := &File{}
	if err := dec.Decode(f); err != nil {
		return nil, fmt.Errorf("the attestations do not parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("the attestations are followed by something else")
	}
	if err := f.Validate(now); err != nil {
		return nil, err
	}
	return f, nil
}

// Encode is the file as it is stored and sent.
func (f *File) Encode() ([]byte, error) {
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// Digest names the file's content, so a publication approved for one file
// cannot send another.
func (f *File) Digest() string {
	body, _ := json.Marshal(f)
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var (
	reID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)
	// reFigure is an operational figure written into words: a percentage,
	// or a count of things against a total.
	reFigure = regexp.MustCompile(`(?i)\d\s*(%|per\s*cent\b|percent\b)|\b\d+\s+(of|out\s+of)\s+\d+\b`)
)

// Validate checks a file at now and says everything that is wrong with it.
func (f *File) Validate(now time.Time) error {
	var bad []string
	add := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }
	if f.Format != 1 {
		add("format is %d, and this reads format 1", f.Format)
	}
	text := func(where, v string, max int, required bool) {
		switch {
		case strings.TrimSpace(v) == "":
			if required {
				add("%s is empty", where)
			}
			return
		case utf8.RuneCountInString(v) > max:
			add("%s is longer than %d characters", where, max)
		case !utf8.ValidString(v):
			add("%s is not text", where)
		}
		for _, r := range v {
			if unicode.IsControl(r) {
				add("%s holds a control character", where)
				break
			}
			if turnsRound(r) {
				add("%s holds a character that sets the direction of the text after it, which can show "+
					"letters in another order than they are written: what a reader sees would not be what "+
					"was checked", where)
				break
			}
		}
		if m := reFigure.FindString(shown(v)); m != "" {
			add("%s holds the figure %q: the public page carries attestations only, and an operational "+
				"figure belongs where its context is, under a non-disclosure agreement", where, m)
		}
	}
	date := func(where, v string, required bool) (time.Time, bool) {
		if v == "" {
			if required {
				add("%s is empty", where)
			}
			return time.Time{}, false
		}
		d, err := time.Parse(time.DateOnly, v)
		if err != nil {
			add("%s is %q, and a date is written YYYY-MM-DD", where, v)
			return time.Time{}, false
		}
		return d, true
	}
	text("organisation", f.Organisation, 120, true)
	text("contact", f.Contact, 200, false)
	if len(f.Attestations) > 50 {
		add("there are %d attestations, and a page lists at most 50", len(f.Attestations))
	}
	if len(f.Policies) > 200 {
		add("there are %d policies, and a page lists at most 200", len(f.Policies))
	}
	seen := map[string]bool{}
	for i, a := range f.Attestations {
		where := fmt.Sprintf("attestation %d", i+1)
		if a.ID != "" {
			where = "attestation " + a.ID
		}
		if !reID.MatchString(a.ID) {
			add("%s: its id %q is not lower-case letters, digits and hyphens", where, a.ID)
		}
		if seen[a.ID] {
			add("%s: two attestations have this id", where)
		}
		seen[a.ID] = true
		if a.Kind != Report && a.Kind != Certificate {
			add("%s: its kind is %q, and it is a report or a certificate", where, a.Kind)
		}
		text(where+": its title", a.Title, 120, true)
		text(where+": its framework", a.Framework, 120, true)
		text(where+": its issuer", a.Issuer, 120, true)
		text(where+": its scope", a.Scope, 300, false)
		text(where+": how it is available", a.Available, 200, false)
		start, okS := date(where+": the start of its period", a.PeriodStart, true)
		end, okE := date(where+": the end of its period", a.PeriodEnd, true)
		issued, okI := date(where+": the date it was issued", a.Issued, true)
		expires, okX := date(where+": its expiry", a.Expires, false)
		if okS && okE && end.Before(start) {
			add("%s: its period ends before it starts", where)
		}
		if okI && issued.After(now) {
			add("%s: it was issued on %s, which has not come yet", where, a.Issued)
		}
		if okX && okI && expires.Before(issued) {
			add("%s: it expires before it was issued", where)
		}
		if a.Kind == Report && a.Expires != "" {
			add("%s: a report covers a period and does not expire; a certificate does", where)
		}
	}
	for i, p := range f.Policies {
		where := fmt.Sprintf("policy %d", i+1)
		if p.Title != "" {
			where = "policy " + clip(p.Title, 40)
		}
		text(where+": its title", p.Title, 120, true)
		text(where+": its version", p.Version, 20, true)
		if appr, ok := date(where+": the date it was approved", p.Approved, true); ok && appr.After(now) {
			add("%s: it was approved on %s, which has not come yet", where, p.Approved)
		}
	}
	for _, c := range f.Claims(now) {
		add("%s: %q — %s", c.Where, c.Term, c.Why)
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("the attestations are not publishable:\n  %s", strings.Join(bad, "\n  "))
}

// shown is text as a reader sees it, without the characters that show
// nothing: the format characters (a soft hyphen, a zero-width space, a word
// joiner), the variation selectors and the combining grapheme joiner. Text
// pasted from a word processor carries them, and one inside "compliant" or
// between a figure and its percent sign would otherwise hide the word or
// the figure from the checks, while the page showed it whole.
func shown(v string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Variation_Selector, r) || r == 0x34f {
			return -1
		}
		return r
	}, v)
}

// turnsRound reports a character that sets the direction of the text after
// it: the embeddings and overrides (U+202A to U+202E) and the isolates
// (U+2066 to U+2069). An override shows Latin letters backwards, so
// "tnailpmoc" is read as the word it is not. The marks right-to-left text
// needs (U+200E, U+200F and U+061C) turn no letter round, and are taken.
func turnsRound(r rune) bool { return r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 }

// Current reports whether an attestation is in force at now: a report once
// issued, a certificate until it expires.
func (a Attestation) Current(now time.Time) bool {
	issued, err := time.Parse(time.DateOnly, a.Issued)
	if err != nil || issued.After(now) {
		return false
	}
	if a.Expires == "" {
		return true
	}
	expires, err := time.Parse(time.DateOnly, a.Expires)
	return err == nil && !now.After(expires.Add(24*time.Hour-time.Nanosecond))
}

// Claims is every use of "compliant" or "certified" that nothing in the
// file backs, found by internal/brand's attestation rules: each attestation
// in force carries the attestation field, a certificate in force the
// certificate field too, and the organisation and the policies carry
// neither.
func (f *File) Claims(now time.Time) []brand.Finding {
	rules := brand.AttestationRules()
	var out []brand.Finding
	// Checked as a reader sees each value (shown), so a character that
	// shows nothing does not split a word past the rule.
	out = append(out, rules.Check("the organisation", map[string]any{
		"organisation": shown(f.Organisation), "contact": shown(f.Contact)})...)
	for _, a := range f.Attestations {
		content := map[string]any{"title": shown(a.Title), "framework": shown(a.Framework),
			"issuer": shown(a.Issuer), "scope": shown(a.Scope), "available": shown(a.Available)}
		if a.Current(now) {
			content[brand.AttestationNeeds] = a.ID
			if a.Kind == Certificate {
				content[brand.CertificateNeeds] = a.ID
			}
		}
		out = append(out, rules.Check("attestation "+a.ID, content)...)
	}
	for _, p := range f.Policies {
		out = append(out, rules.Check("policy "+clip(p.Title, 40), map[string]any{
			"title": shown(p.Title), "version": shown(p.Version)})...)
	}
	return out
}

// clip shortens a title for a message that names it.
func clip(s string, n int) string { return plaintext.Clip(s, n, "…") }
