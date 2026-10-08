// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package indicator

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Reading what feeds publish.
//
// Two shapes: a STIX 2.1 bundle, and a list with one value to a line.
//
// STIX carries its indicators as patterns in a small language of its own.
// This reads the part of that language every feed actually uses — one
// thing equals one value, several of those joined by OR — and nothing
// else. A pattern with AND, a time qualifier, a wildcard or a range is
// counted as not read and reported. It is not approximated: "A AND B"
// read as "A" is a different, broader claim than the feed made, and a
// pattern language evaluated in full is an interpreter for text a stranger
// wrote.

// Report is what reading a feed did.
type Report struct {
	// Read is how many indicators were found, Taken how many were new, and
	// Known how many were already held.
	Read  int `json:"read"`
	Taken int `json:"taken"`
	Known int `json:"known"`
	// Refused are the ones that are never indicators, by reason.
	Refused map[string]int `json:"refused,omitempty"`
	// Unread is patterns this does not read, and Lapsed ones whose own
	// end had passed or that the feed revoked.
	Unread int `json:"unread,omitempty"`
	Lapsed int `json:"lapsed,omitempty"`
	// Examples is a few of what was refused, to check the count against.
	Examples []string `json:"examples,omitempty"`
}

func (r *Report) refuse(why, example string) {
	if r.Refused == nil {
		r.Refused = map[string]int{}
	}
	r.Refused[why]++
	if len(r.Examples) < 5 {
		if len(example) > 80 {
			example = example[:80] + "…"
		}
		r.Examples = append(r.Examples, example+": "+why)
	}
}

// Never is how many were refused as things that are never indicators.
func (r Report) Never() int {
	n := 0
	for _, c := range r.Refused {
		n += c
	}
	return n
}

// MaxPerRead bounds how many indicators one read yields.
const MaxPerRead = 200_000

// reason shortens a refusal to the class of thing it is, for counting.
func reason(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "private or local"):
		return "a private or local address"
	case strings.Contains(s, "empty file"):
		return "the digest of the empty file"
	case strings.Contains(s, "single label"):
		return "a single-label name"
	case strings.Contains(s, "shared by"):
		return "a domain shared by many unrelated people"
	case strings.Contains(s, "whole site"):
		return "a URL naming a whole site"
	case strings.Contains(s, "stopped being believed"):
		return "already lapsed"
	}
	return "not a usable value"
}

// ReadList reads one value to a line. Blank lines and lines starting with
// # are skipped; anything after whitespace or a comma on a line is ignored,
// which is how feeds attach their own columns.
func ReadList(in []byte, source string, now time.Time) ([]Indicator, Report, error) {
	var out []Indicator
	var rep Report
	sc := bufio.NewScanner(bytes.NewReader(in))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if i := strings.IndexAny(line, " \t,;"); i > 0 {
			line = line[:i]
		}
		rep.Read++
		if rep.Read > MaxPerRead {
			return nil, rep, fmt.Errorf("more than %d lines", MaxPerRead)
		}
		k, ok := Guess(line)
		if !ok {
			rep.refuse("not a usable value", line)
			continue
		}
		i, err := New(k, line, source, "", time.Time{}, time.Time{}, now)
		if err != nil {
			rep.refuse(reason(err), line)
			continue
		}
		out = append(out, i)
	}
	if err := sc.Err(); err != nil {
		return nil, rep, err
	}
	return out, rep, nil
}

// stixKinds maps the STIX object paths this reads onto kinds.
var stixKinds = map[string]Kind{
	"ipv4-addr:value": IP, "ipv6-addr:value": IP,
	"domain-name:value": Domain, "url:value": URL,
	"email-addr:value":        Email,
	"file:hashes.'SHA-256'":   Hash,
	"file:hashes.'SHA-1'":     Hash,
	"file:hashes.MD5":         Hash,
	"file:hashes.'MD5'":       Hash,
	"file:hashes.\"SHA-256\"": Hash,
	"file:hashes.SHA-256":     Hash,
	"file:hashes.SHA-1":       Hash,
}

type term struct {
	Kind  Kind
	Value string
}

// parsePattern reads [a = 'v'] OR [b = 'w'] and [a = 'v' OR b = 'w'].
// Anything else is not read.
func parsePattern(p string) ([]term, bool) {
	p = strings.TrimSpace(p)
	if p == "" || len(p) > 16<<10 {
		return nil, false
	}
	var out []term
	for p != "" {
		if !strings.HasPrefix(p, "[") {
			return nil, false
		}
		end := closing(p)
		if end < 0 {
			return nil, false
		}
		inner := p[1:end]
		p = strings.TrimSpace(p[end+1:])
		for inner != "" {
			t, rest, ok := comparison(inner)
			if !ok {
				return nil, false
			}
			out = append(out, t)
			rest = strings.TrimSpace(rest)
			if rest == "" {
				break
			}
			if !strings.HasPrefix(rest, "OR ") {
				return nil, false
			}
			inner = strings.TrimSpace(rest[3:])
		}
		if p == "" {
			break
		}
		if !strings.HasPrefix(p, "OR ") {
			// AND, FOLLOWEDBY, WITHIN, REPEATS, START: a narrower claim
			// than any one of its parts.
			return nil, false
		}
		p = strings.TrimSpace(p[3:])
	}
	return out, len(out) > 0 && len(out) <= 1000
}

// closing finds the ] that ends the observation starting at p[0], skipping
// quoted strings.
func closing(p string) int {
	quoted := false
	for i := 1; i < len(p); i++ {
		switch {
		case p[i] == '\\' && quoted:
			i++
		case p[i] == '\'':
			quoted = !quoted
		case p[i] == ']' && !quoted:
			return i
		}
	}
	return -1
}

// comparison reads path = 'value' from the front of s.
func comparison(s string) (term, string, bool) {
	eq := strings.Index(s, "=")
	if eq <= 0 {
		return term{}, "", false
	}
	path := strings.TrimSpace(s[:eq])
	// !=, <=, >= and the word operators all leave something other than a
	// bare path on the left.
	kind, known := stixKinds[path]
	if !known {
		return term{}, "", false
	}
	rest := strings.TrimSpace(s[eq+1:])
	if !strings.HasPrefix(rest, "'") {
		return term{}, "", false
	}
	var val strings.Builder
	for i := 1; i < len(rest); i++ {
		switch rest[i] {
		case '\\':
			if i+1 >= len(rest) {
				return term{}, "", false
			}
			i++
			val.WriteByte(rest[i])
		case '\'':
			return term{kind, val.String()}, rest[i+1:], true
		default:
			val.WriteByte(rest[i])
		}
	}
	return term{}, "", false
}

// ReadSTIX reads the indicators out of a STIX 2.1 bundle.
func ReadSTIX(in []byte, source string, now time.Time) ([]Indicator, Report, error) {
	var bundle struct {
		Type    string            `json:"type"`
		Objects []json.RawMessage `json:"objects"`
	}
	var rep Report
	if err := json.Unmarshal(in, &bundle); err != nil {
		return nil, rep, fmt.Errorf("this is not JSON: %w", err)
	}
	if bundle.Type != "bundle" {
		return nil, rep, fmt.Errorf("this says type %q; a STIX bundle says "+
			"\"bundle\"", bundle.Type)
	}
	var out []Indicator
	for _, raw := range bundle.Objects {
		var o struct {
			Type        string    `json:"type"`
			Name        string    `json:"name"`
			Pattern     string    `json:"pattern"`
			PatternType string    `json:"pattern_type"`
			ValidFrom   time.Time `json:"valid_from"`
			ValidUntil  time.Time `json:"valid_until"`
			Revoked     bool      `json:"revoked"`
		}
		if json.Unmarshal(raw, &o) != nil || o.Type != "indicator" {
			continue
		}
		if o.Revoked || (!o.ValidUntil.IsZero() && !o.ValidUntil.After(now)) {
			rep.Lapsed++
			continue
		}
		if o.PatternType != "" && o.PatternType != "stix" {
			rep.Unread++
			continue
		}
		terms, ok := parsePattern(o.Pattern)
		if !ok {
			rep.Unread++
			continue
		}
		note := o.Name
		if len(note) > 200 {
			note = note[:200]
		}
		for _, t := range terms {
			rep.Read++
			if rep.Read > MaxPerRead {
				return nil, rep, fmt.Errorf("more than %d indicators",
					MaxPerRead)
			}
			i, err := New(t.Kind, t.Value, source, note, o.ValidFrom,
				o.ValidUntil, now)
			if err != nil {
				rep.refuse(reason(err), t.Value)
				continue
			}
			out = append(out, i)
		}
	}
	return out, rep, nil
}
