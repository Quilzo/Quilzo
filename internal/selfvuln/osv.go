// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package selfvuln

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// The part of the OSV schema (https://ossf.github.io/osv-schema/) the Go
// vulnerability database's standard-library records use, and nothing
// else: this reads one database about one program.

// Record is one advisory.
type Record struct {
	ID        string     `json:"id"`
	Modified  time.Time  `json:"modified,omitzero"`
	Published time.Time  `json:"published,omitzero"`
	Withdrawn *time.Time `json:"withdrawn,omitempty"`
	Aliases   []string   `json:"aliases,omitempty"`
	Summary   string     `json:"summary,omitempty"`
	Details   string     `json:"details,omitempty"`
	Affected  []Affected `json:"affected,omitempty"`
	Refs      []Ref      `json:"references,omitempty"`
}

// Affected is one package and the versions of it a record applies to.
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []VRange `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
	// Specific is what the Go database adds: the affected symbols. Kept raw
	// and read leniently, so a shape this does not expect cannot make the
	// rest of the record unreadable.
	Specific json.RawMessage `json:"ecosystem_specific,omitempty"`
}

// Specific is the Go database's ecosystem_specific.
type Specific struct {
	Imports []struct {
		Path    string   `json:"path"`
		Symbols []string `json:"symbols,omitempty"`
	} `json:"imports,omitempty"`
}

// Package names something in an ecosystem.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// VRange is a run of affected versions, as an ordered list of events in
// which each introduced opens a run that the next fixed or last_affected
// closes. Introduced "0" with no fixed is every version, none safe yet.
type VRange struct {
	Type   string  `json:"type"`
	Events []Event `json:"events,omitempty"`
}

// Event is one boundary in a range.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Ref is a link.
type Ref struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// compare orders two dotted versions with an optional pre-release suffix
// after a hyphen, for what goVersion cannot read. The bool is false when it
// cannot tell: a suffix that is not a conventional pre-release word may be
// a revision that sorts the other way, and is not guessed at.
func compare(a, b string) (int, bool) {
	an, apre, aok := parseVersion(a)
	bn, bpre, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	for i := 0; i < len(an) || i < len(bn); i++ {
		av, bv := 0, 0
		if i < len(an) {
			av = an[i]
		}
		if i < len(bn) {
			bv = bn[i]
		}
		if av != bv {
			if av < bv {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case apre == bpre:
		return 0, true
	case apre == "":
		return 1, true
	case bpre == "":
		return -1, true
	case apre < bpre:
		return -1, true
	default:
		return 1, true
	}
}

var preWords = []string{"alpha", "beta", "rc", "pre", "preview", "dev",
	"snapshot", "nightly", "canary"}

func prerelease(s string) bool {
	low := strings.ToLower(s)
	for _, w := range preWords {
		rest, ok := strings.CutPrefix(low, w)
		if !ok {
			continue
		}
		rest = strings.TrimLeft(rest, ".-_")
		if rest == "" {
			return true
		}
		if _, err := strconv.Atoi(rest); err == nil {
			return true
		}
	}
	return false
}

func parseVersion(v string) ([]int, string, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	pre := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre, v = v[i+1:], v[:i]
		if !prerelease(pre) {
			return nil, "", false
		}
	}
	if v == "" {
		return nil, "", false
	}
	var out []int
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, "", false
		}
		out = append(out, n)
	}
	return out, pre, true
}

// Live reports whether a record still stands: a withdrawn one was wrong.
func (r Record) Live() bool { return r.Withdrawn == nil }
