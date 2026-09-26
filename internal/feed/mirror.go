// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package feed

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Mirror is a local copy of a feed and its history.
type Mirror struct {
	Feed     Feed      `json:"feed"`
	Releases []Release `json:"releases,omitempty"`
	// Failures are fetches that did not work, kept because a mirror that
	// is trying and failing is a different situation from one nothing has
	// asked about, and they look identical from the age alone.
	Failures []Failure `json:"failures,omitempty"`
}

// Failure is a fetch that did not produce a release.
type Failure struct {
	At    time.Time `json:"at"`
	Error string    `json:"error"`
}

// Take records a successful fetch.
func (m *Mirror) Take(r Release) error {
	if r.Feed != m.Feed.Name {
		return fmt.Errorf("that release is from %q, not %q", r.Feed,
			m.Feed.Name)
	}
	if r.Fetched.IsZero() {
		return fmt.Errorf("a release records when it was fetched")
	}
	if strings.TrimSpace(r.Digest) == "" {
		return fmt.Errorf(
			"a release carries a digest over its contents. Without one a " +
				"re-fetch that changed nothing cannot be told from one " +
				"that replaced everything")
	}
	m.Releases = append(m.Releases, r)
	return nil
}

// Missed records a fetch that failed.
func (m *Mirror) Missed(at time.Time, err error) {
	msg := "unknown"
	if err != nil {
		msg = err.Error()
	}
	m.Failures = append(m.Failures, Failure{At: at.UTC(), Error: msg})
}

// Current is the newest release.
func (m *Mirror) Current() (Release, bool) {
	if len(m.Releases) == 0 {
		return Release{}, false
	}
	best := m.Releases[0]
	for _, r := range m.Releases[1:] {
		if !r.Fetched.Before(best.Fetched) {
			best = r
		}
	}
	return best, true
}

// Age is how old the mirrored data is.
//
// From the fetch rather than from the source's publication date, because
// the question this answers is how long this program has been working from
// what it has — and a release published last week and fetched an hour ago
// is an hour old to everything downstream.
func (m *Mirror) Age(now time.Time) (time.Duration, bool) {
	c, ok := m.Current()
	if !ok {
		return 0, false
	}
	return now.Sub(c.Fetched), true
}

// Lag is how far behind the source's own publication this is, where the
// source dates its releases.
func (m *Mirror) Lag() (time.Duration, bool) {
	c, ok := m.Current()
	if !ok || c.Published.IsZero() {
		return 0, false
	}
	return c.Fetched.Sub(c.Published), true
}

// Stale reports whether the mirror is behind, and whose problem it is.
//
// The distinction is the point. A mirror this program has not fetched is
// ours. A source that has published nothing is theirs, and for a feed with
// no schedule it is not a problem at all. Conflating them is why staleness
// alerts get ignored.
func (m *Mirror) Stale(now time.Time) (bool, string) {
	age, ok := m.Age(now)
	if !ok {
		return true, fmt.Sprintf(
			"%q has never been fetched, so every answer derived from it "+
				"is about an empty database. This decides %s", m.Feed.Name,
			m.Feed.Kind.Decides())
	}
	if age <= m.Feed.Fetch {
		return false, ""
	}
	// Ours: we said we would look this often and we have not.
	behind := age - m.Feed.Fetch
	why := fmt.Sprintf(
		"%q is fetched every %s and was last fetched %s ago, so it is %s "+
			"overdue. That is this program's, not the source's",
		m.Feed.Name, plainly(m.Feed.Fetch), plainly(age), plainly(behind))
	if n := m.recentFailures(now); n > 0 {
		why += fmt.Sprintf(", and %d fetch(es) have failed since", n)
	}
	return true, why
}

func (m *Mirror) recentFailures(now time.Time) int {
	c, ok := m.Current()
	since := now.Add(-30 * 24 * time.Hour)
	if ok {
		since = c.Fetched
	}
	n := 0
	for _, f := range m.Failures {
		if f.At.After(since) {
			n++
		}
	}
	return n
}

// Missing estimates how many publications this mirror has not seen.
//
// Only meaningful for a feed with a schedule. For one without — a
// known-exploited catalogue with no fixed cadence — this returns false, and
// that is the honest answer rather than a number derived from an average
// somebody invented.
func (m *Mirror) Missing(now time.Time) (int, bool) {
	if !m.Feed.Scheduled() {
		return 0, false
	}
	age, ok := m.Age(now)
	if !ok || age < m.Feed.Publishes {
		return 0, true
	}
	return int(age / m.Feed.Publishes), true
}

// Attestation is what has to accompany any result derived from a mirror.
//
// A clean scan is a statement about a system and a database. Printing the
// first without the second is how a report becomes misleading without
// anybody lying, so this exists to be carried alongside the result rather
// than looked up afterwards by somebody who thought to ask.
type Attestation struct {
	Feed    string        `json:"feed"`
	Version string        `json:"version,omitempty"`
	Fetched time.Time     `json:"fetched,omitzero"`
	Age     time.Duration `json:"age"`
	Entries int           `json:"entries"`
	Stale   bool          `json:"stale,omitempty"`
	// Missed is publications not seen, where the source has a schedule.
	Missed   int  `json:"missed,omitempty"`
	Schedule bool `json:"schedule"`
	// Signs says the source publishes signatures at all, and Verified
	// whether this release's was checked. Both, because "unverified" only
	// means something where there was something to verify — saying it of
	// a source that signs nothing is noise that trains people to skip the
	// line where it matters.
	Signs    bool `json:"signs,omitempty"`
	Verified bool `json:"verified,omitempty"`
}

// Attest describes the mirror as it stands.
func (m *Mirror) Attest(now time.Time) Attestation {
	a := Attestation{Feed: m.Feed.Name, Schedule: m.Feed.Scheduled(),
		Signs: m.Feed.Signs}
	if c, ok := m.Current(); ok {
		a.Version, a.Fetched = c.Version, c.Fetched
		a.Entries, a.Verified = c.Entries, c.Verified
	}
	if age, ok := m.Age(now); ok {
		a.Age = age
	}
	a.Stale, _ = m.Stale(now)
	if n, ok := m.Missing(now); ok {
		a.Missed = n
	}
	return a
}

// Says describes an attestation in the sentence that should go under a
// result.
func (a Attestation) Says() string {
	if a.Fetched.IsZero() {
		return fmt.Sprintf(
			"checked against %s, which has never been fetched", a.Feed)
	}
	out := fmt.Sprintf("checked against %s as of %s ago (%d entries)",
		a.Feed, plainly(a.Age), a.Entries)
	switch {
	case a.Missed > 1:
		out += fmt.Sprintf(", missing about %d publication(s) since",
			a.Missed)
	case a.Stale && !a.Schedule:
		out += ", which is overdue — and this source has no schedule, so " +
			"how much is missing cannot be said"
	case a.Stale:
		out += ", which is overdue"
	}
	if a.Signs && !a.Verified {
		out += ". This source signs its releases and this one was not " +
			"verified"
	}
	return out
}

// Trouble is something wrong with a mirror, ranked.
type Trouble struct {
	Feed   string `json:"feed"`
	What   string `json:"what"`
	Weight int    `json:"weight"`
	Detail string `json:"detail,omitempty"`
}

// Weights, stated rather than buried in comparisons.
const (
	// Never: no data at all. Everything derived from it is about nothing.
	Never = 100
	// Empty: a fetch succeeded and returned nothing, which is usually a
	// moved URL answering 200.
	Empty = 95
	// Overdue: this program has not fetched when it said it would.
	Overdue = 80
	// Failing: fetches are erroring.
	Failing = 70
	// Unsigned: a source that signs produced a release that did not
	// verify.
	Unsigned = 60
	// Frozen: a scheduled source that has published nothing for several
	// intervals, which is about them rather than us.
	Frozen = 40
)

// Look reports what is wrong with a mirror.
func (m *Mirror) Look(now time.Time) []Trouble {
	var out []Trouble
	add := func(w int, what, detail string) {
		out = append(out, Trouble{Feed: m.Feed.Name, Weight: w,
			What: what, Detail: detail})
	}

	c, has := m.Current()
	if !has {
		add(Never, "never fetched", fmt.Sprintf(
			"every answer derived from this is about an empty database, "+
				"and an empty database reports nothing wrong. This "+
				"decides %s", m.Feed.Kind.Decides()))
		return rank(out)
	}
	if c.Empty() {
		add(Empty, "the last fetch returned nothing", fmt.Sprintf(
			"a feed that answers successfully with no entries is usually "+
				"a moved address returning an empty document. It reads as "+
				"a clean result, because %s", m.Feed.Kind.Decides()))
	}
	if stale, why := m.Stale(now); stale {
		add(Overdue, "overdue", why)
	}
	if n := m.recentFailures(now); n > 0 {
		last := m.Failures[len(m.Failures)-1]
		add(Failing, fmt.Sprintf("%d fetch(es) failing", n),
			"most recently: "+last.Error)
	}
	if m.Feed.Signs && !c.Verified {
		why := c.Why
		if why == "" {
			why = "no reason recorded"
		}
		add(Unsigned, "the release did not verify", fmt.Sprintf(
			"%s signs its releases and this one was accepted unverified: "+
				"%s. Accepted rather than refused, because a mirror that "+
				"stops updating over a signature problem has chosen the "+
				"worse failure — but it is a channel into what the scanner "+
				"can find", m.Feed.Name, why))
	}
	if m.Feed.Scheduled() {
		if since := now.Sub(c.Published); !c.Published.IsZero() &&
			since > 4*m.Feed.Publishes {
			add(Frozen, "the source has published nothing recently",
				fmt.Sprintf("%s publishes every %s and its newest release "+
					"is %s old. That is about them rather than about this "+
					"program, and it is still what the scanner is working "+
					"from", m.Feed.Name, plainly(m.Feed.Publishes),
					plainly(since)))
		}
	}
	return rank(out)
}

func rank(in []Trouble) []Trouble {
	sort.SliceStable(in, func(a, b int) bool {
		return in[a].Weight > in[b].Weight
	})
	return in
}

// Set is every mirror a deployment keeps.
type Set struct {
	Mirrors []*Mirror `json:"mirrors"`
}

// Add puts a feed in the set.
func (s *Set) Add(f Feed) (*Mirror, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	for _, m := range s.Mirrors {
		if strings.EqualFold(m.Feed.Name, f.Name) {
			return nil, fmt.Errorf("there is already a feed called %q",
				f.Name)
		}
	}
	m := &Mirror{Feed: f}
	s.Mirrors = append(s.Mirrors, m)
	return m, nil
}

// Mirror finds one by name.
func (s *Set) Mirror(name string) (*Mirror, bool) {
	for _, m := range s.Mirrors {
		if strings.EqualFold(m.Feed.Name, name) {
			return m, true
		}
	}
	return nil, false
}

// Due is the feeds that should be fetched now, longest overdue first.
func (s *Set) Due(now time.Time) []*Mirror {
	var out []*Mirror
	for _, m := range s.Mirrors {
		if stale, _ := m.Stale(now); stale {
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		x, _ := out[a].Age(now)
		y, _ := out[b].Age(now)
		return x > y
	})
	return out
}

// Look reports everything wrong across the set, worst first.
func (s *Set) Look(now time.Time) []Trouble {
	var out []Trouble
	for _, m := range s.Mirrors {
		out = append(out, m.Look(now)...)
	}
	return rank(out)
}

// Attest describes every mirror, for carrying alongside a result.
func (s *Set) Attest(now time.Time) []Attestation {
	out := make([]Attestation, 0, len(s.Mirrors))
	for _, m := range s.Mirrors {
		out = append(out, m.Attest(now))
	}
	sort.SliceStable(out, func(a, b int) bool {
		return out[a].Feed < out[b].Feed
	})
	return out
}

// Trustworthy reports whether a result derived from this set can be read as
// a statement about the system rather than about the database.
//
// False does not mean the result is wrong. It means the result cannot be
// read on its own, and the reason has to travel with it.
func (s *Set) Trustworthy(now time.Time) (bool, string) {
	var bad []string
	for _, m := range s.Mirrors {
		if stale, _ := m.Stale(now); stale {
			bad = append(bad, m.Feed.Name)
		}
	}
	if len(bad) == 0 {
		return true, ""
	}
	sort.Strings(bad)
	return false, fmt.Sprintf(
		"%s %s behind, so a clean result here is a statement about this "+
			"database rather than about the system",
		strings.Join(bad, ", "), isAre(len(bad)))
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// Known is the set of feeds a deployment would ordinarily keep, with what
// is publicly known about how each behaves.
//
// A starting point rather than a configuration. The addresses and cadences
// are the sources' and change; what is worth carrying here is which of them
// publish on a schedule and which do not, because that decides what a quiet
// week means.
func Known() []Feed {
	return []Feed{
		{
			Name: "osv", Kind: Advisories,
			From: "https://osv-vulnerabilities.storage.googleapis.com/",
			// OSV exports continuously, so the hour is a floor rather
			// than a schedule: it publishes faster than anybody fetches,
			// which means the source is never the thing behind and the
			// only measurable claim is about our own fetching. Matched
			// rather than sampled because the modification index makes an
			// incremental fetch cheap — and the validation above is right
			// that checking four times less often than a source changes
			// is being behind on purpose.
			Publishes: time.Hour, Fetch: time.Hour,
			Incremental: true,
		},
		{
			Name: "epss", Kind: Scores,
			From:      "https://epss.empiricalsecurity.com/",
			Publishes: 24 * time.Hour, Fetch: 24 * time.Hour,
		},
		{
			Name: "kev", Kind: Exploited,
			From: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
			// No Publishes: the catalogue has no fixed schedule, and
			// additions in 2026 ranged from nine to thirty-one a month.
			// A week with no changes is a normal week.
			Fetch: 12 * time.Hour,
		},
		{
			Name: "sigma", Kind: Rules,
			From:  "https://github.com/SigmaHQ/sigma/releases",
			Fetch: 7 * 24 * time.Hour, Signs: true,
		},
	}
}
