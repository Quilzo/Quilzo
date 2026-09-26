// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package feed keeps the databases a scanner is only as good as.
//
// A vulnerability scanner is a comparison between an inventory and a list.
// The inventory is measured; the list is fetched from somebody else, and
// everything about the answer depends on how recently.
//
// # Silence is the failure, and it looks exactly like success
//
// A scanner whose advisory database stopped updating three months ago
// reports no vulnerabilities. So does a system with no vulnerabilities.
// They are the same screen. Nothing errors, nothing is red, and the longer
// it goes on the more reassuring it looks — which is the same shape as
// internal/flow's filter that silently discards, and the reason both
// packages exist.
//
// So staleness is a finding here, and any result derived from a mirror
// carries the mirror's age. A clean scan is not a statement about a system,
// it is a statement about a system and a database, and printing the first
// without the second is how a report becomes misleading without anybody
// lying.
//
// # Two different silences
//
// "We have not fetched" and "they have not published" are different facts
// with different owners, and conflating them is why staleness alerts get
// ignored. EPSS publishes a scored CSV every day, so a mirror three days
// behind is our problem. CISA's known-exploited catalogue has no fixed
// schedule at all — additions in 2026 ranged from nine to thirty-one a
// month — so a week with no changes is a normal week and says nothing about
// whether fetching works.
//
// A feed therefore declares what the source does and what we do separately.
// Where the source has no schedule, the only checkable claim is about our
// own fetching, and the package says that rather than inventing a cadence
// for somebody else's publication.
//
// # A feed is a supply chain
//
// An auto-updating database is a channel into the thing that decides what
// your scanner finds, which makes it worth the same care as a dependency.
// Every release is identified, digested and — where the source signs —
// verified, and a release that arrives unverified is accepted and marked
// rather than refused, because a mirror that stops updating over a
// signature problem has chosen the failure above over the one it was
// avoiding. internal/proving is where a release's contents are staged; this
// is where they come from and what is known about them.
package feed

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Kind is what a feed carries.
type Kind string

const (
	// Advisories are vulnerability records: OSV, a vendor's own.
	Advisories Kind = "advisories"
	// Exploited is a known-exploited catalogue.
	Exploited Kind = "exploited"
	// Scores are exploit predictions.
	Scores Kind = "scores"
	// Rules are detections.
	Rules Kind = "rules"
)

// Kinds is every kind of feed.
var Kinds = []Kind{Advisories, Exploited, Scores, Rules}

// Known reports whether a kind is one of the four.
func (k Kind) Known() bool {
	for _, c := range Kinds {
		if c == k {
			return true
		}
	}
	return false
}

// Decides says what a stale feed of this kind gets wrong, which is not the
// same for all of them.
func (k Kind) Decides() string {
	switch k {
	case Advisories:
		return "whether a dependency is reported at all"
	case Exploited:
		return "whether something already in the queue is urgent"
	case Scores:
		return "the order the queue is worked in"
	case Rules:
		return "what a detection can see"
	}
	return string(k)
}

// Feed is a source and what is known about how it behaves.
type Feed struct {
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	From string `json:"from"`

	// Publishes is how often the source puts out new data.
	//
	// Zero means it has no schedule, which is a fact about the source and
	// not a gap in the configuration. CISA's catalogue is the example: it
	// changes several times some weeks and not at all in others, so "it
	// has not changed" is never evidence of anything.
	Publishes time.Duration `json:"publishes,omitempty"`
	// Fetch is how often this program goes and looks. Always known,
	// because it is ours.
	Fetch time.Duration `json:"fetch"`

	// Signs says the source publishes a signature over its releases.
	Signs bool `json:"signs,omitempty"`
	// Incremental says the source offers a way to fetch only what changed
	// — OSV's modification index, an ETag, a since parameter. Recorded
	// because a feed without one has to be pulled whole every time, which
	// is what makes people fetch it less often than they should.
	Incremental bool `json:"incremental,omitempty"`
}

// MaxFetch caps how rarely a feed may be checked.
//
// A week. Past that the answer to "is this current" is no, whatever the
// source's schedule, and a configuration saying otherwise is a decision
// somebody should have to make deliberately rather than by leaving a field
// large.
const MaxFetch = 7 * 24 * time.Hour

// Validate refuses a feed that cannot be reasoned about.
func (f Feed) Validate() error {
	if strings.TrimSpace(f.Name) == "" {
		return fmt.Errorf("a feed needs a name")
	}
	if !f.Kind.Known() {
		return fmt.Errorf("%q is not a kind of feed; they are %s", f.Kind,
			strings.Join(kindNames(), ", "))
	}
	if strings.TrimSpace(f.From) == "" {
		return fmt.Errorf("%q says nothing about where it comes from",
			f.Name)
	}
	if f.Fetch <= 0 {
		return fmt.Errorf(
			"%q does not say how often it is fetched. That interval is "+
				"ours rather than the source's, and without it a mirror "+
				"that has stopped updating cannot be told from one whose "+
				"source is quiet", f.Name)
	}
	if f.Fetch > MaxFetch {
		return fmt.Errorf(
			"%q is fetched every %s and the cap is %s. Past that the "+
				"answer to whether it is current is no, whatever the "+
				"source's schedule", f.Name, plainly(f.Fetch),
			plainly(MaxFetch))
	}
	if f.Publishes > 0 && f.Fetch > f.Publishes*4 {
		return fmt.Errorf(
			"%q publishes every %s and is fetched every %s. Checking four "+
				"times less often than the source changes means the mirror "+
				"is usually behind by design", f.Name,
			plainly(f.Publishes), plainly(f.Fetch))
	}
	return nil
}

func kindNames() []string {
	out := make([]string, 0, len(Kinds))
	for _, k := range Kinds {
		out = append(out, string(k))
	}
	return out
}

// Scheduled reports whether the source has a publication schedule to
// measure against.
func (f Feed) Scheduled() bool { return f.Publishes > 0 }

// Release is one version of a feed's contents.
type Release struct {
	Feed string `json:"feed"`
	// Version is the source's own identifier for this release, where it
	// has one, or the fetch time formatted where it does not.
	Version string `json:"version"`
	// Fetched is when this program took delivery. Published is when the
	// source says it was made, when it says — the two are kept apart for
	// the reason every other clock in this program is.
	Fetched   time.Time `json:"fetched"`
	Published time.Time `json:"published,omitzero"`

	// Digest is over the contents, so two mirrors can be compared and a
	// re-fetch that changed nothing is recognisable.
	Digest  string `json:"digest"`
	Entries int    `json:"entries"`
	// Added, Changed and Removed are against the previous release. A
	// release that changed nothing is normal and worth distinguishing from
	// a fetch that failed.
	Added   int `json:"added,omitempty"`
	Changed int `json:"changed,omitempty"`
	Removed int `json:"removed,omitempty"`

	// Verified says a signature over this release was checked. Why carries
	// the reason when it was not.
	Verified bool   `json:"verified,omitempty"`
	Why      string `json:"why,omitempty"`
	// Partial says this was an incremental fetch rather than a whole one.
	Partial bool `json:"partial,omitempty"`
}

// Empty reports whether a release carries nothing.
//
// Worth its own question. A feed that fetched successfully and returned
// nothing is either a source with nothing to say or a fetch that succeeded
// against the wrong thing, and the second is common enough — a moved URL
// that returns an empty document with a 200 — that it should not be read as
// "no vulnerabilities".
func (r Release) Empty() bool { return r.Entries == 0 }

// Quiet reports whether this release changed nothing.
func (r Release) Quiet() bool {
	return r.Added == 0 && r.Changed == 0 && r.Removed == 0
}

// Digest computes a release digest over a set of entry identities.
//
// Sorted first, so two mirrors that fetched the same contents in different
// orders agree — which is the whole use of it.
func Digest(ids []string) string {
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, id := range sorted {
		h.Write([]byte(id))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func plainly(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d second(s)", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s)", int(d.Hours()))
	}
	return fmt.Sprintf("%d day(s)", int(d.Hours()/24))
}
