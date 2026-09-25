// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package baseline answers "has this ever happened before, and how often".
//
// # Why this is not a UEBA product
//
// Commercial user-and-entity behaviour analytics needs two things a small
// organisation does not have: a large population, so that peer comparison has
// peers, and a high event volume, so that "normal" has enough points to be a
// distribution rather than a handful. Give it neither and it does the thing it
// always does — flags everything for sixty days, then flags a different
// everything.
//
// There is no study of UEBA performance as a function of organisation size.
// What there is: no independent adversarial evaluation of any commercial UEBA
// product at all; red-team work showing evasion by randomised timing and
// human-cadence input going uncaught; and an academic insider-threat model
// reporting perfect recall with 0.54 precision on curated data with known
// ground truth. Half its alerts were wrong under laboratory conditions.
//
// So this is not that. It is the mechanism underneath it, built so that the
// small case is the honest case and the large case is the same code with more
// data.
//
// # One mechanism, two regimes
//
// Rarity within an entity's own history needs no peers and no population. "The
// first time this account has signed in from this country, against 1,247 prior
// sign-ins" is computable on day one, explainable in one sentence, and
// auditable by anybody who can count. Splunk's hunting guidance calls this
// stacking or least-frequency analysis; it is the oldest technique here and
// the one that scales *down*.
//
// Peer comparison is the same question asked across a population, and it only
// means anything once the population is large enough for "peer" to denote
// something. That is not a different system. It is this one with a second
// denominator, and it is reported only when the denominator exists.
//
// # Saying "not yet" is the feature
//
// The failure that makes UEBA unusable at small scale is not wrong answers, it
// is confident answers from no data. An entity seen four times has no baseline,
// and the correct output is that it has no baseline — not that its fifth action
// is anomalous, which is true of every fifth action and therefore says nothing.
//
// Every verdict here carries what it was computed from. A caller that wants to
// alert on novelty can require a denominator; one that wants to hunt can ignore
// it. Neither is forced to guess which it is getting.
//
// # What this deliberately does not do
//
// It does not learn a model, score with one, or update a profile from the event
// it is judging. Self-baselining that folds in the event under examination is
// how a patient attacker becomes normal: act slowly enough and the baseline
// follows you. Observe and Judge are separate calls, and the caller chooses the
// order — which means the choice is visible in the caller rather than hidden
// here.
package baseline

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// MinObservations is the point below which no claim of unusualness is made.
//
// Thirty is a convention rather than a discovery, and it is a floor on the
// denominator rather than a threshold on a score: below it the honest output
// is that there is not enough history, and above it the number itself is what
// gets reported. Chosen so that "0 of 30" is a statement somebody can act on
// and "0 of 3" is visibly not.
const MinObservations = 30

// MinPopulation is the point below which peer comparison is not attempted.
//
// A peer group needs peers. In an organisation of twelve there are no true
// peers for a role, so a comparison degenerates into either self-baselining
// (which the entity history already does, better) or whole-company comparison
// (too coarse to mean anything). Reporting nothing is more useful than
// reporting a comparison against two people.
const MinPopulation = 50

// Dimension is one thing worth counting: "country", "user_agent",
// "parent_process", "oauth_app". Named by the caller, because what is worth
// counting depends on the source and this package has no opinion about it.
type Dimension string

// Profile is what one entity has been seen doing.
//
// Counts rather than a model. A count can be explained to an auditor, a
// regulator and the person it flagged, in one sentence, with the denominator
// in it. A learned score cannot be explained to any of them.
type Profile struct {
	// Entity is who or what this describes, as the issuer-qualified
	// identifier internal/telemetry insists on. Without the issuer two
	// directories' accounts merge into one profile and the baseline describes
	// a person who does not exist.
	Entity string

	counts map[Dimension]map[string]int
	first  map[Dimension]map[string]time.Time
	last   map[Dimension]map[string]time.Time
	total  map[Dimension]int
}

// NewProfile starts an empty history.
func NewProfile(entity string) *Profile {
	return &Profile{
		Entity: entity,
		counts: map[Dimension]map[string]int{},
		first:  map[Dimension]map[string]time.Time{},
		last:   map[Dimension]map[string]time.Time{},
		total:  map[Dimension]int{},
	}
}

// Observe records that an entity did something, at a time.
//
// Separate from Judge on purpose. Folding the event under examination into the
// baseline it is judged against is how a slow attacker becomes normal: the
// profile follows whoever is patient enough to move at its pace. Keeping the
// two apart puts the order in the caller, where it is visible.
func (p *Profile) Observe(d Dimension, value string, at time.Time) {
	value = strings.TrimSpace(value)
	if value == "" {
		// An absent value is not an observation of anything. Counting it would
		// make "the field was missing" the commonest value of every dimension
		// and quietly make the real values look rarer than they are.
		return
	}
	if p.counts[d] == nil {
		p.counts[d] = map[string]int{}
		p.first[d] = map[string]time.Time{}
		p.last[d] = map[string]time.Time{}
	}
	if _, seen := p.counts[d][value]; !seen {
		p.first[d][value] = at
	}
	p.counts[d][value]++
	p.total[d]++
	if at.After(p.last[d][value]) {
		p.last[d][value] = at
	}
}

// Verdict is what the history says about one value.
type Verdict struct {
	Entity    string
	Dimension Dimension
	Value     string

	// Seen is how many times this entity has done this before, and Total how
	// many observations of this dimension there are to compare against.
	//
	// Both, always. "Never seen before" means something entirely different
	// against a history of 12 than against one of 12,000, and a verdict
	// carrying only the first is one nobody can weigh.
	Seen  int
	Total int

	// First is when this value was first seen for this entity, zero if never.
	First time.Time

	// Enough reports whether there is a baseline at all.
	//
	// False is not "normal" and not "anomalous" — it is "no opinion", and a
	// caller that treats it as either is making up the part this package
	// refused to.
	Enough bool

	// Peers is how many entities in the population have done this, and
	// Population how many were compared. Zero when no comparison was made.
	Peers      int
	Population int
}

// New reports whether this entity has never done this before.
//
// True on a profile with no history at all, which is why Enough exists: the
// first thing anybody does is new, and that is not a finding.
func (v Verdict) New() bool { return v.Seen == 0 }

// Share is how much of this entity's history is this value, 0 when none.
func (v Verdict) Share() float64 {
	if v.Total == 0 {
		return 0
	}
	return float64(v.Seen) / float64(v.Total)
}

// Why explains the verdict in one sentence, with its denominator.
//
// The sentence an analyst reads, an auditor checks and the person who was
// flagged is owed. Every number it needs is in the struct, which is the whole
// argument for counting rather than scoring.
// The two denominators are independent, and a verdict says whichever it has.
//
// An entity with no history supports no claim about what is normal *for it*.
// It supports a claim about the population regardless — and "a three-day-old
// account did something nobody here has ever done" is among the most useful
// sentences this package can produce, while being exactly the case an
// entity-only baseline reports as "no opinion".
//
// So the population half is reported whenever there is a population, and the
// entity half whenever there is a history, and the sentence says which of the
// two it is standing on. A verdict resting on neither says so.
func (v Verdict) Why() string {
	known := v.Population >= MinPopulation

	if !v.Enough {
		// No baseline for this entity. The population may still have one.
		switch {
		case known && v.Peers == 0:
			return fmt.Sprintf(
				"%s has only %d observation(s) of %s, so nothing is known "+
					"about what is normal for it — but none of %d others in "+
					"the population has used %q either",
				v.Entity, v.Total, v.Dimension, v.Population, v.Value)
		case known:
			return fmt.Sprintf(
				"no opinion: %s has %d observation(s) of %s, and %q is "+
					"ordinary for the population (%d of %d)",
				v.Entity, v.Total, v.Dimension, v.Value, v.Peers, v.Population)
		}
		return fmt.Sprintf(
			"no opinion: %s has %d observation(s) of %s and a baseline needs "+
				"at least %d", v.Entity, v.Total, v.Dimension, MinObservations)
	}

	switch {
	case v.New() && known && v.Peers == 0:
		return fmt.Sprintf(
			"first %s %q for %s, against %d prior, and none of %d others in "+
				"the population has done it either",
			v.Dimension, v.Value, v.Entity, v.Total, v.Population)
	case v.New() && known:
		return fmt.Sprintf(
			"first %s %q for %s, against %d prior — though %d of %d others "+
				"in the population have done it",
			v.Dimension, v.Value, v.Entity, v.Total, v.Peers, v.Population)
	case v.New():
		return fmt.Sprintf("first %s %q for %s, against %d prior",
			v.Dimension, v.Value, v.Entity, v.Total)
	default:
		return fmt.Sprintf("%s has used %s %q %d time(s) in %d, since %s",
			v.Entity, v.Dimension, v.Value, v.Seen, v.Total,
			v.First.UTC().Format("2006-01-02"))
	}
}

// Judge says what the history makes of a value, without recording it.
func (p *Profile) Judge(d Dimension, value string) Verdict {
	value = strings.TrimSpace(value)
	v := Verdict{
		Entity: p.Entity, Dimension: d, Value: value,
		Seen:  p.counts[d][value],
		Total: p.total[d],
	}
	v.Enough = v.Total >= MinObservations
	if f, ok := p.first[d][value]; ok {
		v.First = f
	}
	return v
}

// Values returns every value seen for a dimension, rarest first.
//
// Stacking, which is the oldest technique in this file and the one that keeps
// earning its place: sort by count ascending and read the top. Malicious
// activity is rare by definition, and rarity here is absolute — within
// whatever data exists — rather than relative to a peer group, which is
// exactly why it works at a size where peer comparison does not.
func (p *Profile) Values(d Dimension) []Count {
	out := make([]Count, 0, len(p.counts[d]))
	for value, n := range p.counts[d] {
		out = append(out, Count{Value: value, Seen: n, First: p.first[d][value]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seen != out[j].Seen {
			return out[i].Seen < out[j].Seen
		}
		// Ties by value, so the same history reads the same twice running.
		// Map iteration would not, and a hunt list that reorders is one
		// nobody can work through.
		return out[i].Value < out[j].Value
	})
	return out
}

// Count is one value and how often it has been seen.
type Count struct {
	Value string
	Seen  int
	First time.Time
}

// Total is how many observations of a dimension this profile holds.
func (p *Profile) Total(d Dimension) int { return p.total[d] }

// Population is a set of profiles, for the comparison that needs peers.
type Population struct {
	profiles map[string]*Profile
}

// NewPopulation starts an empty one.
func NewPopulation() *Population {
	return &Population{profiles: map[string]*Profile{}}
}

// For returns an entity's profile, creating it if new.
func (pop *Population) For(entity string) *Profile {
	if p, ok := pop.profiles[entity]; ok {
		return p
	}
	p := NewProfile(entity)
	pop.profiles[entity] = p
	return p
}

// Size is how many entities the population holds.
func (pop *Population) Size() int { return len(pop.profiles) }

// Judge asks the entity's own history first and the population second.
//
// In that order, and the second only when there is a population to ask. Peer
// comparison is the part that needs scale; entity history is not, so a small
// deployment gets a real answer rather than a degraded one.
func (pop *Population) Judge(entity string, d Dimension, value string) Verdict {
	v := pop.For(entity).Judge(d, value)
	if pop.Size() < MinPopulation {
		// Deliberately silent rather than comparing against a handful. A
		// "peer group" of eleven is not a peer group, and a comparison
		// against one reads as evidence while being noise.
		return v
	}
	v.Population = pop.Size()
	for name, p := range pop.profiles {
		if name == entity {
			continue
		}
		if p.counts[d][strings.TrimSpace(value)] > 0 {
			v.Peers++
		}
	}
	return v
}

// Rare returns the values in a dimension that few entities have used.
//
// The population-scale form of stacking: a user agent one account in eight
// hundred has presented is worth a look, and the same string on six hundred
// accounts is the fleet's browser. Requires a population, and says so by
// returning nothing rather than a list computed from too few.
func (pop *Population) Rare(d Dimension, atMost int) []Count {
	if pop.Size() < MinPopulation {
		return nil
	}
	holders := map[string]int{}
	firstSeen := map[string]time.Time{}
	for _, p := range pop.profiles {
		for value := range p.counts[d] {
			holders[value]++
			at := p.first[d][value]
			if cur, ok := firstSeen[value]; !ok || at.Before(cur) {
				firstSeen[value] = at
			}
		}
	}
	out := make([]Count, 0, len(holders))
	for value, n := range holders {
		if n <= atMost {
			out = append(out, Count{Value: value, Seen: n, First: firstSeen[value]})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seen != out[j].Seen {
			return out[i].Seen < out[j].Seen
		}
		return out[i].Value < out[j].Value
	})
	return out
}
