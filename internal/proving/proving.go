// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package proving is where a detection goes before it goes live.
//
// # The most expensive argument for this already happened
//
// On 19 July 2024 CrowdStrike shipped Channel File 291, a Rapid Response
// Content update — not code, content — that took down around eight and a
// half million Windows machines. The sensor expected twenty input fields
// and the update supplied twenty-one. CrowdStrike's own root cause analysis
// says the mismatch evaded multiple layers of build validation and testing,
// and gives the reason: the tests used wildcard matching criteria for the
// twenty-first input.
//
// That sentence is the whole design of this package. A rule tested only
// against inputs it was written to match proves nothing at all. It is the
// same point internal/detect makes when it refuses a rule with no negative
// fixture, and it generalises: the thing you have to show is not that a
// detection fires, it is what it does to everything else.
//
// CrowdStrike's remediation commitments were staged rollout of every
// template instance, automated tests for all template types, and customer
// control over when content updates arrive. Those are the three things here.
//
// # What a rule has to survive
//
// Rings, and nothing skips one. A candidate enters shadow, where it is
// evaluated and its matches are counted and nobody is woken up. It reaches
// canary when it has fixtures both ways and a replay over real recorded
// telemetry. It reaches live when somebody has looked at the measured
// volume and accepted it by name.
//
// The measurement is the point. Every team deploys detections without
// knowing how often they will fire, finds out in production, and tunes by
// suppression — which is how a detection estate becomes a set of rules
// nobody trusts and an exception list nobody can explain. Replaying a
// candidate over last week's events gives the number before the decision
// instead of after it.
//
// # Where the model is allowed to be
//
// An agent may propose a rule, write fixtures for it, and run a replay.
// All three are read-only or confined, and internal/agent's manifest is
// what bounds them. What it may never do is promote: a rule written by a
// model is held to exactly the same gates as one written by a person, with
// one addition — the person who accepts it must not be the one who asked
// for it. There is no fast path for generated content, because a fast path
// for generated content is the only kind of fast path an attacker with a
// prompt needs.
package proving

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/detect"
)

// Ring is how far a candidate has got.
type Ring string

const (
	// Shadow evaluates and counts and tells nobody.
	Shadow Ring = "shadow"
	// Canary alerts a small audience who know they are the first.
	Canary Ring = "canary"
	// Live alerts everybody.
	Live Ring = "live"
	// Retired is a rule that was withdrawn, which is not the same as one
	// that was never promoted.
	Retired Ring = "retired"
)

// Rings in order.
var Rings = []Ring{Shadow, Canary, Live}

func (r Ring) rank() int {
	for i, c := range Rings {
		if c == r {
			return i
		}
	}
	return -1
}

// Known reports whether a ring is one of the four.
func (r Ring) Known() bool { return r.rank() >= 0 || r == Retired }

// Next is the ring after this one.
func (r Ring) Next() (Ring, bool) {
	i := r.rank()
	if i < 0 || i+1 >= len(Rings) {
		return r, false
	}
	return Rings[i+1], true
}

// Loud reports whether a ring wakes anybody up.
func (r Ring) Loud() bool { return r == Canary || r == Live }

// OriginKind is who wrote a candidate.
type OriginKind string

const (
	// ByPerson: somebody wrote it.
	ByPerson OriginKind = "person"
	// ByFeed: it arrived from a rule library or a signature feed.
	ByFeed OriginKind = "feed"
	// ByAgent: a model proposed it.
	ByAgent OriginKind = "agent"
)

// Origin is where a candidate came from.
//
// Required and carried forward, because the three kinds need different
// scrutiny and a system that forgets which was which ends up applying the
// weakest to all of them.
type Origin struct {
	Kind OriginKind `json:"kind"`
	// Who is the person, the feed, or the agent's manifest name.
	Who string `json:"who"`
	// Version is the feed release this arrived in, so a bad batch can be
	// identified as a batch rather than one rule at a time.
	Version string `json:"version,omitempty"`
	// Signed says the feed's release carried a signature that verified.
	//
	// An auto-updating rule feed is a channel into a detection estate, and
	// a channel into a detection estate is a way to turn a detector off by
	// shipping it a rule that matches everything. Unsigned content is
	// allowed and is never allowed to skip a ring.
	Signed bool `json:"signed,omitempty"`
	// Asked is who requested an agent's proposal, so that the person who
	// accepts it can be required to be somebody else.
	Asked string    `json:"asked,omitempty"`
	At    time.Time `json:"at"`
}

// Validate refuses an origin that says nothing useful.
func (o Origin) Validate() error {
	switch o.Kind {
	case ByPerson, ByFeed, ByAgent:
	default:
		return fmt.Errorf("%q is not somewhere a rule comes from; it is "+
			"person, feed or agent", o.Kind)
	}
	if strings.TrimSpace(o.Who) == "" {
		return fmt.Errorf("an origin names who or what wrote it")
	}
	if o.Kind == ByFeed && strings.TrimSpace(o.Version) == "" {
		return fmt.Errorf(
			"a rule from a feed carries the release it arrived in. Without " +
				"it a bad batch has to be found one rule at a time, which " +
				"is the situation everybody is in at exactly the wrong moment")
	}
	if o.Kind == ByAgent && strings.TrimSpace(o.Asked) == "" {
		return fmt.Errorf(
			"a rule a model proposed records who asked for it, because the " +
				"person who accepts it has to be somebody else")
	}
	return nil
}

// Promotion is one move between rings.
type Promotion struct {
	From Ring      `json:"from"`
	To   Ring      `json:"to"`
	By   string    `json:"by"`
	At   time.Time `json:"at"`
	Why  string    `json:"why,omitempty"`
	// Volume is the alert rate the promoter was shown and accepted. Kept
	// because "we did not know it would do that" is the thing this exists
	// to make impossible to say afterwards.
	Volume float64 `json:"volume"`
}

// Candidate is a rule on its way in.
type Candidate struct {
	Rule   detect.Rule `json:"rule"`
	Origin Origin      `json:"origin"`
	Ring   Ring        `json:"ring"`

	Proofs     []Replay    `json:"proofs,omitempty"`
	Promotions []Promotion `json:"promotions,omitempty"`
	Entered    time.Time   `json:"entered"`
	// Moved is when it last changed ring, which is what a soak time is
	// measured from.
	Moved time.Time `json:"moved"`
	Note  string    `json:"note,omitempty"`
}

// Propose starts a candidate in shadow.
//
// Everything starts in shadow, including a rule from a signed feed and a
// rule written by the person who runs the team. There is no argument for an
// exception that does not also excuse the next bad batch.
func Propose(r detect.Rule, o Origin, at time.Time) (*Candidate, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(r.ID) == "" {
		return nil, fmt.Errorf("a candidate needs an identifier")
	}
	return &Candidate{
		Rule: r, Origin: o, Ring: Shadow,
		Entered: at.UTC(), Moved: at.UTC(),
	}, nil
}

// Latest is the most recent replay, if there is one.
//
// Ties go to the one recorded last. Two replays of the same rule against
// different recordings can carry the same timestamp — a batch job does
// this routinely — and the useful answer there is the one that was just
// run, not whichever happened to be appended first.
func (c *Candidate) Latest() (Replay, bool) {
	if len(c.Proofs) == 0 {
		return Replay{}, false
	}
	best := c.Proofs[0]
	for _, p := range c.Proofs[1:] {
		if !p.At.Before(best.At) {
			best = p
		}
	}
	return best, true
}

// Prove records a replay against this candidate.
func (c *Candidate) Prove(r Replay) error {
	if err := r.Validate(); err != nil {
		return err
	}
	c.Proofs = append(c.Proofs, r)
	return nil
}

// MinSoak is how long a candidate stays in a ring before moving up.
//
// A week, because the thing a soak is for is the traffic that only happens
// on some days: a backup window, a payroll run, a Monday. A detection that
// has been in canary for an afternoon has been tested against an afternoon.
const MinSoak = 7 * 24 * time.Hour

// May reports whether a candidate can move to a ring, and why not.
func (c *Candidate) May(to Ring, by string, at time.Time) error {
	if !to.Known() {
		return fmt.Errorf("%q is not a ring", to)
	}
	if to == Retired {
		return nil
	}
	if c.Ring == Retired {
		return fmt.Errorf("this candidate was retired; propose it again " +
			"rather than reviving it, so the replay is redone against " +
			"telemetry from now")
	}
	from := c.Ring
	if to.rank() <= from.rank() {
		return fmt.Errorf("%s is not forward of %s", to, from)
	}
	if next, _ := from.Next(); to != next {
		return fmt.Errorf(
			"a candidate in %s goes to %s next, not %s. Nothing skips a "+
				"ring — the whole point of the ring before this one is "+
				"that it is where a mistake is cheap", from, next, to)
	}
	if strings.TrimSpace(by) == "" {
		return fmt.Errorf("a promotion is somebody's")
	}
	if c.Origin.Kind == ByAgent &&
		strings.EqualFold(strings.TrimSpace(by), c.Origin.Asked) {
		return fmt.Errorf(
			"%s asked for this rule and cannot also be the one who accepts "+
				"it. A model's proposal reviewed only by the person who "+
				"requested it has been reviewed by the request", by)
	}
	if err := c.Rule.Validate(); err != nil {
		return fmt.Errorf(
			"this rule does not load yet: %w. A rule with no fixture it "+
				"matches and none it does not has been shown to fire and "+
				"not shown to discriminate", err)
	}

	p, ok := c.Latest()
	if !ok {
		return fmt.Errorf(
			"nothing has been replayed against this rule, so nobody knows " +
				"how often it would fire. That number is the decision, and " +
				"finding it out in production is how a detection estate " +
				"becomes a suppression list")
	}
	if err := p.Enough(); err != nil {
		return err
	}
	if p.Indiscriminate() {
		return fmt.Errorf(
			"this matched %.0f%% of the events it was replayed against. A "+
				"rule that matches most of what it sees is the shape of "+
				"Channel File 291, where a wildcard in the test data hid a "+
				"mismatch that took down eight and a half million machines",
			p.Share()*100)
	}
	if soaked := at.Sub(c.Moved); soaked < MinSoak {
		return fmt.Errorf(
			"this has been in %s for %s and the soak is %s. The traffic "+
				"a detection gets wrong is the traffic that only happens "+
				"on some days", from, plainly(soaked), plainly(MinSoak))
	}
	if to == Live && !p.Fired() {
		return fmt.Errorf(
			"this never fired in canary. It may be correct and quiet, and " +
				"it may be broken; promoting it to live decides which one " +
				"you believe without checking. Say so in the reason if you " +
				"mean it")
	}
	return nil
}

// Promote moves a candidate forward.
func (c *Candidate) Promote(to Ring, by, why string, at time.Time) error {
	if err := c.May(to, by, at); err != nil {
		// A refusal about a quiet rule is overridable with a stated reason,
		// because "it is correct and quiet" is a real answer. Nothing else
		// here is.
		if !strings.Contains(err.Error(), "never fired in canary") ||
			strings.TrimSpace(why) == "" {
			return err
		}
	}
	p, _ := c.Latest()
	c.Promotions = append(c.Promotions, Promotion{
		From: c.Ring, To: to, By: strings.TrimSpace(by), At: at.UTC(),
		Why: strings.TrimSpace(why), Volume: p.PerDay(),
	})
	c.Ring, c.Moved = to, at.UTC()
	return nil
}

// Retire withdraws a candidate.
func (c *Candidate) Retire(by, why string, at time.Time) error {
	if strings.TrimSpace(why) == "" {
		return fmt.Errorf("retiring a detection needs a reason. A rule " +
			"that disappeared without one is a gap nobody can tell from a " +
			"decision")
	}
	c.Promotions = append(c.Promotions, Promotion{
		From: c.Ring, To: Retired, By: strings.TrimSpace(by), At: at.UTC(),
		Why: strings.TrimSpace(why),
	})
	c.Ring, c.Moved = Retired, at.UTC()
	return nil
}

// Estate is every candidate, at whatever ring it has reached.
type Estate struct {
	Candidates []*Candidate `json:"candidates"`
}

// Add puts a candidate in the estate.
func (e *Estate) Add(c *Candidate) { e.Candidates = append(e.Candidates, c) }

// In is everything at a ring.
func (e *Estate) In(r Ring) []*Candidate {
	var out []*Candidate
	for _, c := range e.Candidates {
		if c.Ring == r {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Moved.Before(out[j].Moved)
	})
	return out
}

// FromBatch is everything that arrived in one feed release.
//
// The query nobody has when they need it. A bad batch is found as a batch,
// and the alternative is working out which of four hundred new rules
// arrived together at three in the morning.
func (e *Estate) FromBatch(feed, version string) []*Candidate {
	var out []*Candidate
	for _, c := range e.Candidates {
		if c.Origin.Kind == ByFeed &&
			strings.EqualFold(c.Origin.Who, feed) &&
			c.Origin.Version == version {
			out = append(out, c)
		}
	}
	return out
}

// Recall retires a whole feed release at once.
func (e *Estate) Recall(feed, version, by, why string,
	at time.Time) ([]*Candidate, error) {
	batch := e.FromBatch(feed, version)
	if len(batch) == 0 {
		return nil, fmt.Errorf("nothing here came from %s %s", feed, version)
	}
	for _, c := range batch {
		if err := c.Retire(by, why, at); err != nil {
			return nil, err
		}
	}
	return batch, nil
}

// Noise is the estate's total alert volume, and who is making it.
type Noise struct {
	PerDay  float64 `json:"per_day"`
	Rules   int     `json:"rules"`
	Worst   string  `json:"worst,omitempty"`
	WorstAt float64 `json:"worst_at,omitempty"`
}

// Noise measures what the live rules cost an analyst per day.
//
// The number a detection estate is actually judged by and that nobody
// computes, because it lives across as many dashboards as there are tools.
func (e *Estate) Noise() Noise {
	var n Noise
	for _, c := range e.Candidates {
		if !c.Ring.Loud() {
			continue
		}
		p, ok := c.Latest()
		if !ok {
			continue
		}
		n.Rules++
		n.PerDay += p.PerDay()
		if p.PerDay() > n.WorstAt {
			n.Worst, n.WorstAt = c.Rule.Title, p.PerDay()
		}
	}
	return n
}

func plainly(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s)", int(d.Hours()))
	}
	return fmt.Sprintf("%d day(s)", int(d.Hours()/24))
}
