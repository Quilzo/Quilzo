// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package detect

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Tuning: what a rule has turned out to be worth, and the two honest ways
// to quieten one.
//
// # Measured, not felt
//
// The package comment says precision is the only thing that matters. Until
// now nothing measured it. Every finding a person closes as a false
// positive, as benign, or as real is a verdict on the rule that raised it,
// and those verdicts were recorded and never read. A rule's precision is
// counted from them here — with an interval, and refused below a minimum,
// because "100% precise" after two verdicts is the claim that gets a noisy
// rule kept.
//
// # Two ways to quieten a rule, and the one way not to
//
// A rule that is wrong about everybody is demoted: moved to the trial ring,
// where it still runs and its findings still collect verdicts, but outside
// the queue people work from. A rule that is wrong about one thing — the
// backup account that does look like exfiltration — gets a suppression for
// that one thing.
//
// What is refused is the suppression with no edges: a whole rule, or a whole
// source, for ever, for a reason nobody wrote down. That is how detection is
// switched off without anybody deciding to — by an analyst on a bad night,
// or by an intruder who got to the console first. So a suppression names one
// rule and one thing, has an owner and a reason, expires within ninety days,
// counts what it hid, and cannot be written by a model.
//
// # Proposed, never applied
//
// This suggests demotions, promotions and suppressions from the numbers. It
// changes nothing itself. A detector that tunes itself quieter in response
// to being closed as noise can be talked out of its rules by whoever can
// generate noise.

// Ring is how much of a rule's output reaches people.
type Ring string

const (
	// Live raises findings into the queue. The default.
	Live Ring = "live"
	// Trial runs the rule and records what it finds, marked, outside the
	// default queue: how a new rule earns its place, and where a noisy one
	// goes while somebody fixes it.
	Trial Ring = "trial"
	// Off does not run the rule. Kept distinct from deleting it: the file,
	// its reasoning and its history stay.
	Off Ring = "off"
)

// Rings lists them.
func Rings() []Ring { return []Ring{Live, Trial, Off} }

func (r Ring) known() bool { return r == Live || r == Trial || r == Off }

// Placement is one rule's ring, and who put it there.
type Placement struct {
	Ring    Ring      `json:"ring"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
	Because string    `json:"because"`
}

// Validate refuses a placement nobody can account for.
func (p Placement) Validate(kind audit.Kind) error {
	if !p.Ring.known() {
		return fmt.Errorf("%q is not a ring; they are live, trial and off",
			p.Ring)
	}
	if kind == audit.KindAI {
		return fmt.Errorf("a model may propose moving a rule and may not " +
			"move one: a model that can quieten a detection can quieten " +
			"the one that would have caught it")
	}
	if strings.TrimSpace(p.By) == "" || p.At.IsZero() {
		return fmt.Errorf("a ring change needs who and when")
	}
	if p.Ring != Live && strings.TrimSpace(p.Because) == "" {
		return fmt.Errorf("moving a rule out of the queue needs a reason. " +
			"Six months on, the question is not whether it was noisy but " +
			"why anybody thought so")
	}
	return nil
}

// MaxSuppression is the longest a suppression may last.
//
// Ninety days. Long enough that a quarterly review renews what is still
// true; short enough that a suppression written for a migration does not
// outlive the migration by years, which is what happens to every exclusion
// list with no dates on it.
const MaxSuppression = 90 * 24 * time.Hour

// Suppression stops one rule raising findings about one thing.
type Suppression struct {
	ID   string `json:"id"`
	Rule string `json:"rule"`
	// Field and Value are what is suppressed: an event whose Field is
	// exactly Value. One field, compared for equality — a suppression is
	// not a second rule language.
	Field string `json:"field"`
	Value string `json:"value"`

	Owner   string     `json:"owner"`
	Because string     `json:"because"`
	By      string     `json:"by"`
	Kind    audit.Kind `json:"kind,omitempty"`
	At      time.Time  `json:"at"`
	Until   time.Time  `json:"until"`
}

// tooBroad are fields a suppression may not be written on. Each would
// silence a rule for a whole source or a whole class of event, which is a
// demotion wearing a narrower name; message is free text written by
// whoever can reach the log, including whoever is being detected.
var tooBroad = map[string]bool{
	"source": true, "class": true, "activity": true, "severity": true,
	"disposition": true, "message": true,
}

var reField = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

// Validate refuses a suppression with no edges.
func (s Suppression) Validate(now time.Time) error {
	if strings.TrimSpace(s.Rule) == "" || s.Rule == "*" {
		return fmt.Errorf("a suppression names one rule. Quietening every " +
			"rule for something is a decision about that thing, not a " +
			"suppression")
	}
	if !reField.MatchString(s.Field) {
		return fmt.Errorf("%q is not a field", s.Field)
	}
	if tooBroad[s.Field] || strings.HasSuffix(s.Field, ".issuer") {
		return fmt.Errorf(
			"%s is too broad to suppress on: it would silence %s for every "+
				"event with that %s. Move the rule to the trial ring if it "+
				"is wrong that widely", s.Field, s.Rule, s.Field)
	}
	if strings.TrimSpace(s.Value) == "" || len(s.Value) > 256 ||
		strings.ContainsAny(s.Value, "*?\r\n") {
		return fmt.Errorf("a suppression is for one exact value, with no " +
			"wildcard")
	}
	if s.Kind == audit.KindAI {
		return fmt.Errorf("a model may propose a suppression and may not " +
			"make one")
	}
	if strings.TrimSpace(s.Owner) == "" {
		return fmt.Errorf("a suppression needs an owner: the person who is " +
			"asked whether it is still true when it comes up for renewal")
	}
	if strings.TrimSpace(s.Because) == "" {
		return fmt.Errorf("a suppression needs a reason")
	}
	if strings.TrimSpace(s.By) == "" || s.At.IsZero() {
		return fmt.Errorf("a suppression needs who made it and when")
	}
	if s.Until.IsZero() {
		return fmt.Errorf("a suppression expires. One with no date is an " +
			"exclusion list, and nobody ever takes anything off an " +
			"exclusion list")
	}
	if !s.Until.After(now) {
		return fmt.Errorf("that date has passed")
	}
	if s.Until.Sub(now) > MaxSuppression {
		return fmt.Errorf("a suppression lasts at most %d days; renew it "+
			"then if it is still true", int(MaxSuppression.Hours()/24))
	}
	return nil
}

// Active reports whether it applies at a moment.
func (s Suppression) Active(now time.Time) bool { return now.Before(s.Until) }

// Hides reports whether an event raised by a rule is covered.
func (s Suppression) Hides(rule string, e telemetry.Event, now time.Time) bool {
	if s.Rule != rule || !s.Active(now) {
		return false
	}
	got, ok := e.Fields()[s.Field]
	if !ok {
		return false
	}
	// An observable field holds every value of its kind, space-separated;
	// one of them being the value is a match.
	for _, part := range strings.Fields(got) {
		if strings.EqualFold(part, s.Value) {
			return true
		}
	}
	return strings.EqualFold(got, s.Value)
}

// MinVerdicts is how many decided findings a rule needs before its
// precision is quoted or anything is proposed from it.
const MinVerdicts = 10

// Stats is what one rule has turned out to be worth.
type Stats struct {
	Rule string `json:"rule"`
	Ring Ring   `json:"ring"`
	// Findings is how many it has raised; Fired is how many times those
	// have been seen, which is the volume somebody had to look past.
	Findings int `json:"findings"`
	Fired    int `json:"fired"`
	// Real, False and Benign are the verdicts; Undecided is what nobody
	// has looked at.
	Real      int `json:"real"`
	False     int `json:"false"`
	Benign    int `json:"benign"`
	Undecided int `json:"undecided"`
	// Last is when it last fired.
	Last time.Time `json:"last,omitempty"`
	// Suppressed is how many events suppressions hid.
	Suppressed int `json:"suppressed"`
	// NoisyEntity is the one thing behind most of the noise, if there is
	// one, and how much of it.
	NoisyEntity string `json:"noisy_entity,omitempty"`
	NoisyCount  int    `json:"noisy_count,omitempty"`
}

// Decided is how many verdicts there are.
func (s Stats) Decided() int { return s.Real + s.False + s.Benign }

// Useful is the share of verdicts that were real, with a 95% Wilson
// interval, and whether there are enough verdicts to say it.
//
// Benign counts against. It was true and expected: the rule was right and
// somebody still had to stop and look, which is the cost precision is
// measuring. Precision in the narrow sense — real over real plus false — is
// Precision.
func (s Stats) Useful() (rate, low, high float64, enough bool) {
	n := s.Decided()
	if n == 0 {
		return 0, 0, 0, false
	}
	rate = float64(s.Real) / float64(n)
	low, high = wilson(s.Real, n)
	return rate, low, high, n >= MinVerdicts
}

// Precision is real over real plus false, ignoring benign.
func (s Stats) Precision() (rate float64, enough bool) {
	n := s.Real + s.False
	if n == 0 {
		return 0, false
	}
	return float64(s.Real) / float64(n), s.Decided() >= MinVerdicts
}

// wilson is the 95% Wilson score interval for k successes in n.
//
// Wilson rather than the normal approximation, which gives an interval of
// zero width at 0 and at 100% — exactly where a small sample most needs one.
func wilson(k, n int) (low, high float64) {
	if n == 0 {
		return 0, 1
	}
	const z = 1.959964
	p := float64(k) / float64(n)
	nn := float64(n)
	denom := 1 + z*z/nn
	centre := p + z*z/(2*nn)
	margin := z * math.Sqrt(p*(1-p)/nn+z*z/(4*nn*nn))
	low, high = (centre-margin)/denom, (centre+margin)/denom
	return math.Max(0, low), math.Min(1, high)
}

// Measure counts verdicts per rule from the findings, with decisions
// already applied. Rules are included even when they have raised nothing,
// because a rule that has never fired is the row most worth seeing.
func Measure(rules []Rule, findings []finding.Finding,
	rings map[string]Placement, hits map[string]int,
	sups []Suppression) []Stats {

	by := map[string]*Stats{}
	order := []string{}
	for _, r := range rules {
		ring := Live
		if p, ok := rings[r.ID]; ok && p.Ring.known() {
			ring = p.Ring
		}
		by[r.ID] = &Stats{Rule: r.ID, Ring: ring}
		order = append(order, r.ID)
	}
	noise := map[string]map[string]int{}
	for _, f := range findings {
		if f.Kind != finding.FromDetection {
			continue
		}
		s, ok := by[f.Source]
		if !ok {
			continue
		}
		s.Findings++
		s.Fired += f.Seen
		if f.Last.After(s.Last) {
			s.Last = f.Last
		}
		switch f.State {
		case finding.FalsePositive, finding.Benign:
			if f.State == finding.FalsePositive {
				s.False++
			} else {
				s.Benign++
			}
			if noise[f.Source] == nil {
				noise[f.Source] = map[string]int{}
			}
			noise[f.Source][f.Entity.String()]++
		case finding.Triaged, finding.Fixed, finding.Accepted:
			s.Real++
		default:
			s.Undecided++
		}
	}
	for _, sup := range sups {
		if s, ok := by[sup.Rule]; ok {
			s.Suppressed += hits[sup.ID]
		}
	}
	for rule, per := range noise {
		s := by[rule]
		for entity, n := range per {
			if n > s.NoisyCount || (n == s.NoisyCount && entity < s.NoisyEntity) {
				s.NoisyEntity, s.NoisyCount = entity, n
			}
		}
	}
	out := make([]Stats, 0, len(order))
	for _, id := range order {
		out = append(out, *by[id])
	}
	return out
}

// Proposal is a change the numbers suggest. A person makes it or does not.
type Proposal struct {
	Rule string `json:"rule"`
	// Do is demote, promote, suppress, renew or retire.
	Do string `json:"do"`
	// What is the change in words, and Why the numbers behind it.
	What string `json:"what"`
	Why  string `json:"why"`
	// Suppression is the one a renew or retire is about.
	Suppression string `json:"suppression,omitempty"`
}

// Propose suggests what to change.
func Propose(stats []Stats, sups []Suppression, hits map[string]int,
	now time.Time) []Proposal {

	var out []Proposal
	suppressed := map[string]bool{}
	for _, s := range sups {
		if s.Active(now) {
			suppressed[s.Rule+"|"+s.Value] = true
		}
	}
	for _, s := range stats {
		rate, low, high, enough := s.Useful()
		if !enough {
			continue
		}
		noise := s.False + s.Benign
		switch {
		case s.Ring == Live && noise >= 5 && s.NoisyCount*5 >= noise*4 &&
			!suppressed[s.Rule+"|"+s.NoisyEntity]:
			// Four fifths of the noise is one thing. Fixing that is
			// narrower than quietening the rule for everybody.
			out = append(out, Proposal{Rule: s.Rule, Do: "suppress",
				What: fmt.Sprintf("suppress %s for %s", s.Rule, s.NoisyEntity),
				Why: fmt.Sprintf("%d of its %d false or benign verdicts are "+
					"about %s; the rule may be right about everybody else",
					s.NoisyCount, noise, s.NoisyEntity)})
		case s.Ring == Live && high < 0.5:
			out = append(out, Proposal{Rule: s.Rule, Do: "demote",
				What: fmt.Sprintf("move %s to the trial ring", s.Rule),
				Why: fmt.Sprintf("%d of %d verdicts were real (%.0f%%); even "+
					"at the top of the likely range, %.0f%%, fewer than half "+
					"of what it raises is worth somebody's time", s.Real,
					s.Decided(), rate*100, high*100)})
		case s.Ring == Trial && low >= 0.5:
			out = append(out, Proposal{Rule: s.Rule, Do: "promote",
				What: fmt.Sprintf("move %s to the live ring", s.Rule),
				Why: fmt.Sprintf("%d of %d verdicts were real (%.0f%%); even "+
					"at the bottom of the likely range, %.0f%%, more than "+
					"half of what it raises is real", s.Real, s.Decided(),
					rate*100, low*100)})
		}
	}
	for _, sup := range sups {
		left := sup.Until.Sub(now)
		switch {
		case left <= 0:
			out = append(out, Proposal{Rule: sup.Rule, Do: "retire",
				Suppression: sup.ID, What: fmt.Sprintf(
					"remove the expired suppression of %s for %s", sup.Rule,
					sup.Value),
				Why: fmt.Sprintf("it expired %s and no longer hides anything; "+
					"%s owns it", sup.Until.Format("2 Jan 2006"), sup.Owner)})
		case left < 14*24*time.Hour && hits[sup.ID] > 0:
			out = append(out, Proposal{Rule: sup.Rule, Do: "renew",
				Suppression: sup.ID, What: fmt.Sprintf(
					"ask %s whether %s for %s is still true", sup.Owner,
					sup.Rule, sup.Value),
				Why: fmt.Sprintf("it expires %s and has hidden %d event(s)",
					sup.Until.Format("2 Jan 2006"), hits[sup.ID])})
		case now.Sub(sup.At) > 30*24*time.Hour && hits[sup.ID] == 0:
			out = append(out, Proposal{Rule: sup.Rule, Do: "retire",
				Suppression: sup.ID, What: fmt.Sprintf(
					"remove the suppression of %s for %s", sup.Rule, sup.Value),
				Why: "it has hidden nothing in thirty days, so it is either " +
					"fixed or was never the cause"})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Do < out[j].Do
	})
	return out
}
