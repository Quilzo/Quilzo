// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package canary is the one detection that does not have a false positive
// problem, and everything here exists to keep it that way.
//
// # Why this is the highest-value thing a small team can deploy
//
// Axelsson's base-rate argument (ACM TISSEC 3(3), 2000) is the reason most
// detection content is unusable: when almost nothing is an attack, even a
// very low false positive rate produces a queue of overwhelmingly innocent
// alerts, and the detection rate barely matters. A detection with a 1-in-1000
// false positive rate over a million events a day is four thousand wrong
// alerts and a team that stops reading them.
//
// A canary escapes that arithmetic, but not by being cleverer. A canary is a
// value that has no legitimate use: a credential no service authenticates
// with, a file no job reads, a record no query returns. Nobody can name it by
// accident, because it was minted from 160 bits of randomness and written
// down in exactly one place. So the false positive rate is not low, it is
// zero — as a matter of construction rather than tuning.
//
// That construction is a premise, and the premise is fragile. This package is
// about the premise, not about the detection, because the detection is four
// lines and the premise is where every real deployment fails.
//
// # The three ways the premise dies
//
// Something legitimate touches it. A backup job enumerates the bucket, a DLP
// scanner reads every document, an EDR agent hashes every file, a search
// indexer crawls the share. The canary fires, an analyst investigates, finds
// the backup job, and the next one gets less attention. This is not a false
// positive to be tuned away — it is the canary ceasing to be evidence, and it
// is recorded as Burned so that it reads as work to do rather than as noise
// to suppress. Expect names who is permitted to touch it; a touch from one of
// them spends the canary instead of firing it.
//
// It quietly disappears. The bucket is migrated, the repository is
// rewritten, a tidy-up removes a file nobody could explain. Nothing fires,
// because nothing is there to fire, and the silence reads exactly like
// safety. internal/detect refuses a rule that has never matched anything on
// the grounds that a detection that cannot fire is not a detection; a canary
// that has been deleted is the worse case, because it was a detection and
// stopped, without telling anybody. Check records that it is still in place,
// and a canary nobody has confirmed for MaxSilence reads as unknown rather
// than as armed.
//
// It is recognisable. A file called canary.txt detects nobody. Validate
// refuses a placement or a value that names itself, which is a small rule
// that catches the commonest way a first deployment is wasted.
//
// # Why a trip is trusted and its description is not
//
// Everything else in this codebase treats telemetry as attacker-controlled,
// because whoever can write a log line can write a prompt and the measured
// attack success rate against models reading telemetry is 83-88%. A canary
// trip is the one case where part of the signal is ours: we minted the value,
// so the fact that it appeared somewhere is a fact about our own secret and
// not a claim made by the log.
//
// The narrative around it is still the log's. So a tripped canary produces
// two pieces of evidence: the fact, untainted, and the description, tainted.
// An agent may act on the first and may not act on the second.
package canary

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// MinLength is the shortest value that can be a canary.
//
// Not a style rule. A canary's entire claim is that nobody could produce the
// value by accident or by guessing, and a short token fails that claim
// against a scanner rather than against an analyst. Mint produces far more
// than this; the floor exists for values planted by hand.
const MinLength = 16

// MaxSilence is how long a canary may go unconfirmed before it stops counting.
//
// A month. Long enough that confirming is not a chore, short enough that a
// canary removed in a migration is noticed in the same quarter it was
// removed. After this it is not Missing — nobody has said it is gone — it is
// unknown, which is a different and more honest thing to report.
const MaxSilence = 30 * 24 * time.Hour

// Kind is what a canary imitates. It decides the shape Mint produces and
// nothing else: the detection is the same in every case.
type Kind string

const (
	// AsCredential is a secret that looks like it would authenticate.
	AsCredential Kind = "credential"
	// AsFile is a distinctive string inside a document.
	AsFile Kind = "file"
	// AsRecord is an identifier that looks like a row or an object.
	AsRecord Kind = "record"
	// AsAddress is the local part of an address nobody should write to.
	AsAddress Kind = "address"
)

// Kinds lists them, for a caller validating input.
func Kinds() []Kind { return []Kind{AsCredential, AsFile, AsRecord, AsAddress} }

func (k Kind) known() bool {
	for _, x := range Kinds() {
		if x == k {
			return true
		}
	}
	return false
}

// State is what a canary is currently worth.
type State string

const (
	// Armed is planted, confirmed present, untouched. The only state in
	// which it is evidence.
	Armed State = "armed"
	// Tripped is somebody who should not have, did.
	Tripped State = "tripped"
	// Burned is something legitimate touched it, so it can no longer
	// distinguish. Needs replanting somewhere the legitimate thing does not
	// go, which is a decision only a person can make.
	Burned State = "burned"
	// Missing is a presence check said it is not there any more.
	Missing State = "missing"
	// Retired is somebody deliberately took it out of service.
	Retired State = "retired"
)

// Outcome is what a touch turned out to mean.
type Outcome string

const (
	// Fired is nobody had any business touching this.
	Fired Outcome = "fired"
	// Spent is an expected toucher did, and the canary is no longer evidence.
	Spent Outcome = "spent"
	// Ignored is a touch of something already burned, missing or retired.
	// Recorded, because the history is worth having, and not reported as a
	// detection, because a burned canary cannot distinguish.
	Ignored Outcome = "ignored"
)

// Trip is one observation of a canary's value somewhere.
type Trip struct {
	At time.Time `json:"at"`
	// By is who touched it, issuer-qualified. Zero when the source could not
	// say, which is common and is not a reason to discard the trip.
	By telemetry.ID `json:"by"`
	// From is the connector that saw it.
	From string `json:"from"`
	// How is the source's own description. Attacker-influenced; see the
	// package comment for why it is carried separately from the fact.
	How string `json:"how,omitempty"`
	// Ref points into the tamper-evident record where one exists.
	Ref string `json:"ref,omitempty"`
}

// Canary is a value planted somewhere it has no reason to be read.
type Canary struct {
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// Value is the token itself.
	Value string `json:"value"`
	// Where it was planted, as somebody would have to be told to find it.
	Where string `json:"where"`
	// Why a trip would mean something, in one line.
	//
	// Required, and the most useful field here. A canary nobody can say what
	// a trip would mean is a canary nobody will act on at three in the
	// morning — the alert arrives, it is unarguably real, and the person
	// reading it still has to reconstruct from scratch what an attacker
	// would have had to do. Writing it at planting time is also the moment
	// the hypothesis gets tested: a canary whose Why cannot be written is
	// usually one in a place attackers have no reason to go.
	Why string `json:"why"`
	// Owner is who is told. Empty is allowed and is itself worth sorting by.
	Owner string `json:"owner,omitempty"`

	Planted time.Time `json:"planted"`
	// Checked is when somebody last confirmed it is still in place.
	//
	// No omitempty: encoding/json does not omit a zero time, and a tag that
	// says it does is a tag somebody will believe. A register a person edits
	// by hand is better off showing the zero than pretending to hide it.
	Checked time.Time `json:"checked"`

	State State `json:"state"`
	// Expect names what is permitted to touch this without it counting.
	//
	// Matched against the toucher's identifier and against the connector
	// name. Usually empty, and an empty Expect is the strong form: the
	// canary is somewhere nothing at all goes. Every entry weakens it, which
	// is why they are written down rather than configured as exclusions.
	Expect []string `json:"expect,omitempty"`

	Trips []Trip `json:"trips,omitempty"`
}

// Ident is the identity of a canary, derived from its value.
//
// Derived so the same token planted twice is one canary, and a hash so the
// identifier can be printed, logged and put in a ticket without printing the
// secret next to it. A canary whose id gives away its value is a canary an
// attacker with read access to the register can avoid.
func Ident(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}

// giveaways are words that tell whoever finds the canary what it is.
//
// Not exhaustive and not meant to be. It catches the first draft, which is
// where this mistake is made: the file is called canary.txt, the bucket is
// called honeypot-test, the key is named FAKE_AWS_KEY, and the deployment
// detects nobody who can read.
var giveaways = []string{
	"canary", "honeypot", "honeytoken", "honey-token", "decoy", "tripwire",
	"bait", "trap", "dummy", "fake", "notreal", "not-real", "donottouch",
	"do-not-touch", "doNotUse", "test-token", "lure",
}

// Validate refuses a canary that cannot do its job.
func (c Canary) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("a canary needs an id")
	}
	if !c.Kind.known() {
		return fmt.Errorf("%s is not a kind of canary", c.Kind)
	}
	if len(strings.TrimSpace(c.Value)) < MinLength {
		return fmt.Errorf(
			"%s is %d characters. A canary's whole claim is that nobody "+
				"produces the value by accident, and under %d characters "+
				"that claim fails against a scanner rather than against a "+
				"person", c.ID, len(strings.TrimSpace(c.Value)), MinLength)
	}
	if strings.TrimSpace(c.Where) == "" {
		return fmt.Errorf(
			"%s says nothing about where it is planted, so nobody can "+
				"confirm it is still there and nobody can replant it once "+
				"it burns", c.ID)
	}
	if strings.TrimSpace(c.Why) == "" {
		return fmt.Errorf(
			"%s says nothing about what a trip would mean. Write it now, "+
				"while the reasoning is fresh — the person who has to act on "+
				"this will be reading it at three in the morning, and a "+
				"canary whose hypothesis cannot be written down is usually "+
				"one in a place attackers have no reason to go", c.ID)
	}
	if c.Planted.IsZero() {
		return fmt.Errorf("%s has no planting time, so it can never go stale",
			c.ID)
	}
	if word := gives(c.Where); word != "" {
		return fmt.Errorf(
			"%s is planted at %q, which contains %q. Whoever finds it can "+
				"read, and a canary that announces itself detects nobody",
			c.ID, c.Where, word)
	}
	if word := gives(c.Value); word != "" {
		return fmt.Errorf(
			"%s has %q in its value, which tells the person who exfiltrates "+
				"it not to use it", c.ID, word)
	}
	for _, e := range c.Expect {
		if strings.TrimSpace(e) == "" {
			return fmt.Errorf("%s expects an unnamed toucher", c.ID)
		}
		if strings.Contains(e, "*") {
			return fmt.Errorf(
				"%s expects %q. A wildcard here permits everything, which "+
					"is the same as having no canary while still reporting "+
					"one", c.ID, e)
		}
	}
	return nil
}

func gives(s string) string {
	low := strings.ToLower(s)
	for _, w := range giveaways {
		if strings.Contains(low, strings.ToLower(w)) {
			return w
		}
	}
	return ""
}

// Confident reports whether the canary has been confirmed present recently
// enough to be believed.
//
// False is not an alert. It is the honest answer to "is this armed": nobody
// knows, because nobody has looked. Reported separately from State for the
// same reason internal/baseline reports "not enough observations" separately
// from "normal".
func (c Canary) Confident(now time.Time) bool {
	if c.State != Armed {
		return false
	}
	last := c.Checked
	if last.IsZero() {
		last = c.Planted
	}
	return now.Sub(last) <= MaxSilence
}

// Expects reports whether a toucher was permitted.
func (c Canary) Expects(by telemetry.ID, from string) bool {
	for _, e := range c.Expect {
		want := strings.ToLower(strings.TrimSpace(e))
		for _, got := range []string{by.String(), by.Value, from} {
			if got != "" && strings.ToLower(strings.TrimSpace(got)) == want {
				return true
			}
		}
	}
	return false
}

// Touch records an observation and says what it meant.
//
// Always appends. A canary that has already burned still keeps its history,
// because "this burned in March and has been touched weekly since" is how you
// find out the backup job was never the explanation.
func (c *Canary) Touch(t Trip) Outcome {
	c.Trips = append(c.Trips, t)
	switch c.State {
	case Burned, Missing, Retired:
		return Ignored
	}
	if c.Expects(t.By, t.From) {
		c.State = Burned
		return Spent
	}
	c.State = Tripped
	return Fired
}

// Check records that somebody looked for the canary.
//
// Confirming absence is as much of a result as confirming presence, and the
// absence is the one nothing else in the system would ever notice.
func (c *Canary) Check(now time.Time, present bool) {
	c.Checked = now
	if present {
		if c.State == Missing {
			// It came back: a migration that restored the file, or a check
			// that was wrong. Armed again, and the history says it wobbled.
			c.State = Armed
		}
		return
	}
	if c.State == Armed {
		c.State = Missing
	}
}

// Seen reports whether an event mentions the canary's value.
//
// Every field, not a named one. The point of a canary is that you do not know
// how it will come back: a stolen key appears in an authentication event's
// actor, the same key appears in a proxy log's URL, and in a support ticket
// it appears in the middle of a sentence. A detection written against one
// field would have found one of those three.
func (c Canary) Seen(e telemetry.Event) bool {
	if len(c.Value) < MinLength {
		return false
	}
	for _, v := range e.Fields() {
		if v == c.Value || containsToken(v, c.Value) {
			return true
		}
	}
	for _, o := range e.Observables {
		if o.Value == c.Value {
			return true
		}
	}
	return false
}

// containsToken looks for the value as a whole token inside free text.
//
// Bounded by separators rather than a bare substring search, so a canary does
// not match a longer random string that happens to contain it — which cannot
// really happen at these lengths, but a matcher whose correctness rests on
// "cannot really happen" is one that fails on the day it does.
func containsToken(in, value string) bool {
	for _, f := range strings.FieldsFunc(in, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '"', '\'', ',', ';', '=', ':', '/', '\\',
			'(', ')', '[', ']', '{', '}', '<', '>', '&', '?', '|':
			return true
		}
		return false
	}) {
		if f == value {
			return true
		}
	}
	return false
}

// Finding is what this canary currently warrants somebody doing.
//
// Nothing, for an armed one. The three other answers are a detection, a
// burned canary to replant, and a missing one to explain — and the second two
// go into the same register as the first because they are the same kind of
// work: something that was protecting you has stopped, and somebody has to
// decide what to do about it.
func (c Canary) Finding(now time.Time) (finding.Finding, bool) {
	f := finding.Finding{
		Source: "canary",
		Entity: telemetry.ID{Issuer: "canary", Value: c.ID},
		First:  c.Planted, Last: now, Owner: c.Owner,
		State: finding.Open, Seen: 1,
	}
	switch c.State {
	case Tripped:
		last := c.Trips[len(c.Trips)-1]
		f.Kind = finding.FromDetection
		f.Severity = telemetry.SeverityCritical
		f.Title = fmt.Sprintf("canary %s was used: %s", c.ID, c.Why)
		f.First = last.At
		f.Evidence = []finding.Evidence{{
			At: last.At, Source: "canary",
			What: fmt.Sprintf(
				"a value planted at %s and written down nowhere else "+
					"appeared in %s", c.Where, last.From),
			Ref: last.Ref,
		}}
		if strings.TrimSpace(last.How) != "" {
			// The fact above is ours. This is the log's account of it, and
			// the log is written by whoever can reach it.
			f.Evidence = append(f.Evidence, finding.Evidence{
				At: last.At, Source: last.From, What: last.How,
				Ref: last.Ref, Tainted: true,
			})
		}
	case Burned:
		f.Kind = finding.FromControl
		f.Severity = telemetry.SeverityMedium
		f.Title = fmt.Sprintf(
			"canary %s burned and needs replanting somewhere else", c.ID)
		f.Evidence = []finding.Evidence{{
			At: now, Source: "canary",
			What: fmt.Sprintf(
				"something expected touched the canary at %s, so it can no "+
					"longer tell an attacker from routine work", c.Where),
		}}
	case Missing:
		f.Kind = finding.FromControl
		f.Severity = telemetry.SeverityHigh
		f.Title = fmt.Sprintf("canary %s is gone from %s", c.ID, c.Where)
		f.Evidence = []finding.Evidence{{
			At: c.Checked, Source: "canary",
			What: "a check found it absent. Until it is replanted or " +
				"explained, its silence is not evidence of anything",
		}}
	default:
		if c.State == Armed && !c.Confident(now) {
			f.Kind = finding.FromControl
			f.Severity = telemetry.SeverityLow
			f.Title = fmt.Sprintf(
				"canary %s has not been confirmed present since %s", c.ID,
				c.lastLook().Format("2006-01-02"))
			f.Evidence = []finding.Evidence{{
				At: now, Source: "canary",
				What: "nobody has looked for it in over a month, so it " +
					"reads as armed without anybody knowing that it is",
			}}
			break
		}
		return finding.Finding{}, false
	}
	f.ID = finding.Key(f.Kind, f.Source, f.Entity)
	return f, true
}

func (c Canary) lastLook() time.Time {
	if c.Checked.IsZero() {
		return c.Planted
	}
	return c.Checked
}

// Set is the canaries a deployment has planted.
type Set struct {
	byValue map[string]*Canary
	order   []string
}

// NewSet starts an empty one.
func NewSet() *Set { return &Set{byValue: map[string]*Canary{}} }

// Plant adds a canary, or returns the one already planted with that value.
func (s *Set) Plant(c Canary) (*Canary, error) {
	if c.ID == "" {
		c.ID = Ident(c.Value)
	}
	if c.State == "" {
		c.State = Armed
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if existing, ok := s.byValue[c.Value]; ok {
		return existing, nil
	}
	copied := c
	s.byValue[c.Value] = &copied
	s.order = append(s.order, c.Value)
	return &copied, nil
}

// Match returns every canary the event mentions.
//
// Exact lookup first, which is the common case and is one map read per field
// rather than one comparison per canary per field. A deployment with a
// thousand canaries and a million events a day is a thousand map reads a
// second, not a billion comparisons.
func (s *Set) Match(e telemetry.Event) []*Canary {
	var hit []*Canary
	seen := map[string]bool{}
	for _, v := range e.Fields() {
		for _, tok := range append([]string{v}, tokens(v)...) {
			c, ok := s.byValue[tok]
			if !ok || seen[c.Value] {
				continue
			}
			seen[c.Value] = true
			hit = append(hit, c)
		}
	}
	for _, o := range e.Observables {
		if c, ok := s.byValue[o.Value]; ok && !seen[c.Value] {
			seen[c.Value] = true
			hit = append(hit, c)
		}
	}
	sort.Slice(hit, func(i, j int) bool { return hit[i].ID < hit[j].ID })
	return hit
}

func tokens(in string) []string {
	if len(in) < MinLength {
		return nil
	}
	return strings.FieldsFunc(in, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '"', '\'', ',', ';', '=', ':', '/', '\\',
			'(', ')', '[', ']', '{', '}', '<', '>', '&', '?', '|':
			return true
		}
		return false
	})
}

// All returns every canary in planting order.
func (s *Set) All() []Canary {
	out := make([]Canary, 0, len(s.order))
	for _, v := range s.order {
		out = append(out, *s.byValue[v])
	}
	return out
}

// Len is how many canaries are planted.
func (s *Set) Len() int { return len(s.byValue) }

// Findings is everything the set currently warrants somebody doing.
func (s *Set) Findings(now time.Time) []finding.Finding {
	var out []finding.Finding
	for _, v := range s.order {
		if f, ok := s.byValue[v].Finding(now); ok {
			out = append(out, f)
		}
	}
	return finding.Rank(out, now)
}
