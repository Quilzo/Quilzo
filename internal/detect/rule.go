// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package detect is a detection, declared as data and run without a model.
//
// # Why precision is the only thing that matters here
//
// Axelsson's base-rate result (ACM TISSEC, 2000) is twenty-six years old and
// still governs: the false-positive rate, not the detection rate, decides
// whether a detector is usable. True positives are capped by the intrusion
// rate, which is tiny; false positives scale with the benign population,
// which is enormous. A worked example on a million events a day with two
// intrusions:
//
//	FPR 0.00001  ->  20 true, 10 false   -- 67% precision, usable
//	FPR 0.001    ->  20 true, 1000 false --  2% precision, drowned
//
// A hundredfold change in false-positive rate swamps any achievable
// improvement in detection rate. Everything below follows from that: rules
// are narrow, deterministic and tested, because a broad probabilistic rule
// costs more attention than it returns and attention is the scarce thing.
//
// # A rule is data
//
// Not code, and not a query string compiled at run time. The whole program
// refuses to execute anything — no eval in the template language, no plugin
// runtime — and a detection engine that took a query language would be the
// exception that made the rule a preference. A predicate here is a closed
// tree of comparisons over the fields internal/telemetry publishes.
//
// It is also what makes authoring by model safe. A model may propose a rule;
// what it proposes is reviewable data with a diff, and nothing it writes
// executes. That is the DeepParse result applied to detections: use a model
// at design time to produce an artefact, run the artefact deterministically,
// and keep the model out of the path where attacker-controlled input flows.
//
// # A detection that has never fired is not a detection
//
// The field's own measurement is that 13-18% of deployed SIEM rules are
// broken and would never fire under any input. They pass review, sit on the
// coverage chart, and are counted as protection. The usual cause is a field
// name that does not exist in the data — the rule is syntactically fine, runs
// nightly, and matches nothing forever.
//
// Nothing about a rule's text reveals this. So a rule here carries fixtures:
// events it must match and events it must not, and a rule with no passing
// fixture is refused. Not warned about — refused, because the cost of a rule
// that cannot fire is paid by whoever believed it could.
package detect

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Op is how a field is compared. A closed set, because a predicate is data
// and the set of things data can ask for has to be finite and reviewable.
type Op string

const (
	// Equals is exact, after case folding. Folding is the default because a
	// Windows event source will spell a username three ways in one day, and a
	// rule that matches two of them is the silent kind of broken.
	Equals Op = "equals"
	// Contains is a substring. The most over-used operator in the field and
	// the one that quietly turns a precise rule into a broad one.
	Contains Op = "contains"
	Prefix   Op = "prefix"
	Suffix   Op = "suffix"
	// Exists tests presence rather than value, which is how a rule says "this
	// source stopped sending a field it always sent".
	Exists Op = "exists"
	// Above and Below compare numerically, refusing a non-numeric value
	// rather than comparing it as text — "10" < "9" as a string, and a
	// severity threshold that behaves that way is worse than none.
	Above Op = "above"
	Below Op = "below"
	// Matches is a regular expression.
	//
	// Safe here in a way it is not in most languages: Go's regexp is RE2,
	// which has no backtracking and runs in time linear in the input. A
	// detection language with a backtracking engine hands whoever can
	// influence an event field a way to stop the detector, which is a
	// strange property for a security control. Still the operator of last
	// resort — a regular expression is the hardest thing on this list for
	// the next person to read, and Contains or Prefix says what it means.
	Matches Op = "matches"
	// Inside tests whether an address falls in a CIDR block.
	//
	// Its own operator rather than a prefix match on the text, because
	// "10.1.1.1" is not inside "10.1.1.0/24" by string comparison and is
	// by arithmetic, and every team that has tried the string version has
	// shipped a rule that missed half its range.
	Inside Op = "inside"
)

// Ops lists every operator, for telling an author what exists.
func Ops() []Op {
	return []Op{Equals, Contains, Prefix, Suffix, Exists, Above, Below,
		Matches, Inside}
}

func (o Op) known() bool {
	for _, k := range Ops() {
		if k == o {
			return true
		}
	}
	return false
}

// Match is one comparison against one field.
type Match struct {
	// Field is a name from telemetry.Event.Fields. A name nothing emits is
	// refused at load: that is the "never fires" failure, and it is cheapest
	// to catch while somebody is writing the rule.
	Field string `json:"field"`
	Op    Op     `json:"op"`
	// Values are alternatives: any one matching satisfies the comparison.
	// Empty for Exists, which has nothing to compare against.
	Values []string `json:"values,omitempty"`
}

// Predicate is a tree. Exactly one of All, Any, Not or Match is set.
//
// Deliberately not an expression string. A string needs a parser, a parser
// needs a grammar, and a grammar is the thing that eventually grows an escape
// hatch into evaluation. A tree has no syntax to abuse.
type Predicate struct {
	All   []Predicate `json:"all,omitempty"`
	Any   []Predicate `json:"any,omitempty"`
	Not   *Predicate  `json:"not,omitempty"`
	Match *Match      `json:"match,omitempty"`
}

// Fixture is an event a rule is asserted to match, or not to.
type Fixture struct {
	// Name says what case this is, and appears in the failure when the rule
	// stops agreeing with it.
	Name  string          `json:"name"`
	Event telemetry.Event `json:"event"`
	// Match is what this rule must do with it.
	//
	// The false ones are not optional decoration. A rule with only positive
	// fixtures has been shown to fire and not shown to discriminate, and the
	// way a rule goes wrong in production is almost always that it fires on
	// something benign that looks adjacent.
	Match bool `json:"match"`
}

// Rule is one detection.
type Rule struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Why is the hypothesis: what this is looking for and why that matters.
	// Palantir's ADS framework is right that the reasoning is the artefact
	// that survives whoever wrote it going on holiday.
	Why string `json:"why,omitempty"`
	// Blind is what this deliberately does not catch.
	//
	// The most valuable field here and the one nobody fills in. A detection
	// with an unwritten blind spot is one somebody will eventually believe
	// covers a case it never did.
	Blind string `json:"blind,omitempty"`

	// Sources are the connectors this reads. A rule with no source runs
	// against everything, which is how a narrow rule becomes a broad one
	// without anybody editing it.
	Sources []string `json:"sources"`

	When     Predicate          `json:"when"`
	Severity telemetry.Severity `json:"severity"`

	// Technique are ATT&CK ids, for navigation and never for a score.
	//
	// MITRE's own Center for Threat-Informed Defense now states that a
	// technique marked covered "doesn't reveal whether detections can
	// reliably identify all variations of that technique or if adversaries
	// could easily evade them". A coverage percentage built from these would
	// be selling the metric the framework's stewards have disowned.
	Technique []string `json:"technique,omitempty"`

	Fixtures []Fixture `json:"fixtures"`
}

// Matches reports whether an event satisfies this rule.
//
// Source first: a rule declares what it reads, and a rule evaluated against a
// source it was not written for is being asked a question its author never
// considered.
func (r Rule) Matches(e telemetry.Event) bool {
	if !r.reads(e.Source) {
		return false
	}
	return eval(r.When, e.Fields())
}

func (r Rule) reads(source string) bool {
	for _, s := range r.Sources {
		if strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(source)) {
			return true
		}
	}
	return false
}

func eval(p Predicate, f map[string]string) bool {
	switch {
	case p.Match != nil:
		return p.Match.eval(f)
	case len(p.All) > 0:
		for _, sub := range p.All {
			if !eval(sub, f) {
				return false
			}
		}
		return true
	case len(p.Any) > 0:
		for _, sub := range p.Any {
			if eval(sub, f) {
				return true
			}
		}
		return false
	case p.Not != nil:
		return !eval(*p.Not, f)
	}
	// An empty predicate. Validate refuses one, so reaching here means a
	// caller built a Rule without loading it; false is the safe answer,
	// because true would make an empty rule match everything.
	return false
}

func (m Match) eval(f map[string]string) bool {
	got, present := f[m.Field]
	if m.Op == Exists {
		return present
	}
	if !present {
		return false
	}
	for _, want := range m.Values {
		if compare(m.Op, got, want) {
			return true
		}
	}
	return false
}

func compare(op Op, got, want string) bool {
	switch op {
	case Equals:
		return strings.EqualFold(got, want)
	case Contains:
		return strings.Contains(strings.ToLower(got), strings.ToLower(want))
	case Prefix:
		return strings.HasPrefix(strings.ToLower(got), strings.ToLower(want))
	case Suffix:
		return strings.HasSuffix(strings.ToLower(got), strings.ToLower(want))
	case Above, Below:
		g, err1 := strconv.ParseFloat(strings.TrimSpace(got), 64)
		w, err2 := strconv.ParseFloat(strings.TrimSpace(want), 64)
		if err1 != nil || err2 != nil {
			// Refused rather than compared as text. "10" sorts below "9", and
			// a severity threshold that behaves that way is worse than none
			// because it looks like it is working.
			return false
		}
		if op == Above {
			return g > w
		}
		return g < w
	case Matches:
		// Compiled per comparison rather than cached, because a Rule is
		// data that can be edited between evaluations and a stale cached
		// program is a rule that has silently stopped matching what it
		// says. An invalid expression is false rather than a panic:
		// Validate is where a bad pattern is refused, and a detector that
		// crashes on an event is a detector somebody turns off.
		re, err := regexp.Compile("(?i)" + want)
		if err != nil {
			return false
		}
		return re.MatchString(got)
	case Inside:
		net, err := netip.ParsePrefix(strings.TrimSpace(want))
		if err != nil {
			return false
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(got))
		if err != nil {
			return false
		}
		return net.Contains(addr.Unmap())
	}
	return false
}

// Fields returns every field name this rule reads, sorted.
//
// The list Validate checks against the fixtures, and the list an author is
// shown when a rule refers to something that does not exist.
func (r Rule) Fields() []string {
	seen := map[string]bool{}
	collect(r.When, seen)
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func collect(p Predicate, into map[string]bool) {
	if p.Match != nil {
		into[p.Match.Field] = true
	}
	for _, sub := range p.All {
		collect(sub, into)
	}
	for _, sub := range p.Any {
		collect(sub, into)
	}
	if p.Not != nil {
		collect(*p.Not, into)
	}
}

// Validate refuses a rule that cannot do what it claims.
//
// Every check here answers a way a detection is silently useless rather than
// visibly wrong. A rule that fails one of these would deploy, run, and be
// counted as protection.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("a rule needs an id, so a finding can say which " +
			"rule produced it")
	}
	if strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf("%s has no title; an alert naming only an id is one "+
			"nobody can triage at three in the morning", r.ID)
	}
	if len(r.Sources) == 0 {
		return fmt.Errorf(
			"%s names no source. A rule that reads everything is being asked "+
				"questions its author never considered, and it becomes broader "+
				"every time a connector is added — without anybody editing it",
			r.ID)
	}
	if err := checkPredicate(r.When, 0); err != nil {
		return fmt.Errorf("%s: %w", r.ID, err)
	}

	// The fixtures, which are the part that makes the rest mean anything.
	var fires, discriminates bool
	names := map[string]bool{}
	for i, fx := range r.Fixtures {
		if strings.TrimSpace(fx.Name) == "" {
			return fmt.Errorf("%s: fixture %d has no name", r.ID, i+1)
		}
		if names[fx.Name] {
			return fmt.Errorf("%s: two fixtures are called %q", r.ID, fx.Name)
		}
		names[fx.Name] = true
		if err := fx.Event.Validate(); err != nil {
			return fmt.Errorf("%s: fixture %q is not a usable event: %w",
				r.ID, fx.Name, err)
		}
		if fx.Match {
			fires = true
		} else {
			discriminates = true
		}
	}
	if !fires {
		return fmt.Errorf(
			"%s has no fixture it matches, so nothing shows it can fire at "+
				"all. Between 13 and 18 percent of deployed rules in this "+
				"industry never fire under any input, and nothing about a "+
				"rule's text reveals which ones", r.ID)
	}
	if !discriminates {
		return fmt.Errorf(
			"%s has no fixture it refuses. A rule shown only to fire has not "+
				"been shown to discriminate, and the way a detection fails in "+
				"production is by firing on something benign that looks "+
				"adjacent to what it was written for", r.ID)
	}

	// Every field the rule reads has to appear in the data it was tested
	// against. A typo here is the single commonest way a rule never fires.
	emitted := map[string]bool{}
	for _, fx := range r.Fixtures {
		for name := range fx.Event.Fields() {
			emitted[name] = true
		}
	}
	var missing []string
	for _, f := range r.Fields() {
		if !emitted[f] {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf(
			"%s reads %s, and no fixture carries %s. A field the data does "+
				"not have is the commonest reason a rule runs nightly and "+
				"matches nothing forever",
			r.ID, strings.Join(missing, ", "),
			pluralise(len(missing), "that field", "those fields"))
	}
	return nil
}

// MaxDepth bounds a predicate tree.
//
// A rule is data, and data that arrives from a file somebody generated can
// nest as deeply as the generator felt like. The bound is on the walk rather
// than on the decoder because encoding/json builds the tree first.
const MaxDepth = 16

func checkPredicate(p Predicate, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf("the condition nests more than %d deep", MaxDepth)
	}
	set := 0
	if len(p.All) > 0 {
		set++
	}
	if len(p.Any) > 0 {
		set++
	}
	if p.Not != nil {
		set++
	}
	if p.Match != nil {
		set++
	}
	switch set {
	case 1:
	case 0:
		return fmt.Errorf(
			"a condition here says nothing. An empty condition is either a " +
				"rule that matches everything or one that matches nothing, " +
				"and which one it is should never be decided by a default")
	default:
		return fmt.Errorf(
			"a condition combines all, any, not and match in one place; " +
				"which applies first would be decided by evaluation order, " +
				"and nobody reviewing it would see that")
	}

	if p.Match != nil {
		m := p.Match
		if strings.TrimSpace(m.Field) == "" {
			return fmt.Errorf("a comparison names no field")
		}
		if !m.Op.known() {
			return fmt.Errorf(
				"%q is not an operator; the set is %s", m.Op, opList())
		}
		if m.Op == Exists {
			if len(m.Values) > 0 {
				return fmt.Errorf(
					"%s tests whether %s is present and also gives values to "+
						"compare it against; one of those is not what was "+
						"meant", Exists, m.Field)
			}
			return nil
		}
		if len(m.Values) == 0 {
			return fmt.Errorf("%s on %s has nothing to compare against",
				m.Op, m.Field)
		}
		for _, v := range m.Values {
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf(
					"%s on %s compares against an empty value, which "+
						"matches differently than an author expects: with "+
						"contains it matches every event that has the field "+
						"at all", m.Op, m.Field)
			}
			switch m.Op {
			case Matches:
				// Refused here rather than discovered at evaluation time,
				// where a pattern that does not compile is a rule that
				// quietly matches nothing.
				if _, err := regexp.Compile(v); err != nil {
					return fmt.Errorf(
						"%s on %s has a pattern that does not compile: %w",
						m.Op, m.Field, err)
				}
			case Inside:
				if _, err := netip.ParsePrefix(strings.TrimSpace(v)); err != nil {
					return fmt.Errorf(
						"%s on %s wants a CIDR block like 10.0.0.0/8, and "+
							"%q is not one", m.Op, m.Field, v)
				}
			}
		}
		return nil
	}

	for _, sub := range append(append([]Predicate{}, p.All...), p.Any...) {
		if err := checkPredicate(sub, depth+1); err != nil {
			return err
		}
	}
	if p.Not != nil {
		return checkPredicate(*p.Not, depth+1)
	}
	return nil
}

func opList() string {
	parts := make([]string, 0, len(Ops()))
	for _, o := range Ops() {
		parts = append(parts, string(o))
	}
	return strings.Join(parts, ", ")
}

func pluralise(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Result is what one fixture did.
type Result struct {
	Rule    string
	Fixture string
	Want    bool
	Got     bool
}

// OK reports whether the rule agreed with the fixture.
func (r Result) OK() bool { return r.Want == r.Got }

// Why says what went wrong, in the terms the failure means.
func (r Result) Why() string {
	switch {
	case r.OK():
		return ""
	case r.Want:
		return fmt.Sprintf(
			"%s does not match %q, which it is asserted to catch", r.Rule, r.Fixture)
	default:
		return fmt.Sprintf(
			"%s matches %q, which is benign. A false positive costs more "+
				"attention than a true positive returns", r.Rule, r.Fixture)
	}
}

// Test runs a rule against its own fixtures.
func (r Rule) Test() []Result {
	out := make([]Result, 0, len(r.Fixtures))
	for _, fx := range r.Fixtures {
		out = append(out, Result{
			Rule: r.ID, Fixture: fx.Name,
			Want: fx.Match, Got: r.Matches(fx.Event),
		})
	}
	return out
}
