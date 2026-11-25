// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/register"
)

// The separation policy: who may approve what, declared by the
// organisation.
//
// A rule is about one kind of record, and, where a condition says so, only
// some of them: a risk is a decision when it is accepted, and a decision
// when it was minuted. It names the atom that makes somebody eligible, so
// "who may accept a risk" is answered by the access policy, which already
// says who holds what, and not by a second list somebody has to keep in
// step with it. It names the autonomy level: three is a decision a person
// makes, four one that reaches outside the organisation or cannot be undone,
// which takes two people. And above a threshold, such as an impact of four
// or more, a decision at level three takes two people as well.
//
// The rules that are not the policy's to change are written in code: the
// person who raised or drafted a record does not approve it, no agent
// approves anything, each approver counts once, and a team of one approves
// alone only with the decision marked so and a review by somebody else
// owed. A policy file can ask for more people, never for fewer than these.

// Level is a decision's autonomy level, as the agent safety notes number
// them.
type Level int

const (
	// L3 is a decision a person makes: one approver, or two above the
	// threshold.
	L3 Level = 3
	// L4 is a decision that reaches outside the organisation or cannot be
	// undone: two approvers, always.
	L4 Level = 4
)

// Functions are what a named second approver is to the organisation: one of
// its executives, its risk function, or an adviser from outside it, such as
// a virtual CISO, who holds no role here and approves as second all the
// same.
var Functions = []string{"executive", "risk", "adviser"}

// Policy is the organisation's separation policy.
type Policy struct {
	// Rules are what it says about each kind of decision, the first that
	// applies to a record deciding it.
	Rules []Rule `json:"rules"`
	// Seconds are the people who may be a second approver, by what they
	// are to the organisation, whether or not they hold the atom: the
	// head of risk, an executive, an outside adviser.
	Seconds []Second `json:"seconds,omitempty"`
	// ReviewDays is how long a decision made alone waits for somebody
	// else's review before the review is overdue, which is a problem in
	// the posture.
	ReviewDays int `json:"review_days"`
	// WaitDays is how long a request waits for its approvers before it
	// lapses, and the signatures it gathered with it.
	WaitDays int `json:"wait_days"`
	// PhishingResistant says that whoever may approve, accept a risk,
	// publish outside the organisation or administer signs in with a
	// method that cannot be phished: a passkey, or a single sign-on whose
	// provider said it used one. Anybody else is asked for their passkey
	// before they go on.
	PhishingResistant bool `json:"phishing_resistant"`
}

// Rule is what the policy says about one kind of decision.
type Rule struct {
	// Name is how the approval names the rule that applied.
	Name string `json:"name"`
	// Kind is the kind of record it is about, and When the condition on
	// its fields under which it applies; without one it applies to every
	// record of the kind.
	Kind register.Kind `json:"kind"`
	When *Condition    `json:"when,omitempty"`
	// Atom is the permission that makes somebody eligible to approve.
	Atom auth.Action `json:"atom"`
	// Level is three or four.
	Level Level `json:"level"`
	// Needed is how many approvers it asks for below the threshold, when
	// that is more than the level asks.
	Needed int `json:"needed,omitempty"`
	// Above are the thresholds over any of which a level-three decision
	// takes a second approver.
	Above []Threshold `json:"above,omitempty"`
	// SecondFrom, when it is set, is what a second approver must be to the
	// organisation (Functions); when it is not, anybody eligible may be
	// second.
	SecondFrom []string `json:"second_from,omitempty"`
	// TermDays is how long the approval counts before it lapses and the
	// decision has to be made again. A record that ends sooner ends its
	// approval with it. Zero is an approval that does not lapse, for a
	// decision that is history once it is made.
	TermDays int `json:"term_days"`
}

// Condition is a field of the record and the value it has to hold.
type Condition struct {
	Field  string `json:"field"`
	Equals string `json:"equals"`
}

// Threshold is a number about the record and the least it has to be: a
// field of the record (impact), a field of the record it is about
// (about.impact), or how many days it runs (term_days).
type Threshold struct {
	Field   string `json:"field"`
	AtLeast int64  `json:"at_least"`
}

// Second is a person named as a possible second approver.
type Second struct {
	Principal string `json:"principal"`
	As        string `json:"as"`
}

// Default is the policy an organisation has until it declares its own.
//
// Risk acceptances and exceptions are level three, with a second approver
// for an impact of four or more and for an exception that runs longer than
// a quarter. The board's appetite and a source's write scope are level
// four. A minuted decision is recorded by somebody who may record minutes,
// and every other decision the register holds is approved by somebody who
// may approve, other than whoever drafted it: a starter taken in or out, a
// scope, a line of the statement of applicability, a control test, a
// person's erasure and a third party's key pinned among them.
func Default() *Policy {
	return &Policy{
		ReviewDays: 30, WaitDays: 14, PhishingResistant: true,
		Rules: []Rule{
			{Name: "risk-acceptance", Kind: register.KindRisk, When: &Condition{Field: "status", Equals: "accepted"},
				Atom: auth.ActAcceptRisk, Level: L3, Above: []Threshold{{Field: "impact", AtLeast: 4}}, TermDays: 365},
			{Name: "exception", Kind: register.KindException, Atom: auth.ActApproveException, Level: L3,
				Above: []Threshold{{Field: "about.impact", AtLeast: 4}, {Field: "term_days", AtLeast: 92}}},
			{Name: "risk-appetite", Kind: register.KindRiskAppetite, Atom: auth.ActSignBoardPack, Level: L4, TermDays: 366},
			{Name: "minuted-decision", Kind: register.KindDecision, When: &Condition{Field: "authority", Equals: "minuted"},
				Atom: auth.ActRecordMinute, Level: L3},
			{Name: "decision", Kind: register.KindDecision, Atom: auth.ActApprove, Level: L3},
			{Name: "write-scope", Kind: register.KindSource, Atom: auth.ActManageConnectors, Level: L4, TermDays: 365},
			{Name: "control-test", Kind: register.KindControlTest, Atom: auth.ActApprove, Level: L3, TermDays: 365},
			{Name: "starter", Kind: register.KindStarter, Atom: auth.ActApprove, Level: L3},
			{Name: "erasure", Kind: register.KindErasure, Atom: auth.ActApprove, Level: L3},
			{Name: "pinned-key", Kind: register.KindPinnedKey, Atom: auth.ActApprove, Level: L3, TermDays: 366},
			{Name: "scope", Kind: register.KindScope, Atom: auth.ActApprove, Level: L3, TermDays: 366},
			{Name: "applicability", Kind: register.KindApplicability, Atom: auth.ActApprove, Level: L3, TermDays: 366},
			{Name: "ai-system", Kind: register.KindAISystem, Atom: auth.ActApprove, Level: L3, TermDays: 365},
			{Name: "vendor", Kind: register.KindVendor, Atom: auth.ActApprove, Level: L3, TermDays: 365},
			{Name: "policy-version", Kind: register.KindPolicy, Atom: auth.ActApprove, Level: L3, TermDays: 366},
			{Name: "confirmed-reading", Kind: register.KindExtracted, Atom: auth.ActReadEvidence, Level: L3},
		},
	}
}

var reRuleName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)

// Validate refuses a policy that could not be applied, or that asks for
// fewer people than the rules written in code allow.
func (p *Policy) Validate() error {
	if p.ReviewDays < 1 || p.ReviewDays > 90 {
		return fmt.Errorf("a decision made alone is reviewed within 1 to 90 days, not %d", p.ReviewDays)
	}
	if p.WaitDays < 1 || p.WaitDays > 60 {
		return fmt.Errorf("a request waits for its approvers 1 to 60 days, not %d", p.WaitDays)
	}
	names := map[string]bool{}
	for _, r := range p.Rules {
		if !reRuleName.MatchString(r.Name) {
			return fmt.Errorf("%q is not a rule's name: lowercase letters, digits and dashes", clip(r.Name))
		}
		if names[r.Name] {
			return fmt.Errorf("the rule %s is declared twice", r.Name)
		}
		names[r.Name] = true
		spec, ok := register.SpecOf(string(r.Kind))
		if !ok || spec.Kind != r.Kind {
			return fmt.Errorf("the rule %s is about %q, which is not a kind the register has", r.Name, clip(string(r.Kind)))
		}
		if !carriesApproval(spec) {
			return fmt.Errorf("the rule %s is about %s, which carries no approval", r.Name, r.Kind)
		}
		if _, ok := auth.Needs(r.Atom); !ok {
			return fmt.Errorf("the rule %s makes people eligible by %q, which is not a permission", r.Name, clip(string(r.Atom)))
		}
		if r.Level != L3 && r.Level != L4 {
			return fmt.Errorf("the rule %s is at level %d; a decision a person approves is at level 3 or 4", r.Name, r.Level)
		}
		if r.Needed < 0 || r.Needed > 5 {
			return fmt.Errorf("the rule %s asks for %d approvers; from 1 to 5", r.Name, r.Needed)
		}
		if r.TermDays < 0 || r.TermDays > 3*366 {
			return fmt.Errorf("the rule %s lets an approval count for %d days; at most three years", r.Name, r.TermDays)
		}
		for _, f := range r.SecondFrom {
			if !isFunction(f) {
				return fmt.Errorf("the rule %s takes a second approver from %q, and they are %s", r.Name, clip(f),
					strings.Join(Functions, ", "))
			}
		}
		for _, th := range r.Above {
			if !reThreshold.MatchString(th.Field) {
				return fmt.Errorf("the rule %s has a threshold on %q, which is not a field's name", r.Name, clip(th.Field))
			}
		}
		if r.When != nil && !reThreshold.MatchString(r.When.Field) {
			return fmt.Errorf("the rule %s applies when %q holds a value, and that is not a field's name", r.Name, clip(r.When.Field))
		}
	}
	for _, s := range p.Seconds {
		if strings.TrimSpace(s.Principal) == "" || !isFunction(s.As) {
			return fmt.Errorf("a second approver is somebody named, as %s", strings.Join(Functions, ", "))
		}
	}
	return nil
}

var reThreshold = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$`)

func isFunction(s string) bool {
	for _, f := range Functions {
		if f == s {
			return true
		}
	}
	return false
}

// carriesApproval reports whether a kind's records hold an approval, under
// whatever name: found by the field's type, as the register finds it.
func carriesApproval(spec register.Spec) bool {
	t := reflect.TypeOf(spec.New()).Elem()
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Type == reflect.TypeOf((*register.Approval)(nil)) {
			return true
		}
	}
	return false
}

// RuleFor is the rule that decides a record: the first about its kind whose
// condition its fields meet.
func (p *Policy) RuleFor(rec register.Record) (Rule, bool) {
	fields := fieldsOf(rec)
	for _, r := range p.Rules {
		if r.Kind != rec.Kind() {
			continue
		}
		if r.When != nil && fmt.Sprint(fields[r.When.Field]) != r.When.Equals {
			continue
		}
		return r, true
	}
	return Rule{}, false
}

// seconds is who the policy names as a possible second approver for a
// rule, by name.
func (p *Policy) seconds(r Rule) []Second {
	var out []Second
	for _, s := range p.Seconds {
		if len(r.SecondFrom) == 0 || contains(r.SecondFrom, s.As) {
			out = append(out, s)
		}
	}
	return out
}

// SecondAs is what a person is to the organisation when the policy names
// them as a possible second approver, or "" when it does not.
func (p *Policy) SecondAs(name string) string { return p.functionOf(name) }

// Atoms are the permissions the policy's rules make people eligible by, in
// the order of the rules, each once.
func (p *Policy) Atoms() []auth.Action {
	var out []auth.Action
	seen := map[auth.Action]bool{}
	for _, r := range p.Rules {
		if !seen[r.Atom] {
			seen[r.Atom] = true
			out = append(out, r.Atom)
		}
	}
	return out
}

// functionOf is what a person named as a second is to the organisation, or
// "" when the policy does not name them.
func (p *Policy) functionOf(name string) string {
	for _, s := range p.Seconds {
		if auth.SamePerson(s.Principal, name) {
			return s.As
		}
	}
	return ""
}

// fieldsOf is a record's fields as a map, read from its JSON.
func fieldsOf(rec register.Record) map[string]any {
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

// PolicyPath is where a store keeps its separation policy.
func PolicyPath(root string) string { return filepath.Join(root, "separation.json") }

// LoadPolicy reads a store's separation policy, or the default when it has
// declared none.
func LoadPolicy(root string) (*Policy, bool, error) {
	raw, err := os.ReadFile(PolicyPath(root))
	if errors.Is(err, fs.ErrNotExist) {
		return Default(), false, nil
	}
	if err != nil {
		return nil, false, err
	}
	p, err := ParsePolicy(raw)
	if err != nil {
		return nil, true, err
	}
	return p, true, nil
}

// ParsePolicy reads a separation policy as it is declared, in JSON, and
// refuses one with a field it does not know, so that a misspelt rule is an
// error and not a rule quietly left out, and one that cannot be applied.
// The command line and the admin declare a policy through it, as the store
// reads one back.
func ParsePolicy(raw []byte) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("the separation policy does not read as one: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("the separation policy does not read as one: there is more after it")
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("the separation policy cannot be applied: %w", err)
	}
	return &p, nil
}

// AuditPolicy is the name a declared separation policy is recorded under.
const AuditPolicy = "approval.policy"

// PolicyDetail is what the audit log records of a policy declared: how many
// rules and seconds it has, what it asks of signing in, its days, and the
// hash of all of it, so that the entry names exactly the policy that was
// declared and a later one can be told from it.
func PolicyDetail(p *Policy) map[string]string {
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return map[string]string{"rules": fmt.Sprint(len(p.Rules)), "seconds": fmt.Sprint(len(p.Seconds)),
		"phishing_resistant": fmt.Sprint(p.PhishingResistant), "review_days": fmt.Sprint(p.ReviewDays),
		"wait_days": fmt.Sprint(p.WaitDays), "policy": "sha256:" + hex.EncodeToString(sum[:])}
}

// SavePolicy writes a store's separation policy, refusing one that could
// not be applied.
func SavePolicy(root string, p *Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return atomicfile.Update(PolicyPath(root), func(have *Policy) error {
		*have = *p
		return nil
	})
}

// Describe is what a rule asks, in a sentence code writes: who may
// approve, and how many of them.
func (r Rule) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Anybody who holds %s, other than whoever raised or drafted it", r.Atom)
	switch {
	case r.Level == L4:
		b.WriteString("; two of them, because it reaches outside the organisation or cannot be undone")
	case r.Needed > 1:
		fmt.Fprintf(&b, "; %d of them", r.Needed)
	}
	if len(r.Above) > 0 && r.Level == L3 {
		var over []string
		for _, th := range r.Above {
			over = append(over, fmt.Sprintf("%s of %d or more", strings.ReplaceAll(th.Field, "_", " "), th.AtLeast))
		}
		b.WriteString("; a second approver above the threshold (" + strings.Join(over, ", or ") + ")")
	}
	if len(r.SecondFrom) > 0 {
		b.WriteString(", who is the organisation's " + strings.Join(r.SecondFrom, ", or its "))
	}
	b.WriteString(".")
	return b.String()
}

// contains reports whether a list holds a string.
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// sortedNames is a set's names, in order.
func sortedNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// clip is a value cut short enough to quote in a refusal.
func clip(s string) string { return plaintext.Clip(s, 60, "…") }
