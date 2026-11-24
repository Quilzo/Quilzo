// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package approval is how a decision in the security record is approved:
// by whom, on what evidence, and bound to exactly what they were shown.
//
// An approval lives in the record it decides (register.Approval). This
// package is what fills one in. It reads the organisation's separation
// policy (policy.go) for who may approve each kind of decision and how many
// of them; it works out the surface, the hash of what an approver is shown
// (surface.go); it takes each approver's authentication over that hash, a
// fresh passkey assertion or, for an administrator at the store's own
// console, the hash typed back, and keeps it where it can be checked again
// offline (evidence.go); and when enough people have agreed it writes the
// record through the register's one write path, which checks the evidence
// again before anything is committed (verify.go).
//
// The rules that are not the policy's to relax are kept here, in code:
// whoever raised or drafted a record does not approve it; no agent approves
// anything, so no agent approves an agent's work; each person counts once;
// and a team of one approves alone only with the decision marked so, a
// review by somebody else owed within the policy's days, and not for a day
// after another administrator stopped being one (internal/dual's Settle).
//
// Several records can be approved by one assertion, over the Merkle root of
// their surfaces in the order shown, once the approver has opened the ones
// the batch chose for them (batch.go); and a decision made alone is reviewed
// by somebody else, whose review is a record of its own (review.go).
package approval

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/register"
)

// Approvals is the approvals of one store's register.
type Approvals struct {
	// Root is the store's directory, beside which the evidence, the
	// requests waiting for approvers and the pseudonyms are kept.
	Root     string
	Register *register.Register
	// Access is the access policy, which says who holds each atom. Nil is
	// a store with no access control, where whoever is at it is its owner.
	Access *auth.Policy
	// Separation is the separation policy; nil reads the store's, or the
	// default.
	Separation *Policy
	// People names people by pseudonym; nil is the file beside the store.
	People People
	// Settling is internal/dual's day after an administrator stopped being
	// one, during which nobody approves alone. Nil never holds anybody
	// back.
	Settling func(now time.Time) (*dual.Removal, error)
	// IsAgent says a principal of the access policy is an agent, which is
	// never eligible to approve. Nil takes "agent:" names for agents.
	IsAgent func(name string) bool
	// Audit records each signature and refusal. Nil records nothing, and
	// then nothing is signed: an approval nobody can show was given is
	// not one.
	Audit func(audit.Record) error
	// Now is the clock, for tests.
	Now func() time.Time
}

// AuditSigned and AuditRefused are the names a signature, and a refusal of
// one, are recorded under.
const (
	AuditSigned  = "approval.signed"
	AuditRefused = "approval.refused"
)

// ErrRefused is a signature the separation policy refuses. It is a
// decision, not a failure: nothing broke, and asking again changes nothing.
// It is also register.ErrRefused, so every surface answers it as the
// refusal it is.
var ErrRefused = errors.New("refused by the separation policy")

// ErrOtherSurface is a signature over the hash of something other than what
// is waiting now: another record, or this one as it was before it changed.
var ErrOtherSurface = errors.New("the passkey signed the hash of another surface")

type refusal struct {
	msg   string
	cause error
}

func (r refusal) Error() string { return r.msg }
func (r refusal) Is(target error) bool {
	return target == ErrRefused || target == register.ErrRefused || (r.cause != nil && target == r.cause)
}

func errRefused(format string, args ...any) error { return refusal{msg: fmt.Sprintf(format, args...)} }

// Person is who is approving, as the surface they came through knows them.
type Person struct {
	// Name is the principal, as the access policy names them.
	Name string
	// Kind is a person, a service or a model; only a person approves.
	Kind     audit.Kind
	Verified bool
	// Methods is how their session was signed in to (auth.Token's).
	Methods []string
	// Console is an administrator at the store's own console, approving
	// by typing the hash back.
	Console bool
	// May asks the access policy as their session, with its own limits.
	May func(act auth.Action, resource string) error
}

// Proof is a person's authentication over a hash: a passkey's assertion, or
// the hash typed at the console.
type Proof struct {
	Passkey *PasskeyProof
	Console *ConsoleProof
}

// Ask is a decision waiting for its approvers, as they are shown it.
type Ask struct {
	Proposal register.Proposal
	Rule     Rule
	// Needed is how many approvers the rule asks of this record, and Of
	// how many people are eligible.
	Needed, Of int
	// Over are the thresholds the record is over, in words.
	Over []string
	// Surface is what an approver is shown, and Hash its hash.
	Surface Surface
	Hash    register.Digest
	// Raised is who asked for the decision, as the approval will name
	// them.
	Raised register.ID
	// Signed are the signatures given so far, and Until when they lapse
	// if nobody else signs.
	Signed []Signed
	Until  register.Time
	// Expires is when the approval would lapse, given now.
	Expires register.Time

	eligible map[string]bool
	seconds  map[string]string
	raisers  map[register.ID]bool
}

// AloneFor reports whether the person with this pseudonym would approve
// the decision alone: they are the one person eligible, and either they
// raised it themselves or the rule asks for more people than there are.
// The one eligible person approving what somebody else raised, where one
// approver is all the rule asks, is two people, and not alone.
func (a *Ask) AloneFor(subject register.ID) bool {
	return a.Of == 1 && (a.raisers[subject] || a.Needed > 1)
}

// Raisers reports whether the person with this pseudonym raised or drafted
// the decision, and so may not approve it unless they approve it alone.
func (a *Ask) Raisers(subject register.ID) bool { return a.raisers[subject] }

// Signed is one signature given to a request.
type Signed struct {
	Subject  register.ID     `json:"subject"`
	At       register.Time   `json:"at"`
	Evidence register.Digest `json:"evidence"`
	Method   register.Method `json:"method"`
	Batch    register.Digest `json:"batch,omitempty"`
	// Name is who signed, kept beside the store and never in the record,
	// so the next signer can be told apart from them.
	Name string `json:"name"`
	// Function is what they are to the organisation when the policy names
	// them as a second.
	Function string `json:"function,omitempty"`
	// Holds says they hold the rule's atom, rather than being named as a
	// second only.
	Holds bool `json:"holds"`
}

// Outcome is what a signature did.
type Outcome struct {
	Record   register.ID     `json:"record"`
	Surface  register.Digest `json:"surface"`
	Evidence register.Digest `json:"evidence"`
	// Signed and Needed are the signatures there are now, and how many the
	// rule asks.
	Signed int `json:"signed"`
	Needed int `json:"needed"`
	// Done says the record was written, with Receipt the register's.
	Done    bool              `json:"done"`
	Alone   bool              `json:"alone,omitempty"`
	Receipt *register.Receipt `json:"receipt,omitempty"`
}

func (m *Approvals) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Approvals) policy() (*Policy, error) {
	if m.Separation != nil {
		return m.Separation, nil
	}
	p, _, err := LoadPolicy(m.Root)
	return p, err
}

func (m *Approvals) people() People {
	if m.People != nil {
		return m.People
	}
	return PeopleAt(m.Root)
}

func (m *Approvals) isAgent(name string) bool {
	if m.IsAgent != nil {
		return m.IsAgent(name)
	}
	return strings.HasPrefix(name, "agent:")
}

// Waiting is every proposal a rule of the separation policy decides, oldest
// first, as its approvers are shown it.
func (m *Approvals) Waiting() ([]*Ask, error) {
	list, err := m.Register.Proposals()
	if err != nil {
		return nil, err
	}
	pol, err := m.policy()
	if err != nil {
		return nil, err
	}
	var out []*Ask
	for _, p := range list {
		if _, ok := pol.RuleFor(p.Record); !ok {
			continue
		}
		a, err := m.ask(pol, p)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// Ask is one waiting decision, as its approvers are shown it.
func (m *Approvals) Ask(id register.ID) (*Ask, error) {
	list, err := m.Register.Proposals()
	if err != nil {
		return nil, err
	}
	pol, err := m.policy()
	if err != nil {
		return nil, err
	}
	for _, p := range list {
		if p.ID != id {
			continue
		}
		if _, ok := pol.RuleFor(p.Record); !ok {
			return nil, errRefused("no rule of the separation policy decides this %s, so it is accepted or "+
				"rejected as any proposal is, and not approved here", strings.ToLower(string(p.Kind)))
		}
		return m.ask(pol, p)
	}
	return nil, fmt.Errorf("%w: nothing with the identifier %s waits for an approval", register.ErrNotFound, clip(string(id)))
}

func (m *Approvals) ask(pol *Policy, p register.Proposal) (*Ask, error) {
	rule, _ := pol.RuleFor(p.Record)
	spec, _ := register.SpecOf(string(p.Kind))
	a := &Ask{Proposal: p, Rule: rule, eligible: map[string]bool{}, seconds: map[string]string{},
		raisers: map[register.ID]bool{}}
	if m.Access != nil {
		for _, who := range m.Access.Principals() {
			if !m.isAgent(who) && m.Access.Evaluate(who, rule.Atom, spec.Resource()).Allowed {
				a.eligible[auth.PersonKey(who)] = true
			}
		}
	}
	var err error
	if a.Needed, a.Over, err = m.needed(rule, p.Record); err != nil {
		return nil, err
	}
	if a.Surface, err = SurfaceOf(m.Register, p.Record, p.ID); err != nil {
		return nil, err
	}
	a.Hash = a.Surface.Digest()

	// Whoever raised or drafted it: the person who proposed it, the agent
	// that did, and the person the record itself says raised it.
	if p.Subject.Valid() {
		a.raisers[p.Subject] = true
		a.Raised = p.Subject
	}
	if raised, ok := fieldsOf(p.Record)["raised_by"].(string); ok && register.ID(raised).Valid() {
		a.raisers[register.ID(raised)] = true
		a.Raised = register.ID(raised)
	}
	if a.Raised == "" && p.Agent != "" {
		if id, ok, err := known(m.people(), p.Agent); err != nil {
			return nil, err
		} else if ok {
			a.Raised = id
		}
	}

	// A second named in the policy approves beside somebody who holds the
	// atom and did not raise it, never in their place, so they are counted
	// among those eligible only where the rule asks for a second and there
	// is such a somebody. Counted otherwise, a team of one with an adviser
	// was two people who could not between them approve anything: the one
	// raised it, and the other may only be second.
	free := 0
	for name := range a.eligible {
		id, ok, err := known(m.people(), name)
		if err != nil {
			return nil, err
		}
		if !ok || !a.raisers[id] {
			free++
		}
	}
	if a.Needed > 1 && free > 0 {
		for _, s := range pol.seconds(rule) {
			if !a.eligible[auth.PersonKey(s.Principal)] {
				a.seconds[auth.PersonKey(s.Principal)] = s.As
			}
		}
	}
	a.Of = len(a.eligible) + len(a.seconds)
	if a.Of == 0 {
		// A store with nobody granted anything is its owner's, and whoever
		// is at it is the one person eligible.
		a.Of = 1
	}
	now := m.now()
	a.Expires = expiry(rule, p.Record, now)
	if r, ok, err := m.request(p, a.Hash, now); err != nil {
		return nil, err
	} else if ok {
		a.Signed, a.Until = r.Signers, r.Until
	}
	return a, nil
}

// needed is how many approvers a rule asks of a record, and the thresholds
// it is over.
func (m *Approvals) needed(rule Rule, rec register.Record) (int, []string, error) {
	n := 1
	if rule.Level == L4 {
		n = 2
	}
	n = max(n, rule.Needed)
	var over []string
	for _, th := range rule.Above {
		v, ok, err := m.number(rec, th.Field)
		if err != nil {
			return 0, nil, err
		}
		if ok && v >= th.AtLeast {
			over = append(over, fmt.Sprintf("%s is %d, and the threshold is %d", strings.ReplaceAll(th.Field, "_", " "), v, th.AtLeast))
		}
	}
	if len(over) > 0 {
		n = max(n, 2)
	}
	return n, over, nil
}

// number is a whole-number fact about a record for a threshold: one of its
// fields, one of the fields of the record it is about, or how many days it
// runs.
func (m *Approvals) number(rec register.Record, field string) (int64, bool, error) {
	fields := fieldsOf(rec)
	if field == "term_days" {
		starts, ok1 := fields["starts"].(float64)
		ends, ok2 := fields["expires"].(float64)
		if !ok1 || !ok2 {
			return 0, false, nil
		}
		return int64((ends - starts) / 86400), true, nil
	}
	if ref, sub, ok := strings.Cut(field, "."); ok {
		id, _ := fields[ref].(string)
		if !register.ID(id).Valid() {
			return 0, false, nil
		}
		e, err := m.Register.Get(register.ID(id))
		if errors.Is(err, register.ErrNotFound) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, err
		}
		fields, field = fieldsOf(e.Record), sub
	}
	v, ok := fields[field].(float64)
	return int64(v), ok, nil
}

// expiry is when an approval given now under a rule lapses: after the
// rule's term, or when the record itself ends, whichever is sooner. Zero
// does not lapse.
func expiry(rule Rule, rec register.Record, now time.Time) register.Time {
	var at register.Time
	if rule.TermDays > 0 {
		at = register.TimeOf(now.Add(time.Duration(rule.TermDays) * 24 * time.Hour))
	}
	if ends, ok := fieldsOf(rec)["expires"].(float64); ok && ends > 0 && (at == 0 || register.Time(ends) < at) {
		at = register.Time(ends)
	}
	return at
}

// Sign is one person's approval of a waiting decision, over the hash of
// what they were shown. With as many signatures as the rule asks, the
// record is written to the register, carrying its approval.
func (m *Approvals) Sign(by Person, id register.ID, proof Proof) (*Outcome, error) {
	if m.Audit == nil {
		return nil, fmt.Errorf("the approvals have no audit log to record a signature in, so nothing is signed")
	}
	pol, err := m.policy()
	if err != nil {
		return nil, err
	}
	a, err := m.Ask(id)
	if err != nil {
		return nil, err
	}
	now := m.now()
	refuse := func(err error) (*Outcome, error) {
		m.audited(by, audit.Denied, AuditRefused, map[string]string{"record": string(id),
			"kind": string(a.Proposal.Kind), "surface": string(a.Hash), "why": err.Error()})
		return nil, err
	}
	if err := m.mayDecide(pol, by); err != nil {
		return refuse(err)
	}
	subject, err := m.people().Pseudonym(by.Name)
	if err != nil {
		return nil, err
	}
	ev, err := m.evidenceOf(by, subject, ForApproval, a.Hash, proof, now)
	if err != nil {
		return refuse(err)
	}
	signed, err := m.canSign(pol, by, subject, a, now)
	if err != nil {
		return refuse(err)
	}
	d, err := keep(m.Root, ev)
	if err != nil {
		return nil, err
	}
	signed.Evidence = d
	return m.signed(pol, by, subject, a, signed, now)
}

// signed adds a signature to a request and, once there are enough, writes
// the record.
func (m *Approvals) signed(pol *Policy, by Person, subject register.ID, a *Ask, s Signed, now time.Time) (*Outcome, error) {
	var signers []Signed
	err := atomicfile.Update(m.requestsPath(), func(f *requestsFile) error {
		f.prune(now)
		r := f.find(a.Proposal.ID)
		if r == nil || r.Object != a.Proposal.Object || r.Surface != a.Hash {
			f.drop(a.Proposal.ID)
			f.Requests = append(f.Requests, request{Record: a.Proposal.ID, Object: a.Proposal.Object, Surface: a.Hash,
				Opened: register.TimeOf(now), Until: register.TimeOf(now.Add(time.Duration(pol.WaitDays) * 24 * time.Hour))})
			r = &f.Requests[len(f.Requests)-1]
		}
		for _, have := range r.Signers {
			if have.Subject == s.Subject {
				return errRefused("you have approved this already; each approver counts once")
			}
		}
		r.Signers = append(r.Signers, s)
		signers = append([]Signed(nil), r.Signers...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := &Outcome{Record: a.Proposal.ID, Surface: a.Hash, Evidence: s.Evidence, Signed: len(signers), Needed: a.Needed}
	detail := map[string]string{"record": string(a.Proposal.ID), "kind": string(a.Proposal.Kind), "surface": string(a.Hash),
		"evidence": string(s.Evidence), "method": string(s.Method), "rule": a.Rule.Name,
		"signed": fmt.Sprintf("%d of %d", len(signers), a.Needed)}
	if s.Batch != "" {
		detail["batch"] = string(s.Batch)
	}
	if err := m.audited(by, audit.Success, AuditSigned, detail); err != nil {
		return nil, fmt.Errorf("the signature could not be recorded, so it does not count: %w", err)
	}
	alone := a.AloneFor(subject)
	if !alone && !complete(a, signers) {
		return out, nil
	}
	ap := &register.Approval{Atom: string(a.Rule.Atom), Rule: a.Rule.Name, Needed: a.Needed, Of: a.Of,
		Surface: a.Hash, Raised: a.Raised, Alone: alone, Expires: a.Expires}
	if alone {
		ap.ReviewDue = register.TimeOf(now.Add(time.Duration(pol.ReviewDays) * 24 * time.Hour))
		signers = signers[len(signers)-1:]
	}
	for _, sg := range signers {
		ap.Signers = append(ap.Signers, register.Signer{Subject: sg.Subject, At: sg.At, Assertion: sg.Evidence,
			Method: sg.Method, Batch: sg.Batch})
	}
	if ap.Raised == "" && a.Proposal.Agent != "" {
		if ap.Raised, err = m.people().Pseudonym(a.Proposal.Agent); err != nil {
			return nil, err
		}
	}
	if ap.Raised == "" {
		ap.Raised = subject
	}
	rc, err := m.Register.Accept(m.actor(by, subject, a), a.Proposal.ID, ap)
	if err != nil && !errors.Is(err, register.ErrUnrecorded) {
		return nil, err
	}
	_ = atomicfile.Update(m.requestsPath(), func(f *requestsFile) error {
		f.drop(a.Proposal.ID)
		return nil
	})
	out.Done, out.Alone, out.Receipt = true, alone, &rc
	return out, err
}

// complete reports whether the signatures meet what the rule asks: enough
// of them, at least one by somebody who holds the atom, and a second from
// where the rule says a second comes from.
func complete(a *Ask, signers []Signed) bool {
	if len(signers) < a.Needed {
		return false
	}
	holds := false
	for _, s := range signers {
		holds = holds || s.Holds
	}
	if !holds {
		return false
	}
	if len(a.Rule.SecondFrom) > 0 && a.Needed > 1 {
		from := false
		for _, s := range signers {
			from = from || contains(a.Rule.SecondFrom, s.Function)
		}
		return from
	}
	return true
}

// actor is the signer as the register names a writer. Being eligible under
// the separation policy is what lets them write the decision, so the gate
// is asked the rule's atom for the kind, in place of the register's own
// permission to approve, and a second the policy names is eligible by
// being named; everything else is asked as their session asks.
func (m *Approvals) actor(by Person, subject register.ID, a *Ask) register.Actor {
	spec, _ := register.SpecOf(string(a.Proposal.Kind))
	return register.Actor{Name: by.Name, Subject: subject, Kind: by.Kind, Verified: by.Verified,
		May: func(act auth.Action, resource string) error {
			if act == auth.ActApprove && resource == spec.Resource() {
				if a.seconds[auth.PersonKey(by.Name)] != "" {
					return nil
				}
				return m.ask2(by, a.Rule.Atom, resource)
			}
			return m.ask2(by, act, resource)
		}}
}

// ask2 asks the access policy as the person's session does. A store with no
// access control asks nothing.
func (m *Approvals) ask2(by Person, act auth.Action, resource string) error {
	if by.May == nil {
		return errRefused("this surface did not say how to ask the access policy")
	}
	return by.May(act, resource)
}

// mayDecide is what is asked of anybody who approves, before anything about
// what they approve: a person, signed in a way that cannot be phished.
func (m *Approvals) mayDecide(pol *Policy, by Person) error {
	if by.Kind != audit.KindHuman {
		return errRefused("an approval is a person's: no agent or program approves anything, an agent's work included")
	}
	if strings.TrimSpace(by.Name) == "" || m.isAgent(by.Name) {
		return errRefused("an approval is a person's, named as the access policy names them")
	}
	if pol.PhishingResistant && !by.Console && !auth.PhishingResistant(by.Methods) {
		return errRefused("you signed in with %s, which can be phished, and whoever approves signs in with a passkey "+
			"or a single sign-on that used one; confirm it is you with your passkey first", methodsSaid(by.Methods))
	}
	return nil
}

// methodsSaid is how a session was signed in to, in words.
func methodsSaid(methods []string) string {
	switch {
	case len(methods) == 0:
		return "a token alone"
	case contains(methods, auth.MethodSSO):
		return "single sign-on that did not say it used a phishing-resistant method"
	case contains(methods, auth.MethodSSOOneFactor):
		return "single sign-on that did not say it used a second factor"
	}
	return "a token"
}

// evidenceOf is the person's proof as evidence, checked: over the hash of
// what is waiting now, and holding by itself.
func (m *Approvals) evidenceOf(by Person, subject register.ID, p Purpose, want register.Digest, proof Proof, now time.Time) (Evidence, error) {
	ev := Evidence{Purpose: p, Subject: subject, For: want, At: register.TimeOf(now)}
	switch {
	case proof.Passkey != nil && proof.Console == nil && !by.Console:
		purpose, of, err := ChallengeFor(proof.Passkey.Challenge)
		if err != nil {
			return Evidence{}, refusal{msg: err.Error()}
		}
		if purpose != p {
			return Evidence{}, errRefused("the passkey signed a challenge to %s, and this asks for one to %s", purpose, p)
		}
		if of != want {
			return Evidence{}, refusal{cause: ErrOtherSurface, msg: fmt.Sprintf("the passkey signed %s, and what is waiting "+
				"now is %s: another record, or this one since it changed. Nothing was approved; open it again and "+
				"approve what it shows", of, want)}
		}
		ev.Method, ev.Passkey = "passkey", proof.Passkey
	case proof.Console != nil && proof.Passkey == nil && by.Console:
		if proof.Console.Typed != want {
			return Evidence{}, refusal{cause: ErrOtherSurface, msg: fmt.Sprintf("the hash typed, %s, is not the hash of "+
				"what is waiting now, %s. Nothing was approved; show it again and type the hash it shows", clip(string(proof.Console.Typed)), want)}
		}
		ev.Method, ev.Console = "console", proof.Console
	default:
		return Evidence{}, errRefused("an approval is given with a fresh passkey assertion in the admin, or by an " +
			"administrator at the store's console who types the hash back")
	}
	if err := ev.Check(); err != nil {
		return Evidence{}, refusal{msg: err.Error()}
	}
	return ev, nil
}

// canSign holds a signer to the separation policy and the rules beneath
// it, and returns their signature as the request will hold it.
func (m *Approvals) canSign(pol *Policy, by Person, subject register.ID, a *Ask, now time.Time) (Signed, error) {
	key := auth.PersonKey(by.Name)
	spec, _ := register.SpecOf(string(a.Proposal.Kind))
	s := Signed{Subject: subject, At: register.TimeOf(now), Method: "passkey", Name: key}
	if by.Console {
		s.Method = "console"
	}
	// Eligible by holding the atom, as the person's own session is asked
	// it, or by being named as a second.
	holds := m.ask2(by, a.Rule.Atom, spec.Resource()) == nil && (a.eligible[key] || m.Access == nil || len(a.eligible) == 0)
	fn := a.seconds[key]
	if !holds && fn == "" {
		return s, errRefused("approving this needs %s on %s, or being named in the separation policy as a second "+
			"approver for %s, and you are neither", a.Rule.Atom, strings.ToLower(string(a.Proposal.Kind)), a.Rule.Name)
	}
	s.Holds, s.Function = holds, fn
	if s.Function == "" {
		s.Function = pol.functionOf(by.Name)
	}
	alone := a.AloneFor(subject)
	if alone && !holds {
		return s, errRefused("the one person eligible approves this alone; a second named in the separation " +
			"policy approves beside them, not in their place")
	}
	raiser := a.raisers[subject] || (a.Proposal.Agent != "" && auth.SamePerson(a.Proposal.Agent, by.Name))
	if raiser && !alone {
		return s, errRefused("you raised or drafted this %s, and whoever raises a decision does not approve it; "+
			"%d other people may", strings.ToLower(string(a.Proposal.Kind)), a.Of-1)
	}
	if a.Proposal.Agent != "" && auth.SamePerson(a.Proposal.Agent, by.Name) {
		return s, errRefused("an agent does not approve its own proposal")
	}
	for _, have := range a.Signed {
		if have.Subject == subject || auth.SamePerson(have.Name, by.Name) {
			return s, errRefused("you have approved this already; each approver counts once")
		}
	}
	if alone {
		if m.Settling != nil {
			held, err := m.Settling(now)
			if err != nil {
				return s, err
			}
			if held != nil {
				return s, errRefused("%s", held.Refusal())
			}
		}
		return s, nil
	}
	// The signature that would complete the approval has to complete it
	// as the rule says: with a second from where the rule takes one, and
	// with somebody who holds the atom among them.
	after := append(append([]Signed(nil), a.Signed...), s)
	if len(after) >= a.Needed && !complete(a, after) {
		if len(a.Rule.SecondFrom) > 0 && a.Needed > 1 {
			return s, errRefused("the second approver of this decision is the organisation's %s, as the separation "+
				"policy names them", strings.Join(a.Rule.SecondFrom, " or "))
		}
		return s, errRefused("somebody who holds %s approves this first; a second named in the separation policy "+
			"approves beside them, not in their place", a.Rule.Atom)
	}
	return s, nil
}

// audited records a signature, or a refusal of one.
func (m *Approvals) audited(by Person, outcome audit.Outcome, action string, detail map[string]string) error {
	if m.Audit == nil {
		return nil
	}
	kind := by.Kind
	if !kind.Valid() {
		kind = audit.KindUnknown
	}
	return m.Audit(audit.Record{Action: action, Resource: register.Area, Outcome: outcome, Principal: by.Name,
		Kind: kind, Verified: by.Verified && kind != audit.KindUnknown, Detail: detail})
}

// Reject takes a waiting decision off the proposals ref, as a person who
// may approve it, writing nothing to the register.
func (m *Approvals) Reject(by Person, id register.ID) error {
	pol, err := m.policy()
	if err != nil {
		return err
	}
	a, err := m.Ask(id)
	if err != nil {
		return err
	}
	if err := m.mayDecide(pol, by); err != nil {
		return err
	}
	subject, err := m.people().Pseudonym(by.Name)
	if err != nil {
		return err
	}
	if err := m.Register.Reject(m.actor(by, subject, a), id); err != nil {
		return err
	}
	return atomicfile.Update(m.requestsPath(), func(f *requestsFile) error {
		f.drop(id)
		return nil
	})
}

// The requests waiting for more approvers, in one file beside the store.

type request struct {
	Record  register.ID     `json:"record"`
	Object  string          `json:"object"`
	Surface register.Digest `json:"surface"`
	Signers []Signed        `json:"signers"`
	Opened  register.Time   `json:"opened"`
	Until   register.Time   `json:"until"`
}

type requestsFile struct {
	Requests []request `json:"requests"`
}

func (m *Approvals) requestsPath() string { return filepath.Join(m.Root, "approvals", "requests.json") }

func (f *requestsFile) find(id register.ID) *request {
	for i := range f.Requests {
		if f.Requests[i].Record == id {
			return &f.Requests[i]
		}
	}
	return nil
}

func (f *requestsFile) drop(id register.ID) {
	kept := f.Requests[:0]
	for _, r := range f.Requests {
		if r.Record != id {
			kept = append(kept, r)
		}
	}
	f.Requests = kept
}

// prune lets requests whose wait is over lapse, with their signatures:
// approvals expire while they are being gathered too, so a signature given
// months ago does not complete a decision today.
func (f *requestsFile) prune(now time.Time) {
	kept := f.Requests[:0]
	for _, r := range f.Requests {
		if register.TimeOf(now) < r.Until {
			kept = append(kept, r)
		}
	}
	f.Requests = kept
}

// request is the open request for a proposal as it stands, if there is one.
func (m *Approvals) request(p register.Proposal, surface register.Digest, now time.Time) (request, bool, error) {
	var out request
	var ok bool
	err := atomicfile.Update(m.requestsPath(), func(f *requestsFile) error {
		f.prune(now)
		if r := f.find(p.ID); r != nil && r.Object == p.Object && r.Surface == surface {
			out, ok = *r, true
		}
		return atomicfile.ErrUnchanged
	})
	return out, ok, err
}
