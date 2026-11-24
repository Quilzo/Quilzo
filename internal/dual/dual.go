// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package dual keeps the privileged changes that wait for a second
// administrator (NIST SP 800-53 AC-5, CM-5(4) and AU-9(5): dual
// authorisation).
//
// Making somebody an administrator (by hand, or by mapping an identity
// provider's group), issuing an administrator's token or an enrolment link
// that adds a passkey for one, making the provisioning token while a group
// makes administrators, weakening a setting,
// lowering how many approvals a change needs, moving the audit log and
// letting an agent send to another system from runs nobody started are
// each something one person, or whoever has their
// session, could do to take a store over or to hide that they had. So one
// administrator proposes and another approves, and the request records
// both. A store with one administrator is not left unable to change
// anything: their own request is applied as they make it, and the record
// says it was approved alone. Not for a day after another administrator
// stopped being one, though (Settle): removing the other was otherwise the
// way to approve anything alone.
//
// The store keeps the request, not the change: what applying a request
// does is its caller's, by kind, because the changes live in different
// parts of the program.
package dual

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/scim"
)

// The kinds of change that wait.
const (
	// Grant is a binding that makes somebody an administrator of
	// something.
	Grant = "grant"
	// Token is an administrator's token, issued to whoever asked once
	// another administrator agrees.
	Token = "token"
	// Setting is a setting weakened, or an approval count lowered.
	Setting = "setting"
	// AuditLog is the audit log moved to another directory.
	AuditLog = "auditlog"
	// Mapping is an identity provider's group mapped to a role or a job
	// that makes its members administrators.
	Mapping = "mapping"
	// Pay is the site starting to take money, through a provider's hosted
	// checkout: from then on a price on a page is a price somebody pays.
	Pay = "pay"
	// Enrol is a passkey enrolment link for somebody who administers
	// something, given to whoever asked once another administrator agrees.
	Enrol = "enrol"
	// SCIMToken is the identity provider's provisioning token while a
	// group it sends makes administrators, given to whoever asked once
	// another administrator agrees.
	SCIMToken = "scim-token"
	// Approval is the approval policy `quilzo review require` writes,
	// when it asks fewer people, or people the policy in force does not
	// name, to approve a change.
	Approval = "approval"
	// Sends is an agent let send through one tool, or one of its hands'
	// actions, from the runs nobody started, without a person deciding
	// each call. A triggered run's write to another system, or its hand's
	// reach out to one, otherwise waits for one, because what goes
	// out from a run nobody started is a person's decision; one
	// administrator lifting that for every run to come is a widening
	// nobody else saw.
	Sends = "unattended-sends"
)

// ApprovalChange is an Approval request: the policy, as approval.json
// holds it.
type ApprovalChange struct {
	Required       int      `json:"required"`
	RequiredHumans int      `json:"required_humans,omitempty"`
	Approvers      []string `json:"approvers,omitempty"`
}

// SendsChange is a Sends request: the agent, the tool or the hand's
// action, and the host it reaches (for a hand, every host it may reach),
// which the grant is for and only for.
type SendsChange struct {
	Agent string `json:"agent"`
	Tool  string `json:"tool"`
	Host  string `json:"host"`
}

// PayChange is a Pay request: the provider, and how its checkout behaves.
type PayChange struct {
	Provider string   `json:"provider"`
	ShipTo   []string `json:"ship_to,omitempty"`
	Done     string   `json:"done,omitempty"`
}

// GrantChange is a Grant request: bindings granted together.
type GrantChange struct {
	Bindings []auth.Binding `json:"bindings"`
}

// TokenChange is a Token request: the command that issues it, run again
// for whoever asked once it is approved.
type TokenChange struct {
	Args []string `json:"args"`
}

// EnrolChange is an Enrol request: who the link adds a passkey for, and
// how long it waits to be opened once it is made (zero is the longest).
type EnrolChange struct {
	Principal string        `json:"principal"`
	For       time.Duration `json:"for,omitempty"`
}

// SCIMTokenChange is a SCIMToken request: how many days the token works
// (zero is the usual length).
type SCIMTokenChange struct {
	Days int `json:"days,omitempty"`
}

// Received reports whether an approved request of this kind is a
// credential that waits for whoever asked to receive it, once, rather than
// a change made as it is approved: an administrator's token, an enrolment
// link and a provisioning token, whose secret is shown only to the person
// it is given to.
func Received(kind string) bool {
	return kind == Token || kind == Enrol || kind == SCIMToken
}

// SettingChange is a Setting request.
type SettingChange struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Reason string `json:"reason,omitempty"`
}

// AuditLogChange is an AuditLog request: the directory the log moves to.
type AuditLogChange struct {
	Dir string `json:"dir"`
}

// MappingChange is a Mapping request: what the group's members become.
type MappingChange struct {
	Group string `json:"group"`
	To    string `json:"to"`
}

// MapsToAdministrator reports whether a group mapped to this, a role or a
// job, makes its members administrators of anything, which is what a
// Mapping request is for. Who is in the group is the identity provider's
// to say from then on, so the mapping is the grant. A mapping that ends on
// a day (scim.MappedUntil) is asked about what it grants until then, so the
// day written after a job cannot hide that the job makes administrators.
func MapsToAdministrator(to string) bool {
	to, _, _ = scim.SplitMapping(to)
	if job, ok := auth.JobNamed(to); ok {
		return Privileged(job.Bindings)
	}
	return auth.Role(to) == auth.RoleAdmin
}

// Privileged reports whether bindings make somebody an administrator of
// anything, which is what a Grant request is for.
func Privileged(bindings []auth.Binding) bool {
	for _, b := range bindings {
		if !b.Deny && b.Role == auth.RoleAdmin {
			return true
		}
	}
	return false
}

// Lowering are the settings whose every decrease waits for a second
// administrator, because each is how many people a change needs.
var Lowering = []string{"review.required_approvals", "approval.required_humans"}

// AppliesAbove is, for each of the Lowering settings, the count that applies
// where it is more than the setting says: approvals is how many approvals
// publishing needs and people how many of them from people, as they apply.
//
// The count that applies is the larger of the setting and approval.json, which
// `quilzo review require` writes, so a setting can say less than applies. Said
// beside it, wherever it is shown or set: `config set review.required_approvals
// 2` under a file asking five said "= 2", and so did the settings screen.
func AppliesAbove(c *config.Config, approvals, people int) map[string]string {
	out := map[string]string{}
	for key, n := range map[string]int{Lowering[0]: approvals, Lowering[1]: people} {
		if set, _ := strconv.Atoi(strings.TrimSpace(c.Raw(key))); n > set {
			out[key] = fmt.Sprintf("%d apply: approval.json, written by quilzo review require, asks "+
				"more than this, and the larger of the two applies", n)
		}
	}
	return out
}

// SettingNeedsSecond says why a setting's new value waits for a second
// administrator: weaker than the default, or fewer people needed for a
// change than now (c is the configuration as it stands).
func SettingNeedsSecond(c *config.Config, key, value string) (bool, string) {
	if s, ok := config.Lookup(key); ok {
		if weaker, why := s.IsWeaker(value); weaker {
			return true, why
		}
	}
	for _, k := range Lowering {
		if k != key {
			continue
		}
		now, nerr := strconv.Atoi(strings.TrimSpace(c.Raw(key)))
		next, xerr := strconv.Atoi(strings.TrimSpace(value))
		if nerr != nil || xerr != nil || next < now {
			return true, fmt.Sprintf("%s from %s to %s: fewer people would approve a change", key, c.Raw(key), value)
		}
	}
	return false, ""
}

// Wait is how long a request waits for a decision, and Redeem how long an
// approved token may wait to be issued to whoever asked for it.
const (
	Wait   = 7 * 24 * time.Hour
	Redeem = 24 * time.Hour
)

// The states a request is in.
const (
	Waiting   = "waiting"
	Approved  = "approved"
	Declined  = "declined"
	Withdrawn = "withdrawn"
	Done      = "done"
)

// Request is one privileged change and who decided it.
type Request struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// What is the change in words, for the person deciding.
	What string `json:"what"`
	// Payload is the change itself, as its kind's caller reads it.
	Payload json.RawMessage `json:"payload"`
	Why     string          `json:"why,omitempty"`
	By      string          `json:"by"`
	At      time.Time       `json:"at"`
	State   string          `json:"state"`
	// DecidedBy decided it and Alone says they were the only
	// administrator, deciding their own request.
	DecidedBy string    `json:"decided_by,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitzero"`
	Alone     bool      `json:"alone,omitempty"`
}

// About is who a request is about, under the identity keys an audit
// record carries them by: the person a grant is for ("subject"), or the
// one a token acts as ("for"). What, the sentence a person deciding reads,
// names them; a record that copies it carries this beside it, and the log
// pseudonymises them in both.
func (r Request) About() map[string]string {
	switch r.Kind {
	case Grant:
		var ch GrantChange
		if json.Unmarshal(r.Payload, &ch) == nil && len(ch.Bindings) > 0 && ch.Bindings[0].Principal != "" {
			return map[string]string{"subject": ch.Bindings[0].Principal}
		}
	case Enrol:
		var ch EnrolChange
		if json.Unmarshal(r.Payload, &ch) == nil && ch.Principal != "" {
			return map[string]string{"for": ch.Principal}
		}
	case Token:
		var ch TokenChange
		if json.Unmarshal(r.Payload, &ch) != nil {
			return nil
		}
		for i, a := range ch.Args {
			name := strings.TrimLeft(a, "-")
			if len(name) == len(a) {
				continue
			}
			if v, ok := strings.CutPrefix(name, "principal="); ok {
				return map[string]string{"for": v}
			}
			if name == "principal" && i+1 < len(ch.Args) {
				return map[string]string{"for": ch.Args[i+1]}
			}
		}
	}
	return nil
}

// Approvers is whose approval an Approval request would count, as whoever
// decides it reads them, or empty for any other request and for one that
// counts anybody who may publish, which What says.
//
// Beside What rather than in it: every record of a request copies What in
// clear, with only the one person About names pseudonymised, and a list of
// people has no one identity key to go under. Left out altogether, the
// administrator deciding read "to somebody the list in force does not
// name" on People and in quilzo pending, and let somebody's approval count
// without being told whose.
func (r Request) Approvers() string {
	if r.Kind != Approval {
		return ""
	}
	var ch ApprovalChange
	if json.Unmarshal(r.Payload, &ch) != nil {
		return ""
	}
	return strings.Join(ch.Approvers, ", ")
}

// Open reports whether a request still waits for a decision at now.
func (r Request) Open(now time.Time) bool {
	return r.State == Waiting && now.Before(r.At.Add(Wait))
}

// Redeemable reports whether an approved token or link may still be
// issued.
func (r Request) Redeemable(now time.Time) bool {
	return r.State == Approved && now.Before(r.DecidedAt.Add(Redeem))
}

type file struct {
	Requests []Request `json:"requests"`
	// Removed is the last administrator who stopped being one while
	// another still was, until two or more hold the role again.
	Removed *Removal `json:"removed,omitempty"`
}

// Settle is how long, after an administrator stops being one, the
// administrator left does not approve alone, unless two or more hold the
// role again before it is over.
//
// One administrator may remove another; that is not dual-controlled. And
// the only administrator approves alone. Together, two administrators
// became one in a single step, and the one approved their own requests at
// once, including the one the other would have refused. A day is long
// enough for the person removed, or anybody watching the log, to notice
// and say so before anything is approved on one person's word.
const Settle = 24 * time.Hour

// Removal is an administrator who stopped being one, and when.
type Removal struct {
	Principal string    `json:"principal"`
	At        time.Time `json:"at"`
}

// Until is when approving alone is allowed again.
func (r Removal) Until() time.Time { return r.At.Add(Settle) }

// Refusal is why approving alone is refused, and until when, as the
// person refused reads it. It names nobody: it is said where a record may
// copy it, and the person removed is in the record under an identity key.
func (r Removal) Refusal() string {
	const when = "15:04 MST on 2 Jan 2006"
	return fmt.Sprintf("approving alone is refused until %s: an administrator stopped being one at %s, "+
		"and for a day after that the administrator left does not approve alone. Another administrator "+
		"approves it, or you do once the day is over", r.Until().UTC().Format(when), r.At.UTC().Format(when))
}

// Detail is the removal as the record of a refusal carries it: who was
// removed (an identity key, so the log pseudonymises them), when, and
// until when approving alone is refused.
func (r Removal) Detail() map[string]string {
	return map[string]string{"subject": r.Principal, "removed_at": r.At.UTC().Format(time.RFC3339),
		"until": r.Until().UTC().Format(time.RFC3339)}
}

// Administrators are who pol lets administer the whole site now, by name
// in lower case: a binding that has ended, or one a deny outranks, is
// nobody. These are who could approve a request; only they count towards
// whether somebody is the only one.
func Administrators(pol *auth.Policy) map[string]bool {
	out := map[string]bool{}
	if pol == nil {
		return out
	}
	for _, b := range pol.Snapshot() {
		if !b.Deny && b.Role == auth.RoleAdmin && pol.Evaluate(b.Principal, auth.ActGrant, "/").Allowed {
			out[strings.ToLower(b.Principal)] = true
		}
	}
	return out
}

// Administered reports whether anybody at all may grant access on the whole
// site under pol, by any binding: a role, a permission or a job. Wider than
// Administrators, which counts who could approve a request, because the
// question here is whether the store can be administered at all.
func Administered(pol *auth.Policy) bool {
	if pol == nil {
		return false
	}
	for _, who := range pol.Principals() {
		if pol.Evaluate(who, auth.ActGrant, "/").Allowed {
			return true
		}
	}
	return false
}

// ErrLastAdministrator is a change to the access policy that would leave a
// store somebody administered with nobody able to administer it.
//
// Refused wherever the policy is written, rather than by each command that
// can take access away. People refused revoking your own last admin
// binding, and the access review a revoke that left nobody; `quilzo auth
// revoke` and `auth deny` asked nothing, so the only administrator tidying
// up a binding locked the store, and the break-glass then refused to
// help. One rule in the one place every change passes cannot be forgotten
// by the next command that removes access.
var ErrLastAdministrator = errors.New("that would leave nobody able to administer this store, so it is refused; " +
	"grant another administrator first")

// KeepsAnAdministrator is ErrLastAdministrator when a store that was
// administered (was, asked before the change) is not after it.
func KeepsAnAdministrator(was bool, after *auth.Policy) error {
	if was && !Administered(after) {
		return ErrLastAdministrator
	}
	return nil
}

// FirstWayIn reports whether a credential for subject, an administrator
// who holds none (held is false), asked for by asker, is one asker is the
// only administrator able to decide: nobody but the two of them
// administers the whole site.
//
// An administrator granted before their passkey could never be given one.
// Every way in for them waited for a second administrator, and the only
// other administrator was them, with no way to sign in and approve it;
// the other order, a passkey as an author and then admin, worked. Until
// they hold a credential there is one administrator who can act, and her
// request is hers alone, as it would be in the other order. Once they hold
// one there are two, and this is false: one administrator does not give
// herself another's sign-in.
//
// Nor while asker has a request waiting (OpenBy), which subject would be
// the one to decide: given their sign-in alone, asker would approve her
// own request as them. She withdraws it first, and asks again once there
// are two administrators who can sign in.
//
// Held is whether subject is, or has been, an administrator who could act:
// a token or session (WayIn), a passkey, or single sign-on that could sign
// them in (SingleSignOn).
func FirstWayIn(pol *auth.Policy, asker, subject string, held bool) bool {
	if held || pol == nil || strings.EqualFold(asker, subject) {
		return false
	}
	admins := Administrators(pol)
	if !admins[strings.ToLower(subject)] {
		return false
	}
	delete(admins, strings.ToLower(subject))
	return len(admins) == 1 && admins[strings.ToLower(asker)]
}

// WayIn reports whether tokens show subject, an administrator under pol,
// to be one who could act as it: a token or session of theirs that could
// approve a request (approves) works at now, was a sign-in (a session)
// made since they became an administrator, or has been used since then.
//
// FirstWayIn was told only what worked at the moment it was asked, so the
// first way in came back whenever nothing of the other administrator's
// did. One administrator revoked the other's token, which is one
// administrator's to do, was told he had no way to sign in yet, issued
// herself a token as him and approved her own request with it. A token of
// his that had run out did as well.
//
// What never made them a second administrator does not count, or the dead
// end FirstWayIn ends would come back: a token that stopped working before
// anybody used it, as a first one issued for an hour and not passed on in
// time is, and anything not used since they were made an administrator,
// so somebody made one again a day after being removed (Settle) starts as
// they did the first time.
//
// Used since, whenever it was made. Only a token made since the grant
// counted, so an analyst with an administrator's token, who administered
// an area and was then made an administrator of the site, went on acting
// with it and was still taken for somebody with no way in the moment the
// other administrator revoked it.
func WayIn(pol *auth.Policy, tokens []auth.Token, subject string, now time.Time) bool {
	since := administratorSince(pol, subject, now)
	for _, t := range tokens {
		if !strings.EqualFold(t.Principal, subject) || !approves(t) {
			continue
		}
		if ok, _ := t.Usable(now); ok {
			return true
		}
		if t.IsSession() && t.CreatedAt >= since {
			return true
		}
		if t.LastUsed != 0 && t.LastUsed >= since {
			return true
		}
	}
	return false
}

// approves reports whether a token could decide a request for a second
// administrator, whoever holds it: it carries an administrator's role over
// the whole site and refuses no write (auth.CheckCredential), which is
// what `quilzo pending approve` and the People screen ask of a credential.
//
// A token is a ceiling. Any token of the subject's counted as their way
// in, so an author with a token for the command line, made an
// administrator, could not then be given a passkey: the link waited for a
// second administrator, the only other one was them, and their token was
// refused with "this credential carries author and grant needs admin". One
// issued narrower than their role after the grant did the same, for good
// once it had been used. Neither made them an administrator who could act,
// and waiting on them was the dead end FirstWayIn ends.
func approves(t auth.Token) bool {
	return auth.CheckCredential(t.Role, t.Resource, t.Scope, auth.ActGrant, "/") == nil
}

// administratorSince is when subject became an administrator of the whole
// site under pol: the earliest of the grants that make them one now. Zero
// when none says, which counts everything they ever held.
func administratorSince(pol *auth.Policy, subject string, now time.Time) int64 {
	var since int64
	found := false
	if pol == nil {
		return 0
	}
	for _, b := range pol.Snapshot() {
		if b.Deny || b.Role != auth.RoleAdmin || !b.Live(now) || !strings.EqualFold(b.Principal, subject) ||
			strings.Trim(strings.TrimSpace(b.Resource), "/") != "" {
			continue
		}
		if !found || b.GrantedAt < since {
			since, found = b.GrantedAt, true
		}
	}
	return since
}

// SingleSignOn is an identity provider set up for signing in, as far as
// who it could sign in: the domains its people's addresses are in, none
// meaning any, and Opaque when it names people by something that is not an
// address.
//
// Somebody it could sign in holds a way in whatever else they hold
// (FirstWayIn). An administrator who signs in through the identity
// provider has no passkey and no token, and a day after their last session
// ended has nothing on record at all: taken for somebody with no way in
// yet, their sign-in was the other administrator's to give herself.
type SingleSignOn struct {
	Domains []string
	Opaque  bool
}

// OpenIDConnect is the SingleSignOn an OpenID Connect provider is, by the
// claim that names the person: a sub is any name, a preferred_username an
// address in the provider's domains, and an email any address, which the
// domains set for it do not narrow everywhere.
func OpenIDConnect(claim string, domains []string) SingleSignOn {
	switch claim {
	case "sub":
		return SingleSignOn{Opaque: true}
	case "preferred_username":
		return SingleSignOn{Domains: domains}
	}
	return SingleSignOn{}
}

// SAML is the SingleSignOn a SAML provider is: an address in its domains,
// or with none set whoever it names.
func SAML(domains []string) SingleSignOn {
	return SingleSignOn{Domains: domains, Opaque: len(domains) == 0}
}

// Covers reports whether the provider could sign name in.
func (s SingleSignOn) Covers(name string) bool {
	_, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(name)), "@")
	if !ok || domain == "" {
		return s.Opaque
	}
	if len(s.Domains) == 0 {
		return true
	}
	for _, d := range s.Domains {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// NoteAdministrators records a change to who administers the whole site,
// from before to after, at now. Somebody who stopped being one while
// another still was starts a day in which the administrator left does not
// approve alone; two or more holding the role ends it. A store that has
// never had two administrators is not touched.
//
// Called by whatever writes the access policy, under its lock, so every
// way an administrator stops being one is seen: revoked, denied, or
// deprovisioned by the identity provider.
func (s Store) NoteAdministrators(before, after map[string]bool, now time.Time) error {
	var gone []string
	for p := range before {
		if !after[p] {
			gone = append(gone, p)
		}
	}
	sort.Strings(gone)
	removed := len(gone) > 0 && len(before) >= 2 && len(after) < 2
	again := len(after) >= 2 && len(before) < 2
	if !removed && !again {
		return nil
	}
	return atomicfile.Update(s.Path, func(f *file) error {
		if again {
			if f.Removed == nil {
				return atomicfile.ErrUnchanged
			}
			f.Removed = nil
			return nil
		}
		f.Removed = &Removal{Principal: gone[0], At: now.UTC()}
		return nil
	})
}

// Settling is the removal the administrator left is still waiting out at
// now, or nil when approving alone is not refused.
func (s Store) Settling(now time.Time) (*Removal, error) {
	var out *Removal
	err := atomicfile.Update(s.Path, func(f *file) error {
		if f.Removed != nil && now.Before(f.Removed.Until()) {
			r := *f.Removed
			out = &r
		}
		return atomicfile.ErrUnchanged
	})
	return out, err
}

// Store is the requests, in one file.
type Store struct {
	Path string
}

// ErrNoRequest is an id that names no request.
var ErrNoRequest = errors.New("there is no such request")

// ErrRefused is what a refusal by the rule of two people is, for errors.Is:
// a request approved by the person who made it, or withdrawn or redeemed by
// somebody else. Each refusal keeps its own words; this is for a caller that
// has to tell a refusal from a request that could not be read, as the
// command line does, which exited 1 for an administrator approving their
// own request where the help documents 3 for a refusal by a gate.
var ErrRefused = errors.New("refused by the rule of two people")

// refused is a refusal in its own words that is ErrRefused.
type refused struct{ error }

func (refused) Is(target error) bool { return target == ErrRefused }

// Propose records a request. alone says the proposer is the only
// administrator, so it is decided as it is made, done, for them to apply.
func (s Store) Propose(kind, what string, payload any, why, by string, alone bool, now time.Time) (Request, error) {
	if strings.TrimSpace(by) == "" {
		return Request{}, errors.New("a request is somebody's: nobody was named")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Request{}, err
	}
	id := make([]byte, 4)
	if _, err := rand.Read(id); err != nil {
		return Request{}, err
	}
	r := Request{ID: hex.EncodeToString(id), Kind: kind, What: what, Payload: raw,
		Why: strings.TrimSpace(why), By: by, At: now.UTC(), State: Waiting}
	if alone {
		r.State, r.DecidedBy, r.DecidedAt, r.Alone = Done, by, now.UTC(), true
	}
	err = atomicfile.Update(s.Path, func(f *file) error {
		f.Requests = append(prune(f.Requests, now), r)
		return nil
	})
	return r, err
}

// Decide approves or declines a waiting request. Nobody decides their own,
// unless alone says they are the only administrator. An approved token or
// enrolment link waits for whoever asked to redeem it; anything else
// approved is done, for the approver to apply.
func (s Store) Decide(id, by string, approve, alone bool, now time.Time) (Request, error) {
	var out Request
	err := atomicfile.Update(s.Path, func(f *file) error {
		r := find(f.Requests, id)
		if r == nil {
			return ErrNoRequest
		}
		if !r.Open(now) {
			return fmt.Errorf("request %s is %s, not waiting", r.ID, stateWords(*r, now))
		}
		// One rule for who is the same person, everywhere a second one is
		// asked for (auth.SamePerson).
		if approve && auth.SamePerson(r.By, by) && !alone {
			return refused{fmt.Errorf("request %s is yours: another administrator approves it", r.ID)}
		}
		r.DecidedBy, r.DecidedAt = by, now.UTC()
		r.Alone = alone && auth.SamePerson(r.By, by)
		switch {
		case !approve:
			r.State = Declined
		case Received(r.Kind):
			r.State = Approved
		default:
			r.State = Done
		}
		out = *r
		return nil
	})
	return out, err
}

// Withdraw takes back a request its proposer no longer wants.
func (s Store) Withdraw(id, by string, now time.Time) (Request, error) {
	var out Request
	err := atomicfile.Update(s.Path, func(f *file) error {
		r := find(f.Requests, id)
		if r == nil {
			return ErrNoRequest
		}
		if !strings.EqualFold(r.By, by) {
			return refused{fmt.Errorf("request %s is %s's to withdraw", r.ID, r.By)}
		}
		if !r.Open(now) && !r.Redeemable(now) {
			return fmt.Errorf("request %s is %s", r.ID, stateWords(*r, now))
		}
		r.State = Withdrawn
		out = *r
		return nil
	})
	return out, err
}

// Redeem uses an approved token or enrolment link request, once, for
// whoever made it.
func (s Store) Redeem(id, by string, now time.Time) (Request, error) {
	var out Request
	err := atomicfile.Update(s.Path, func(f *file) error {
		r := find(f.Requests, id)
		if r == nil || !Received(r.Kind) {
			return ErrNoRequest
		}
		if !strings.EqualFold(r.By, by) {
			return refused{fmt.Errorf("request %s was %s's: only they receive the token", r.ID, r.By)}
		}
		if !r.Redeemable(now) {
			return fmt.Errorf("request %s is %s", r.ID, stateWords(*r, now))
		}
		r.State = Done
		out = *r
		return nil
	})
	return out, err
}

// Get is one request.
func (s Store) Get(id string) (Request, error) {
	var out Request
	err := atomicfile.Update(s.Path, func(f *file) error {
		r := find(f.Requests, id)
		if r == nil {
			return ErrNoRequest
		}
		out = *r
		return atomicfile.ErrUnchanged
	})
	return out, err
}

// OpenBy is the requests by asker still waiting for a decision at now,
// which subject would decide were they given a way in (FirstWayIn): every
// one but a way in for subject themselves, an enrolment link for them or
// a token as them.
//
// Those were counted too, and each ask stood in the way of the next. An
// ask refused alone because a request waited was left waiting itself, so
// once the first was withdrawn the ask after it was refused for the one
// before, and a store that reached the dead end before FirstWayIn ended
// it, with a link and a token for subject both waiting, stayed in it.
// Approving one as subject gives asker their sign-in, which the first way
// in is; it is the other requests she would be deciding for herself.
func (s Store) OpenBy(asker, subject string, now time.Time) ([]Request, error) {
	pend, err := s.Pending(now)
	var out []Request
	for _, r := range pend {
		if r.Open(now) && auth.SamePerson(r.By, asker) && !r.wayInFor(subject) {
			out = append(out, r)
		}
	}
	return out, err
}

// wayInFor reports whether a request is for a credential subject would
// sign in with: an enrolment link for them, or a token as them.
func (r Request) wayInFor(subject string) bool {
	return (r.Kind == Enrol || r.Kind == Token) && subject != "" && strings.EqualFold(r.About()["for"], subject)
}

// Pending are the requests still waiting, and the approved tokens still
// waiting to be issued, oldest first.
func (s Store) Pending(now time.Time) ([]Request, error) {
	var out []Request
	err := atomicfile.Update(s.Path, func(f *file) error {
		for _, r := range f.Requests {
			if r.Open(now) || r.Redeemable(now) {
				out = append(out, r)
			}
		}
		return atomicfile.ErrUnchanged
	})
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, err
}

// StateWords is a request's state as a person reads it.
func StateWords(r Request, now time.Time) string { return stateWords(r, now) }

func stateWords(r Request, now time.Time) string {
	switch {
	case r.State == Waiting && !r.Open(now):
		return "expired"
	case r.State == Approved && !r.Redeemable(now):
		return "approved and never used"
	case r.State == Approved:
		return "approved, waiting for " + r.By + " to receive it"
	case r.State == Done && r.Alone:
		return "approved alone by " + r.DecidedBy
	case r.State == Done:
		return "approved by " + r.DecidedBy
	}
	return r.State
}

func find(rs []Request, id string) *Request {
	id = strings.TrimSpace(id)
	for i := range rs {
		if rs[i].ID == id {
			return &rs[i]
		}
	}
	return nil
}

// prune keeps the record of decisions for a year, so the file does not
// grow without end; the audit log keeps them for ever.
func prune(rs []Request, now time.Time) []Request {
	kept := rs[:0]
	for _, r := range rs {
		if now.Sub(r.At) < 365*24*time.Hour {
			kept = append(kept, r)
		}
	}
	return kept
}
