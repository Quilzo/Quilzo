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
// lowering how many approvals a change needs and moving the audit log are
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
)

// ApprovalChange is an Approval request: the policy, as approval.json
// holds it.
type ApprovalChange struct {
	Required       int      `json:"required"`
	RequiredHumans int      `json:"required_humans,omitempty"`
	Approvers      []string `json:"approvers,omitempty"`
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
			return fmt.Errorf("request %s is yours: another administrator approves it", r.ID)
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
			return fmt.Errorf("request %s is %s's to withdraw", r.ID, r.By)
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
			return fmt.Errorf("request %s was %s's: only they receive the token", r.ID, r.By)
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
