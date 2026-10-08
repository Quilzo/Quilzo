// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package auth decides who may do what, and tries to make the narrow answer the
// easy one.
//
// # What was borrowed, and what was not
//
// Google Cloud IAM has the right core idea: you do not attach permissions to
// people. You create a *binding* — this principal, this role, on this resource —
// and child resources inherit it. That collapses an enormous number of
// individual grants into a few, and it is the part worth copying.
//
// The rest of that design is a warning. Google's own documentation tells you not
// to use its basic roles in production because they carry thousands of
// permissions, and practitioners describe the predictable outcome: most projects
// end up over-permissioned "because granting broad roles is quick and easy while
// figuring out the right narrow role takes effort".
//
// That sentence is the whole design brief. People do not over-grant because they
// want to; they over-grant because the correct thing is harder. So:
//
//   - There are four roles, they form a ladder, and there are no custom roles.
//     Nothing here assembles permissions, because permission assembly is the
//     mechanism by which a role surface becomes unreviewable.
//   - The roles match the workflow rather than the storage model. Publishing is
//     the only action with an outside observer, so it is the sharp boundary, and
//     the ladder is built around it.
//   - `Explain` is a first-class operation. Google needed a separate Policy
//     Troubleshooter product because "why can this person do that" is genuinely
//     hard to answer once inheritance is involved. If the answer is hard to get,
//     nobody audits, and unaudited access drifts.
//
// # One place this deliberately differs
//
// In GCP, inheritance is additive and cannot be revoked from below: a child
// cannot remove a binding set on its parent. That forces the broad grant it warns
// against — if you cannot say "everything except /legal", you grant everything.
//
// Here an explicit deny always wins, wherever it sits. One sentence, no ordering
// rules, no interaction table. That is more expressive than additive-only and
// still simple enough to hold in your head, which additive-plus-conditions is
// not.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Role is a rung on the ladder. Higher includes everything below it.
type Role string

const (
	// RoleNone is the absence of a grant, not a role anyone holds.
	RoleNone Role = ""
	// RoleReader can see content, drafts included.
	RoleReader Role = "reader"
	// RoleAuthor can write drafts. Cannot make anything public.
	RoleAuthor Role = "author"
	// RolePublisher can move the live pointer. The boundary that matters.
	RolePublisher Role = "publisher"
	// RoleAdmin can grant and revoke access.
	RoleAdmin Role = "admin"
)

// rank orders the ladder. A total order is the reason this is easy to reason
// about: there is no permission matrix to consult and no pair of roles whose
// relationship has to be looked up.
var rank = map[Role]int{
	RoleNone: 0, RoleReader: 1, RoleAuthor: 2, RolePublisher: 3, RoleAdmin: 4,
}

// Roles in ladder order, for help text and validation.
var Roles = []Role{RoleReader, RoleAuthor, RolePublisher, RoleAdmin}

func (r Role) Valid() bool { _, ok := rank[r]; return ok && r != RoleNone }

// AtLeast reports whether this role includes another.
func (r Role) AtLeast(other Role) bool { return rank[r] >= rank[other] }

func (r Role) Describe() string {
	switch r {
	case RoleReader:
		return "see content and drafts"
	case RoleAuthor:
		return "write drafts; cannot publish"
	case RolePublisher:
		return "publish and roll back"
	case RoleAdmin:
		return "manage who can do what"
	}
	return "no access"
}

// Action is a thing someone might do, and the role it needs.
type Action string

const (
	ActView      Action = "view"
	ActEditDraft Action = "edit-draft"
	ActPublish   Action = "publish"
	ActRollback  Action = "rollback"
	ActGrant     Action = "grant"
	ActToken     Action = "manage-tokens"
)

// needs maps each action to the minimum role. Kept as data in one short table
// so the complete answer to "what does this system let people do" fits on a
// screen. A permission model you cannot read in full is one nobody checks.
var needs = map[Action]Role{
	ActView:      RoleReader,
	ActEditDraft: RoleAuthor,
	ActPublish:   RolePublisher,
	ActRollback:  RolePublisher,
	ActGrant:     RoleAdmin,
	ActToken:     RoleAdmin,
}

// Actions lists every action, for help and for the explain command.
func Actions() []Action {
	out := make([]Action, 0, len(needs))
	for a := range needs {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if rank[needs[out[i]]] != rank[needs[out[j]]] {
			return rank[needs[out[i]]] < rank[needs[out[j]]]
		}
		return out[i] < out[j]
	})
	return out
}

// Needs reports the role an action requires.
func Needs(a Action) (Role, bool) { r, ok := needs[a]; return r, ok }

// Binding grants — or denies — a role to a principal on a resource subtree.
type Binding struct {
	Principal string `json:"principal"`
	Role      Role   `json:"role"`
	Resource  string `json:"resource"` // "/" is the whole site
	Deny      bool   `json:"deny,omitempty"`
	// OwnOnly restricts this binding to content the principal created.
	//
	// This is the answer to "do we need a contributor role", and the answer is
	// that contributor is not a rung on the ladder. Every CMS vocabulary has
	// one — somebody who writes drafts and cannot publish — and mapping it
	// onto a role ladder gets it wrong, because the distinction is not *less
	// power*. A contributor does exactly what an author does. They do it to a
	// smaller set of pages.
	//
	// So it is a constraint on the binding rather than a role, and it composes
	// with everything: any role can be own-only, it stacks with the resource
	// path, and it stacks with a token's type and locale scope. A new rung
	// would have composed with nothing and would have needed a decision about
	// where it sits relative to every existing one.
	OwnOnly bool `json:"own_only,omitempty"`
	// Expires ends the binding at this Unix time. Zero is never. For a
	// contractor, an auditor, or cover while somebody is away: access that
	// ends by itself is access nobody has to remember to remove.
	Expires   int64  `json:"expires,omitempty"`
	GrantedBy string `json:"granted_by,omitempty"`
	GrantedAt int64  `json:"granted_at,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Live reports whether a binding is in force at a moment.
func (b Binding) Live(now time.Time) bool {
	return b.Expires == 0 || now.Unix() < b.Expires
}

// Areas of the admin that are not content.
//
// A binding's resource has always been a part of the site — "/" for all of
// it, "/blog" for a section. These are parts of the admin instead, named
// where no page can be (a page name cannot begin with @), and the screens,
// commands and machine-interface tools of each area ask about its name. So
// a role granted on "/" covers every area, and a role granted on one area
// covers that area and nothing else — except for the guarded areas below.
//
// That is how a job is given without inventing rungs: a security analyst is
// an administrator of /@security — the findings, cases and hunts — who can
// grant nobody anything, because granting is asked about "/", and who
// cannot open a page, because pages are asked about their own names.
const (
	// AreaSecurity is security operations: findings, events, hunting,
	// detections, cases, indicators, vulnerabilities, workforce risk.
	AreaSecurity = "/@security"
	// AreaCompliance is assurance: the security posture, frameworks,
	// integrity, inventory and the evidence an assessor asks for.
	AreaCompliance = "/@compliance"
	// AreaLog is the audit log.
	AreaLog = "/@log"
	// AreaInbox is the conversations visitors asked to have with a person.
	AreaInbox = "/@inbox"
	// AreaBoards is moderating what a site's members write.
	AreaBoards = "/@boards"
)

// guardedAreas are the areas a role over the site reaches only if it is
// administrator: security operations, the posture and the audit log.
//
// What is in them is a list of where the defences are thin and a record of
// who did what, across everybody, and the screens for them always asked for
// an administrator. Some of their commands asked only to view, and a reader
// over the whole site covered every area, so a content reviewer's token
// could read the audit log from a terminal that the admin would not show
// them. Somebody who should read one of these and change nothing — an
// auditor — is granted reader on the area itself.
var guardedAreas = []string{AreaSecurity, AreaCompliance, AreaLog}

func guarded(target string) bool {
	for _, a := range guardedAreas {
		if covers(a, target) {
			return true
		}
	}
	return false
}

// IsArea reports whether a resource names an area rather than content.
func IsArea(resource string) bool {
	return strings.HasPrefix(normalise(resource), "/@")
}

// Job is a named set of grants for a kind of work.
type Job struct {
	Name     string
	Summary  string
	Bindings []Binding
	// Ends says it is granted only for a time: an assessor is there for an
	// assessment, and access nobody remembered to remove is the finding
	// they would write.
	Ends bool
}

// Jobs are the roles people ask for by what they do. Each is only the
// bindings it lists: granting one is granting those, and the policy holds
// nothing but bindings, so what a job allows is always readable in full.
var Jobs = []Job{
	{Name: "analyst", Summary: "security operations and the audit log; nothing else",
		Bindings: []Binding{{Role: RoleAdmin, Resource: AreaSecurity}, {Role: RoleAdmin, Resource: AreaLog}}},
	{Name: "compliance", Summary: "the security posture, frameworks and evidence, and the audit log",
		Bindings: []Binding{{Role: RoleAdmin, Resource: AreaCompliance}, {Role: RoleAdmin, Resource: AreaLog}}},
	{Name: "support", Summary: "answer visitors in the inbox and moderate members' posts; nothing else",
		Bindings: []Binding{{Role: RoleAuthor, Resource: AreaInbox}, {Role: RoleAuthor, Resource: AreaBoards}}},
	{Name: "auditor", Summary: "read the posture, frameworks, evidence and the audit log, for a set time; change nothing",
		Bindings: []Binding{{Role: RoleReader, Resource: AreaCompliance}, {Role: RoleReader, Resource: AreaLog}}, Ends: true},
}

// JobNamed finds a job by name.
func JobNamed(name string) (Job, bool) {
	for _, j := range Jobs {
		if j.Name == name {
			return j, true
		}
	}
	return Job{}, false
}

// Policy is the whole access model: an ordered list of bindings.
type Policy struct {
	// mu guards Bindings.
	//
	// This began as a CLI type, where one process did one thing and a lock
	// would have been noise. It is now read by every HTTP request the admin
	// interface and the content API serve, concurrently, and a type's
	// thread-safety is a property of its callers rather than of its original
	// author's intentions.
	mu       sync.RWMutex
	Bindings []Binding `json:"bindings"`
}

// normalise makes resource paths comparable. "/a/b/" and "a/b" are the same
// place, and treating them differently is a way to grant access twice and
// revoke it once.
func normalise(resource string) string {
	r := strings.TrimSpace(resource)
	if r == "" {
		return "/"
	}
	if !strings.HasPrefix(r, "/") {
		r = "/" + r
	}
	for strings.HasSuffix(r, "/") && len(r) > 1 {
		r = r[:len(r)-1]
	}
	return r
}

// covers reports whether a binding on `scope` applies to `target`.
//
// Segment-aware on purpose: "/blog" must not cover "/blog-drafts". Comparing by
// string prefix is the obvious implementation and grants access to a resource
// nobody named.
func covers(scope, target string) bool {
	scope, target = normalise(scope), normalise(target)
	if scope == "/" || scope == target {
		return true
	}
	return strings.HasPrefix(target, scope+"/")
}

// Decision is the answer plus the reason for it.
type Decision struct {
	Allowed bool
	Role    Role     // the effective role
	Reason  string   // why, in one line
	Binding *Binding // the binding that decided, if any
	Trail   []string // every binding considered, in order
	// OwnsRequired reports that the winning binding is own-only, so the caller
	// must confirm the principal created the resource. Set on an *allowed*
	// decision, which is deliberate: a caller that ignores it gets the old
	// behaviour rather than a wrong refusal, and EvaluateOwned is the path
	// that does not let it be ignored.
	OwnsRequired bool
}

// Evaluate answers whether a principal may perform an action on a resource.
//
// Two rules, and no third:
//
//  1. An explicit deny wins, wherever it sits.
//  2. Otherwise the effective role is the highest granted at or above the
//     resource.
func (p *Policy) Evaluate(principal string, action Action, resource string) Decision {
	p.mu.RLock()
	defer p.mu.RUnlock()

	required, known := needs[action]
	if !known {
		// An unknown action is refused rather than allowed. A typo in a caller
		// must not become a permission.
		return Decision{Allowed: false, Reason: fmt.Sprintf(
			"unknown action %q; refusing rather than guessing what it needs", action)}
	}

	target := normalise(resource)
	now := time.Now()
	var trail []string
	var best Role
	var bestBinding *Binding

	// Denies first, so the outcome does not depend on the order someone happened
	// to add bindings in.
	for i := range p.Bindings {
		b := &p.Bindings[i]
		if b.Principal != principal || !b.Deny || !covers(b.Resource, target) || !b.Live(now) {
			continue
		}
		// A deny of role R blocks every action needing R *or more*. Denying
		// "author" therefore also stops publishing, because leaving the higher
		// rung open would be a hole shaped exactly like the thing the deny was
		// written to close.
		//
		// It must not run the other way. The first version also blocked when the
		// denied role outranked the requirement, which made "deny publisher on
		// /legal" stop the same person reading /legal — over-denial that looks
		// like the tool is broken, and pushes people to stop using deny at all.
		if required.AtLeast(b.Role) {
			trail = append(trail, fmt.Sprintf(
				"DENY %s on %s — matches", b.Role, normalise(b.Resource)))
			return Decision{
				Allowed: false, Role: RoleNone, Binding: b, Trail: trail,
				Reason: fmt.Sprintf("denied %s on %s, which covers %s",
					b.Role, normalise(b.Resource), target)}
		}
	}

	for i := range p.Bindings {
		b := &p.Bindings[i]
		if b.Principal != principal || b.Deny {
			continue
		}
		if !b.Live(now) {
			trail = append(trail, fmt.Sprintf(
				"skip %s on %s — expired", b.Role, normalise(b.Resource)))
			continue
		}
		if !covers(b.Resource, target) {
			trail = append(trail, fmt.Sprintf(
				"skip %s on %s — does not cover %s", b.Role, normalise(b.Resource), target))
			continue
		}
		if b.Role != RoleAdmin && !IsArea(b.Resource) && guarded(target) {
			trail = append(trail, fmt.Sprintf(
				"skip %s on %s — only an administrator over the site reaches %s",
				b.Role, normalise(b.Resource), target))
			continue
		}
		trail = append(trail, fmt.Sprintf(
			"grant %s on %s — covers %s", b.Role, normalise(b.Resource), target))
		if b.Role.AtLeast(best) {
			best, bestBinding = b.Role, b
		}
	}

	if best == RoleNone {
		return Decision{Allowed: false, Role: RoleNone, Trail: trail,
			Reason: fmt.Sprintf("no binding gives %s any role on %s", principal, target)}
	}
	if !best.AtLeast(required) {
		return Decision{Allowed: false, Role: best, Binding: bestBinding, Trail: trail,
			Reason: fmt.Sprintf("%s is %s on %s; %s needs %s",
				principal, best, target, action, required)}
	}
	// The binding that won may be own-only, which Evaluate cannot resolve on
	// its own: it does not know who created the page, and giving this package
	// access to the store to find out would make the access model depend on
	// the content it guards.
	//
	// So it is reported rather than decided. The caller — which is holding the
	// page and knows its author — checks OwnsRequired against the creator.
	// Fail-closed is the caller's job and EvaluateOwned below makes that the
	// easy path.
	return Decision{Allowed: true, Role: best, Binding: bestBinding, Trail: trail,
		OwnsRequired: bestBinding.OwnOnly,
		Reason: fmt.Sprintf("%s is %s on %s, granted at %s",
			principal, best, target, normalise(bestBinding.Resource))}
}

// Anywhere reports whether a principal may perform an action on anything at
// all.
//
// This is the question a list screen has to ask, and asking the other one is
// how a scoped grant became a way to lock somebody out of the interface. A
// pages screen that asks "may you edit /" refuses an author granted author on
// /blog, because covers("/blog", "/") is false — so somebody narrowed to part
// of the site could not open the list of the pages they were narrowed to. The
// browser did that on every page-shaped screen it has.
//
// The answer here is deliberately weak: it says there is somewhere, not which
// somewhere. A screen uses it to decide whether to open at all, and then asks
// the per-resource question for every row it is about to show. The strong
// check stays where the name is known; this only stops the weak question being
// asked in a strong form.
//
// Implemented by asking Evaluate about each of the principal's own bindings
// rather than by re-deriving the rules. Deny then behaves here exactly as it
// does everywhere else, including a deny that covers the very grant being
// considered — which a second copy of the logic would have got wrong the first
// time somebody changed one of them.
func (p *Policy) Anywhere(principal string, action Action) bool {
	p.mu.RLock()
	scopes := make([]string, 0, len(p.Bindings))
	for i := range p.Bindings {
		// Content only: an area is not somewhere in the site, and an
		// analyst's grant on /@security must not open the Pages list.
		if b := &p.Bindings[i]; b.Principal == principal && !b.Deny && !IsArea(b.Resource) {
			scopes = append(scopes, b.Resource)
		}
	}
	p.mu.RUnlock()

	for _, scope := range scopes {
		if p.Evaluate(principal, action, scope).Allowed {
			return true
		}
	}
	return false
}

// EvaluateOwned is Evaluate for a caller that knows who created the resource.
//
// The creator is passed rather than looked up, because this package must not
// read content in order to decide who may read content — that dependency runs
// the wrong way and would make the policy unevaluable without a store.
//
// An empty creator means nobody knows, and an own-only binding then refuses.
// That is the direction that fails closed: content whose author was never
// recorded is content an own-only principal has no claim to, and treating
// "unknown" as "yours" would make every unattributed page editable by
// everybody holding an own-only grant.
func (p *Policy) EvaluateOwned(principal string, action Action, resource,
	creator string) Decision {

	d := p.Evaluate(principal, action, resource)
	if !d.Allowed || !d.OwnsRequired {
		return d
	}
	// Reads are not restricted by ownership. A contributor who cannot see the
	// site cannot write for it, and an editorial team where people cannot read
	// each other's drafts is not a team.
	if action == ActView {
		return d
	}
	if creator != "" && creator == principal {
		return d
	}
	d.Allowed = false
	if creator == "" {
		d.Reason = fmt.Sprintf(
			"%s may only change content they created, and nothing records who "+
				"created %s", principal, normalise(resource))
		return d
	}
	d.Reason = fmt.Sprintf(
		"%s may only change content they created; %s was created by %s",
		principal, normalise(resource), creator)
	return d
}

// Grant adds a binding. Refuses a duplicate rather than stacking one.
func (p *Policy) Grant(b Binding) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if strings.TrimSpace(b.Principal) == "" {
		return fmt.Errorf("a binding needs a principal")
	}
	if !b.Role.Valid() {
		return fmt.Errorf("%q is not a role; use one of %s", b.Role, roleList())
	}
	b.Resource = normalise(b.Resource)
	if b.GrantedAt == 0 {
		b.GrantedAt = time.Now().Unix()
	}
	for _, e := range p.Bindings {
		if e.Principal == b.Principal && e.Role == b.Role &&
			e.Resource == b.Resource && e.Deny == b.Deny {
			return fmt.Errorf("that binding already exists")
		}
	}
	p.Bindings = append(p.Bindings, b)
	return nil
}

// Revoke removes matching bindings and reports how many went.
func (p *Policy) Revoke(principal string, role Role, resource string) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	resource = normalise(resource)
	kept := p.Bindings[:0]
	removed := 0
	for _, b := range p.Bindings {
		if b.Principal == principal && b.Role == role && normalise(b.Resource) == resource {
			removed++
			continue
		}
		kept = append(kept, b)
	}
	p.Bindings = kept
	return removed
}

// Principals lists everyone with any binding.
func (p *Policy) Principals() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	seen := map[string]bool{}
	for _, b := range p.Bindings {
		seen[b.Principal] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func roleList() string {
	parts := make([]string, len(Roles))
	for i, r := range Roles {
		parts[i] = string(r)
	}
	return strings.Join(parts, ", ")
}

// -- API tokens ---------------------------------------------------------------

// TokenPrefix marks a quilzo token in logs, repositories and paste sites.
//
// GitHub's `ghp_` convention exists so secret scanners can spot a leaked
// credential without knowing what it belongs to. It costs six characters and it
// is the difference between a token found by a scanner and one found by whoever
// picked it up.
const TokenPrefix = "qz_"

// tokenBytes is 256 bits. Tokens are generated, not chosen, so the whole
// dictionary-attack problem that motivates slow password hashing does not exist
// here.
const tokenBytes = 32

var tokenEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret is a fresh token secret. The shield's decoys are made with it
// too, so the only thing that tells a decoy from a real token is trying it,
// and a change to the format moves both at once.
func NewSecret() (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("cannot generate a token: %w", err)
	}
	return TokenPrefix + strings.ToLower(tokenEnc.EncodeToString(raw)), nil
}

// Token is a stored credential. The secret itself is not in this struct and is
// never written anywhere.
//
// Two lifetimes share this type on purpose. A long-lived token is the thing you
// store — in a secret manager, in a file at 0600 — and it is analogous to an
// AWS access key. A session is minted from one at the moment of use, lives for
// minutes, and is analogous to what STS hands back.
//
// The distinction matters because "generated rather than hardcoded" is not the
// same as "short-lived". A 30-day token minted by this program is still a
// bearer credential sitting somewhere for 30 days, and everything that can read
// where it sits can use it for a month.
type Token struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Hash      string `json:"hash"`
	Principal string `json:"principal"`
	Role      Role   `json:"role"`
	Resource  string `json:"resource"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	LastUsed  int64  `json:"last_used,omitempty"`
	Revoked   bool   `json:"revoked,omitempty"`

	// Parent is the id of the token this was exchanged from, empty for a
	// long-lived one. It is what makes revocation mean what it says: revoking a
	// parent has to invalidate everything minted from it, or the sessions
	// outlive the revocation and "revoked" is a claim rather than a fact.
	Parent string `json:"parent,omitempty"`

	// Scope narrows what this credential reaches beneath what the policy
	// grants its principal. Zero value means unrestricted, which is what every
	// token issued before this existed has.
	Scope Scope `json:"scope,omitempty"`

	// Session marks a sign-in session this program minted with no parent
	// token: one an identity provider or a passkey vouched for.
	//
	// Parent alone could not say so. OIDC and passkey sign-in minted their
	// eight-hour credentials with Issue, so they had no parent, IsSession
	// said false, and signing out — which revokes sessions and deliberately
	// leaves somebody's own long-lived token alone — left them working for
	// the rest of the day. The comment on sign-out described revoking them;
	// the test for it built its session with Exchange, which is the one path
	// that set a parent.
	Session bool `json:"session,omitempty"`

	// StepUp, when set, says why this session must prove its person before
	// it may do anything else: an automation judged a sign-in, or something
	// seen elsewhere, unlike them (internal/automate). Cleared when they do.
	StepUp string `json:"step_up,omitempty"`

	// Audience, when set, is the one resource this token may be presented
	// to: an access token an app was given through OAuth for the agent
	// interface (internal/oauthas). Every other surface refuses it, so what
	// an AI app holds to call the interface is not also a way into the
	// admin, the API or a terminal.
	Audience string `json:"audience,omitempty"`
	// Client is the app it was issued to and Grant the person's consent it
	// came from; revoking the grant revokes every token issued under it.
	Client string `json:"client,omitempty"`
	Grant  string `json:"grant,omitempty"`

	// Bound is the kind of device and the country a session was issued to,
	// "Chrome on Windows|GB", so a session carried somewhere else — a
	// cookie copied by malware — can be noticed (see BindSession).
	Bound string `json:"bound,omitempty"`
}

// BindSession records where a session was issued to.
func (ts *TokenStore) BindSession(id, bound string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for i := range ts.Tokens {
		if ts.Tokens[i].ID == id {
			ts.Tokens[i].Bound = bound
			return nil
		}
	}
	return fmt.Errorf("no token %s", id)
}

// IsSession reports whether this is a short-lived sign-in credential rather
// than somebody's own long-lived token: exchanged from one, or minted for a
// sign-in an identity provider or passkey vouched for.
func (t *Token) IsSession() bool { return t.Parent != "" || t.Session }

// MaxSessionTTL caps an exchanged credential. A session that can outlive a
// working day is not doing the job a session exists for.
const MaxSessionTTL = 12 * time.Hour

// DefaultSessionTTL is what you get without asking. Short enough that a leaked
// session is usually expired before anyone finds it, long enough to run a CI
// job without re-exchanging mid-flight.
const DefaultSessionTTL = 15 * time.Minute

// Expired reports whether a token is past its expiry.
func (t *Token) Expired(now time.Time) bool { return now.Unix() >= t.ExpiresAt }

// Usable reports whether a token may authenticate right now.
func (t *Token) Usable(now time.Time) (bool, string) {
	if t.Revoked {
		return false, "this token was revoked"
	}
	if t.Expired(now) {
		return false, fmt.Sprintf("this token expired on %s",
			time.Unix(t.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
	return true, ""
}

// hashToken is a single SHA-256, and that is the right choice rather than a
// shortcut.
//
// NIST SP 800-63B requires a slow KDF — argon2id, scrypt, bcrypt, PBKDF2 — for
// *user-chosen* secrets, because those have little entropy and an offline
// attacker guesses them from a dictionary. A token is 256 bits from a CSPRNG.
// There is no dictionary, so a work factor buys nothing and costs latency on
// every single API request.
//
// The property that matters is that the stored value cannot be replayed, and a
// preimage-resistant hash gives that.
func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// TokenStore holds issued tokens.
type TokenStore struct {
	// mu guards Tokens. See the note on Policy: the same reasoning applies,
	// and here the consequence was worse than a torn read of a boolean.
	//
	// Authenticate ranges over the slice while Issue appends to it. An append
	// that reallocates while another goroutine holds an index into the old
	// array is the textbook case, and the returned *Token pointed into the
	// slice — so a caller held a pointer to memory that Revoke could flip
	// underneath it, between the check that the token was usable and the use
	// of what it authorised.
	mu     sync.Mutex
	Tokens []Token `json:"tokens"`

	// Ended are the sessions pruned lately, by a short fingerprint of their
	// hash: enough to say "that session ended" to a script still using one
	// a day later, rather than "no such token", which the shield counts as
	// a guess; never enough to sign in with.
	Ended []Ended `json:"ended,omitempty"`

	// Admit, when set, is asked about every credential that authenticates,
	// including one presented to be exchanged for a session. The shield's
	// lockdown sets it (internal/shield): it is given when the credential's
	// own long-lived token was made — the parent's, for a session exchanged
	// from one, so a stolen token cannot be laundered into a fresh session —
	// and whether a passkey or single sign-on vouched for it. A store
	// loaded for the command line on the machine has none: that is the way
	// out of a lockdown, not a way in.
	Admit func(c Credential) error `json:"-"`
}

// Credential is what Admit is told about one presented credential.
type Credential struct {
	// ID is the credential's own id; Parent the long-lived token it was
	// exchanged from, if it was; Grant the app connection it was issued
	// for, if it was.
	ID, Parent, Grant string
	// Issued is when the long-lived token behind it was made: the parent's
	// for an exchanged session.
	Issued int64
	// Vouched says a passkey or single sign-on minted it.
	Vouched bool
}

// Ended is a pruned session's fingerprint.
type Ended struct {
	Print string `json:"print"`
	At    int64  `json:"at"`
}

const (
	maxEnded   = 4096
	keepEnded  = 30 * 24 * time.Hour
	endedPrint = 16 // hex characters: 8 bytes of the hash
)

// ErrLockedDown is a credential refused because the admin is accepting
// only passkeys, single sign-on and tokens made since, for a while.
var ErrLockedDown = errors.New("for a while the admin accepts only passkeys, single sign-on and tokens made since then")

// Issue mints a token and returns the secret exactly once.
//
// The caller's role caps what may be issued: a token is a way to act as
// yourself later, never a way to hand out more than you hold. Without that,
// token creation becomes a privilege-escalation path.
func (ts *TokenStore) Issue(name, principal string, role Role, resource string,
	ttl time.Duration, issuerRole Role) (secret string, t Token, err error) {

	return ts.IssueScoped(name, principal, role, resource, ttl, issuerRole,
		Scope{})
}

// IssueScoped mints a token narrowed to particular content types, locales, or
// to reading only.
//
// A separate entry point rather than a longer Issue, because every existing
// caller means "unrestricted" and rewriting twenty call sites to pass an empty
// struct is how a default gets typed wrongly somewhere.
func (ts *TokenStore) IssueScoped(name, principal string, role Role,
	resource string, ttl time.Duration, issuerRole Role, scope Scope) (
	secret string, t Token, err error) {

	return ts.issue(name, principal, role, resource, ttl, issuerRole, scope,
		false)
}

// IssueSession mints a sign-in session for somebody an identity provider or
// a passkey has just vouched for.
//
// Marked as a session so signing out revokes it, capped at MaxSessionTTL like
// every other session, and a moment for clearing out sessions that ended long
// ago — each sign-in adds one, and a store that only ever grows is a store
// somebody eventually edits by hand.
func (ts *TokenStore) IssueSession(name, principal string, role Role,
	resource string, ttl time.Duration, issuerRole Role) (
	secret string, t Token, err error) {

	if ttl > MaxSessionTTL {
		ttl = MaxSessionTTL
	}
	return ts.issue(name, principal, role, resource, ttl, issuerRole, Scope{},
		true)
}

// SessionRetention is how long an ended session is kept before it is removed.
//
// A day, so "who was signed in yesterday afternoon" can still be answered
// from the store as well as from the audit log, which is the record that
// actually has to last.
const SessionRetention = 24 * time.Hour

// pruneSessions removes sessions, and apps' access tokens, that ended more
// than SessionRetention ago. Only those: a long-lived token is somebody's
// credential and is removed by revoking it on purpose, never by a sweep.
// Called with the lock held.
func (ts *TokenStore) pruneSessions(now time.Time) {
	cutoff := now.Add(-SessionRetention).Unix()
	kept := ts.Tokens[:0]
	for _, t := range ts.Tokens {
		if (t.IsSession() || t.Grant != "") && t.ExpiresAt < cutoff {
			if len(t.Hash) >= endedPrint {
				ts.Ended = append(ts.Ended, Ended{Print: t.Hash[:endedPrint], At: now.Unix()})
			}
			continue
		}
		kept = append(kept, t)
	}
	recent := ts.Ended[:0]
	for _, e := range ts.Ended {
		if now.Sub(time.Unix(e.At, 0)) <= keepEnded {
			recent = append(recent, e)
		}
	}
	if len(recent) > maxEnded {
		recent = recent[len(recent)-maxEnded:]
	}
	ts.Ended = recent
	// Zero the tail so the removed tokens' hashes are not left reachable in
	// the backing array.
	for i := len(kept); i < len(ts.Tokens); i++ {
		ts.Tokens[i] = Token{}
	}
	ts.Tokens = kept
}

func (ts *TokenStore) issue(name, principal string, role Role,
	resource string, ttl time.Duration, issuerRole Role, scope Scope,
	session bool) (secret string, t Token, err error) {

	if err := scope.Validate(); err != nil {
		return "", Token{}, err
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	if strings.TrimSpace(name) == "" {
		return "", Token{}, fmt.Errorf("a token needs a name, so it can be recognised later")
	}
	if !role.Valid() {
		return "", Token{}, fmt.Errorf("%q is not a role; use one of %s", role, roleList())
	}
	if !issuerRole.AtLeast(role) {
		return "", Token{}, fmt.Errorf(
			"you are %s and cannot issue a %s token; a token carries your authority, "+
				"it does not create more", issuerRole, role)
	}
	if ttl <= 0 {
		return "", Token{}, fmt.Errorf(
			"a token needs an expiry. A credential with no end is one nobody ever gets " +
				"around to rotating")
	}

	secret, err = NewSecret()
	if err != nil {
		return "", Token{}, err
	}

	idRaw := make([]byte, 6)
	if _, err := rand.Read(idRaw); err != nil {
		return "", Token{}, fmt.Errorf("cannot generate a token id: %w", err)
	}

	now := time.Now()
	t = Token{
		ID:        hex.EncodeToString(idRaw),
		Name:      name,
		Hash:      hashToken(secret),
		Principal: principal,
		Role:      role,
		Resource:  normalise(resource),
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	t.Scope = scope
	t.Session = session
	if session {
		ts.pruneSessions(time.Now())
	}
	ts.Tokens = append(ts.Tokens, t)
	return secret, t, nil
}

// Exchange mints a short-lived session from a long-lived token.
//
// This is the pattern the guidance keeps pointing at: keep the durable
// credential somewhere protected, and hand the process that actually does the
// work something that expires in minutes. What is stored and what is used stop
// being the same object, so exposure of the second is bounded by the clock.
//
// A session can only ever narrow. Role is capped at the parent's, scope must sit
// within the parent's, and the lifetime is capped absolutely — a session that
// could widen would be an escalation path dressed as convenience.
func (ts *TokenStore) Exchange(parentSecret string, role Role, resource string,
	ttl time.Duration, now time.Time) (secret string, t Token, err error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	parent, err := ts.authenticate(parentSecret, now)
	if err == nil && parent.Audience != "" {
		err = audienceError(parent.Audience)
	}
	if err != nil {
		return "", Token{}, err
	}
	if parent.IsSession() {
		// Chaining would make the revocation walk unbounded and give a session
		// a way to outlive its parent by re-minting just before expiry.
		return "", Token{}, fmt.Errorf(
			"a session cannot be exchanged again; exchange from the long-lived token")
	}

	if role == RoleNone {
		role = parent.Role
	}
	if !parent.Role.AtLeast(role) {
		return "", Token{}, fmt.Errorf(
			"cannot exchange %s for %s: a session narrows, it does not widen",
			parent.Role, role)
	}
	if resource == "" {
		resource = parent.Resource
	}
	if !covers(parent.Resource, resource) {
		return "", Token{}, fmt.Errorf(
			"cannot scope a session to %s from a token scoped to %s",
			normalise(resource), normalise(parent.Resource))
	}

	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if ttl > MaxSessionTTL {
		return "", Token{}, fmt.Errorf(
			"a session may last at most %s; asked for %s", MaxSessionTTL, ttl)
	}
	// Never past the parent's own expiry. A session outliving the credential it
	// came from is the same bug as outliving a revocation.
	if remaining := time.Unix(parent.ExpiresAt, 0).Sub(now); ttl > remaining {
		ttl = remaining
	}
	if ttl <= 0 {
		return "", Token{}, fmt.Errorf("the parent token expires too soon to exchange")
	}

	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", Token{}, err
	}
	idRaw := make([]byte, 6)
	if _, err := rand.Read(idRaw); err != nil {
		return "", Token{}, err
	}
	secret = TokenPrefix + strings.ToLower(tokenEnc.EncodeToString(raw))

	t = Token{
		ID: hex.EncodeToString(idRaw), Name: parent.Name + " (session)",
		Hash: hashToken(secret), Principal: parent.Principal,
		Role: role, Resource: normalise(resource),
		CreatedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(),
		Parent: parent.ID,
		// The parent's scope, carried. Leaving it off meant every exchanged
		// session was unrestricted: a credential issued --read-only, or
		// --types article, produced a session with the zero Scope — which
		// CheckCredential reads as no restriction at all. So `quilzo token
		// exchange` turned a read-only CI credential into one that publishes,
		// which is the opposite of what a session is for.
		//
		// Role and resource were capped above and always had been. Scope alone
		// was dropped, which is the shape of bug that survives review: the
		// three narrowing dimensions are checked in three different places and
		// only two of them are next to each other.
		//
		// Narrow rather than assignment. Scope holds slices, so assigning it
		// would give the session and its parent the same backing array;
		// narrowing by nothing copies, and the day somebody adds a tighter
		// session the call is already the intersection rather than a choice
		// about which one wins.
		Scope: parent.Scope.Narrow(Scope{}),
	}
	ts.pruneSessions(now)
	ts.Tokens = append(ts.Tokens, t)
	return secret, t, nil
}

// Authenticate resolves a presented secret to a token.
//
// The comparison is constant-time. Comparing hashes with == leaks how far the
// match got through timing, which is enough to reconstruct a stored hash given
// patience — and the whole point of storing hashes is that the store is not
// enough to authenticate with.
func (ts *TokenStore) Authenticate(secret string, now time.Time) (*Token, error) {
	return ts.AuthenticateFor(secret, "", now)
}

// AuthenticateFor is Authenticate at one resource: a token bound to an
// audience is accepted only where that audience is the resource asked
// about, and refused everywhere else, including by Authenticate.
func (ts *TokenStore) AuthenticateFor(secret, resource string, now time.Time) (*Token, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t, err := ts.authenticate(secret, now)
	if err == nil && t.Audience != "" && (resource == "" || t.Audience != resource) {
		return nil, audienceError(t.Audience)
	}
	if err == nil && t.StepUp != "" {
		// Refused everywhere, so a session waiting to prove its person
		// cannot be carried to the API, the studio or a terminal as a
		// bearer token. The token comes back with the error for the one
		// caller that needs to say who is waiting: the admin's own page.
		return t, ErrStepUp
	}
	return t, err
}

// ErrAudience is a token presented somewhere other than the one resource it
// was issued for.
var ErrAudience = errors.New("this token was issued for one resource only")

func audienceError(aud string) error {
	return fmt.Errorf("%w (%s) and is not accepted here", ErrAudience, aud)
}

// IssueForGrant mints an access token for an app a person consented to,
// bound to one resource. Not a session: signing out of the browser does not
// disconnect the app; revoking the grant does.
func (ts *TokenStore) IssueForGrant(principal string, role Role, scope Scope,
	client, grant, audience string, ttl time.Duration, now time.Time) (string, Token, error) {
	if client == "" || grant == "" || audience == "" {
		return "", Token{}, errors.New("an app's token names its app, its grant and its audience")
	}
	if ttl <= 0 || ttl > MaxSessionTTL {
		return "", Token{}, fmt.Errorf("an app's access token lasts more than nothing and at most %s", MaxSessionTTL)
	}
	if err := scope.Validate(); err != nil {
		return "", Token{}, err
	}
	if !role.Valid() {
		return "", Token{}, fmt.Errorf("%q is not a role", role)
	}
	secret, err := NewSecret()
	if err != nil {
		return "", Token{}, err
	}
	idRaw := make([]byte, 6)
	if _, err := rand.Read(idRaw); err != nil {
		return "", Token{}, fmt.Errorf("cannot generate a token id: %w", err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t := Token{
		ID: hex.EncodeToString(idRaw), Name: "app " + client, Hash: hashToken(secret),
		Principal: principal, Role: role, Resource: "/", Scope: scope,
		CreatedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(),
		Audience: audience, Client: client, Grant: grant,
	}
	ts.pruneSessions(now)
	ts.Tokens = append(ts.Tokens, t)
	return secret, t, nil
}

// RevokeGrant revokes every token issued under one grant, and says how many.
func (ts *TokenStore) RevokeGrant(grant string) int {
	if grant == "" {
		return 0
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	n := 0
	for i := range ts.Tokens {
		if ts.Tokens[i].Grant == grant && !ts.Tokens[i].Revoked {
			ts.Tokens[i].Revoked = true
			n++
		}
	}
	return n
}

// errUnknown marks a secret that is no credential this store ever issued:
// a guess, a forgery or a decoy, as against one that expired or was
// revoked, which is somebody's real credential used late.
var errUnknown = errors.New("not issued here")

var errNoSuchToken = fmt.Errorf("no such token%w", silent{errUnknown})

var errSessionEnded = errors.New("that session has ended; sign in again")

// silent wraps an error for errors.Is without adding to the message, so
// what a caller is told stays exactly what it was.
type silent struct{ error }

func (silent) Error() string { return "" }

func (s silent) Unwrap() error { return s.error }

// Unknown reports whether Authenticate refused a secret because it was never
// issued here, rather than because it expired or was revoked. The shield
// counts the first: guessing is an attack, and a script holding a token that
// ran out is not.
func Unknown(err error) bool { return errors.Is(err, errUnknown) }

// ErrStepUp is a session that must prove its person before it is used.
var ErrStepUp = errors.New("this session must confirm it is its person first: sign in to the admin")

// authenticate is Authenticate with the lock already held, so that Exchange —
// which authenticates the parent and then mints a child — does both under one
// lock rather than deadlocking on a re-entrant call.
func (ts *TokenStore) authenticate(secret string, now time.Time) (*Token, error) {
	if !strings.HasPrefix(secret, TokenPrefix) {
		return nil, fmt.Errorf("that is not a quilzo token (they start with %s)%w", TokenPrefix, silent{errUnknown})
	}
	want := []byte(hashToken(secret))

	var found *Token
	for i := range ts.Tokens {
		if subtle.ConstantTimeCompare([]byte(ts.Tokens[i].Hash), want) == 1 {
			found = &ts.Tokens[i]
			// No early break: returning as soon as a match is found makes the
			// loop's duration depend on the token's position in the store.
		}
	}
	if found == nil {
		// A session pruned lately is somebody's real credential used late,
		// not a guess, and is told so.
		for _, e := range ts.Ended {
			if len(want) >= endedPrint && e.Print == string(want[:endedPrint]) {
				return nil, errSessionEnded
			}
		}
		return nil, errNoSuchToken
	}
	if ok, why := found.Usable(now); !ok {
		return nil, fmt.Errorf("%s", why)
	}
	if ts.Admit != nil {
		issued := found.CreatedAt
		if found.Parent != "" {
			// A parent that is gone made nothing anybody can vouch for.
			issued = 0
			for i := range ts.Tokens {
				if ts.Tokens[i].ID == found.Parent {
					issued = ts.Tokens[i].CreatedAt
				}
			}
		}
		if err := ts.Admit(Credential{ID: found.ID, Parent: found.Parent, Grant: found.Grant,
			Issued: issued, Vouched: found.Session}); err != nil {
			return nil, err
		}
	}
	found.LastUsed = now.Unix()

	// A copy, not the address of a slice element. The caller keeps this for
	// the length of a request; the slice underneath it can be reallocated by
	// Issue and rewritten by Revoke in that time. Handing out an alias into
	// mutable shared state makes every caller responsible for a lock they
	// cannot see.
	out := *found
	return &out, nil
}

// Revoke marks a token unusable, along with every session minted from it.
//
// The cascade is the point. Revoking a long-lived token while its sessions keep
// working would mean revocation does not revoke — the credential you cancelled
// is still doing work for up to twelve hours under a different id, which is
// exactly the window an attacker needs.
//
// Records are kept rather than deleted, so what existed and when it last worked
// survives the revocation.
func (ts *TokenStore) Revoke(id string) (int, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	found := false
	for i := range ts.Tokens {
		if ts.Tokens[i].ID == id {
			if ts.Tokens[i].Revoked {
				return 0, fmt.Errorf("token %s was already revoked", id)
			}
			ts.Tokens[i].Revoked = true
			found = true
			break
		}
	}
	if !found {
		return 0, fmt.Errorf("no token %s", id)
	}

	sessions := 0
	for i := range ts.Tokens {
		if ts.Tokens[i].Parent == id && !ts.Tokens[i].Revoked {
			ts.Tokens[i].Revoked = true
			sessions++
		}
	}
	return sessions, nil
}

// RequireStepUp marks one session as having to prove its person again.
func (ts *TokenStore) RequireStepUp(id, reason string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for i := range ts.Tokens {
		if ts.Tokens[i].ID == id {
			if !ts.Tokens[i].IsSession() {
				return fmt.Errorf("%s is not a session", id)
			}
			ts.Tokens[i].StepUp = reason
			return nil
		}
	}
	return fmt.Errorf("no token %s", id)
}

// RequireStepUpFor marks every live session a principal has, and says how
// many, so that something seen elsewhere reaches the sessions already open.
func (ts *TokenStore) RequireStepUpFor(principal, reason string, now time.Time) int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	n := 0
	for i := range ts.Tokens {
		t := &ts.Tokens[i]
		if strings.EqualFold(t.Principal, principal) && t.IsSession() && !t.Revoked &&
			(t.ExpiresAt == 0 || now.Unix() < t.ExpiresAt) {
			t.StepUp = reason
			n++
		}
	}
	return n
}

// ClearStepUp records that a session has proved its person.
func (ts *TokenStore) ClearStepUp(id string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for i := range ts.Tokens {
		if ts.Tokens[i].ID == id {
			ts.Tokens[i].StepUp = ""
			return nil
		}
	}
	return fmt.Errorf("no token %s", id)
}

// Stale lists tokens that have never been used or have not been used recently.
// Unused credentials are the ones nobody notices are still valid.
func (ts *TokenStore) Stale(now time.Time, idle time.Duration) []Token {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	var out []Token
	for _, t := range ts.Tokens {
		if t.Revoked || t.Expired(now) {
			continue
		}
		last := t.LastUsed
		if last == 0 {
			last = t.CreatedAt
		}
		if now.Sub(time.Unix(last, 0)) > idle {
			out = append(out, t)
		}
	}
	return out
}

// Snapshot returns a copy of the bindings.
//
// A copy, because both of these types are now mutex-guarded and handing out
// the slice would let a caller read it while another goroutine appends. That
// was the shape of the race the admin already had once.
func (p *Policy) Snapshot() []Binding {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]Binding(nil), p.Bindings...)
}

// Snapshot returns a copy of the tokens, hashes included — callers that render
// these must not print the Hash field, which is why nothing here does.
func (ts *TokenStore) Snapshot() []Token {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]Token(nil), ts.Tokens...)
}

// Replace swaps the token set, under the lock.
//
// For a host that re-reads the store from disk because another process may
// have changed it. Revocation is the reason this exists: a token store loaded
// once at startup means a credential revoked in one process keeps working in
// every other one until it restarts, which makes "revoked" a claim about a
// file rather than a fact about a credential.
func (ts *TokenStore) Replace(tokens []Token) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.Tokens = tokens
}
