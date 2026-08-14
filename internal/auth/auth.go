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
	"fmt"
	"sort"
	"strings"
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
	GrantedBy string `json:"granted_by,omitempty"`
	GrantedAt int64  `json:"granted_at,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Policy is the whole access model: an ordered list of bindings.
type Policy struct {
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
}

// Evaluate answers whether a principal may perform an action on a resource.
//
// Two rules, and no third:
//
//  1. An explicit deny wins, wherever it sits.
//  2. Otherwise the effective role is the highest granted at or above the
//     resource.
func (p *Policy) Evaluate(principal string, action Action, resource string) Decision {
	required, known := needs[action]
	if !known {
		// An unknown action is refused rather than allowed. A typo in a caller
		// must not become a permission.
		return Decision{Allowed: false, Reason: fmt.Sprintf(
			"unknown action %q; refusing rather than guessing what it needs", action)}
	}

	target := normalise(resource)
	var trail []string
	var best Role
	var bestBinding *Binding

	// Denies first, so the outcome does not depend on the order someone happened
	// to add bindings in.
	for i := range p.Bindings {
		b := &p.Bindings[i]
		if b.Principal != principal || !b.Deny || !covers(b.Resource, target) {
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
		if !covers(b.Resource, target) {
			trail = append(trail, fmt.Sprintf(
				"skip %s on %s — does not cover %s", b.Role, normalise(b.Resource), target))
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
	return Decision{Allowed: true, Role: best, Binding: bestBinding, Trail: trail,
		Reason: fmt.Sprintf("%s is %s on %s, granted at %s",
			principal, best, target, normalise(bestBinding.Resource))}
}

// Grant adds a binding. Refuses a duplicate rather than stacking one.
func (p *Policy) Grant(b Binding) error {
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

// TokenPrefix marks a scrivet token in logs, repositories and paste sites.
//
// GitHub's `ghp_` convention exists so secret scanners can spot a leaked
// credential without knowing what it belongs to. It costs six characters and it
// is the difference between a token found by a scanner and one found by whoever
// picked it up.
const TokenPrefix = "scv_"

// tokenBytes is 256 bits. Tokens are generated, not chosen, so the whole
// dictionary-attack problem that motivates slow password hashing does not exist
// here.
const tokenBytes = 32

var tokenEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

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
}

// IsSession reports whether this was exchanged from another token.
func (t *Token) IsSession() bool { return t.Parent != "" }

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
	Tokens []Token `json:"tokens"`
}

// Issue mints a token and returns the secret exactly once.
//
// The caller's role caps what may be issued: a token is a way to act as
// yourself later, never a way to hand out more than you hold. Without that,
// token creation becomes a privilege-escalation path.
func (ts *TokenStore) Issue(name, principal string, role Role, resource string,
	ttl time.Duration, issuerRole Role) (secret string, t Token, err error) {

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

	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", Token{}, fmt.Errorf("cannot generate a token: %w", err)
	}
	secret = TokenPrefix + strings.ToLower(tokenEnc.EncodeToString(raw))

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

	parent, err := ts.Authenticate(parentSecret, now)
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
	}
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
	if !strings.HasPrefix(secret, TokenPrefix) {
		return nil, fmt.Errorf("that is not a scrivet token (they start with %s)", TokenPrefix)
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
		return nil, fmt.Errorf("no such token")
	}
	if ok, why := found.Usable(now); !ok {
		return nil, fmt.Errorf("%s", why)
	}
	found.LastUsed = now.Unix()
	return found, nil
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

// Stale lists tokens that have never been used or have not been used recently.
// Unused credentials are the ones nobody notices are still valid.
func (ts *TokenStore) Stale(now time.Time, idle time.Duration) []Token {
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
