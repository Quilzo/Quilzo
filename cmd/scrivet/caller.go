package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/auth"
)

// Who is running this, and did anyone check?
//
// The audit log shipped before this could record any name the caller fancied,
// because the principal came from $USER. `USER=ceo scrivet publish` wrote a
// distinct, plausible principal into a tamper-evident chain — integrity
// without authenticity, which is the worse of the two failures because the
// record looks authoritative.
//
// A caller is now resolved from a token where one is presented, and recorded as
// unverified where none is. The unverified case is deliberately not an error:
// a single-user store with nobody granted anything has nothing to enforce, and
// a tool that demands credentials before it will do anything is a tool people
// route around. What it must never do is describe an unproven name as though it
// were established.

// Caller is the resolved identity of whoever is running the command.
type Caller struct {
	Name string
	// Role and Scope are the token's own limits, which cap what this session
	// may do regardless of what the principal is permitted in general.
	Role     auth.Role
	Scope    string
	Kind     audit.Kind
	Verified bool
	// Why explains an unverified caller, for the message a refusal prints.
	Why string
}

// tokenFile is preferred over the environment.
//
// The research reason, not a stylistic one: every process a user starts
// inherits their environment, so a token in SCRIVET_TOKEN is readable by any
// subprocess — including an agent this CLI is designed to be driven by. A file
// at 0600 is read by what opens it deliberately.
func tokenFile() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".scrivet", "token")
	}
	return ""
}

// findToken looks in the three places, most deliberate first.
func findToken(explicit string) (string, string) {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit), "--token"
	}
	if p := tokenFile(); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				return t, p
			}
		}
	}
	if t := strings.TrimSpace(os.Getenv("SCRIVET_TOKEN")); t != "" {
		return t, "SCRIVET_TOKEN"
	}
	return "", ""
}

// resolveCaller identifies whoever is running the command.
//
// Never returns an error for a missing token. It returns an unverified caller
// and lets the action decide whether that is good enough, which keeps the
// decision where the consequences are.
func resolveCaller(root, explicitToken string) *Caller {
	unverified := func(why string) *Caller {
		return &Caller{
			Name: osUser(), Kind: audit.KindHuman, Verified: false, Why: why,
		}
	}

	secret, _ := findToken(explicitToken)
	if secret == "" {
		return unverified("no token was presented")
	}
	toks, err := loadTokens(root)
	if err != nil {
		return unverified(fmt.Sprintf("the token store could not be read: %v", err))
	}
	tok, err := toks.Authenticate(secret, time.Now())
	if err != nil {
		// A bad token is worse than none: somebody tried. It is still not an
		// identity, so it is still unverified, and the reason says what happened.
		return unverified(fmt.Sprintf("the token was rejected: %v", err))
	}

	// Using a token records that it was used, which is what makes `token stale`
	// able to find credentials nobody needs any more.
	_ = saveJSON(tokensPath(root), toks)

	kind := audit.KindService
	if strings.EqualFold(tok.Name, "cli") || strings.Contains(tok.Name, "@") {
		// A weak heuristic, and named as one. Distinguishing a person's own
		// token from a CI credential properly needs the token to say which it
		// is at issue time; until then a service label is the safer default,
		// because over-attributing to a human is the direction that misleads.
		kind = audit.KindHuman
	}
	return &Caller{
		Name: tok.Principal, Role: tok.Role, Scope: tok.Resource,
		Kind: kind, Verified: true,
	}
}

func osUser() string {
	for _, k := range []string{"USER", "USERNAME", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "unknown-operator"
}

// policyInUse reports whether anybody has been granted anything.
//
// This is what decides whether authorisation is enforced, and it needs no
// configuration: a store where nobody has been granted a role is a single-user
// store with nothing to enforce, and the first `auth grant` turns enforcement
// on. A flag would be one more thing to set wrongly.
func policyInUse(root string) bool {
	p, err := loadPolicy(root)
	if err != nil {
		return false
	}
	return len(p.Bindings) > 0
}

// authorise checks a caller against the policy for privileged actions.
//
// Returns nil when the action may proceed. The refusal explains which of the
// two things was missing — an identity or a permission — because they need
// different fixes and "forbidden" tells nobody which.
func authorise(root string, c *Caller, action auth.Action, resource string) error {
	if !policyInUse(root) {
		return nil // nothing has been granted; there is nothing to enforce
	}
	if !c.Verified {
		return fmt.Errorf(
			"this store has access control configured, so %s needs a verified "+
				"identity (%s).\nPresent one with --token, %s, or SCRIVET_TOKEN",
			action, c.Why, tokenFile())
	}
	p, err := loadPolicy(root)
	if err != nil {
		return err
	}
	if d := p.Evaluate(c.Name, action, resource); !d.Allowed {
		return fmt.Errorf("%s", d.Reason)
	}

	// The token's own limits, checked second and separately.
	//
	// This was missing, and its absence made scoped tokens decorative: a
	// read-only token issued for CI could publish, because the *person* it acts
	// as is a publisher and only the policy was consulted. Issue-time checking
	// stops somebody minting more authority than they hold; this is what makes
	// a narrow token actually narrow, which is the entire reason to issue one.
	need, known := auth.Needs(action)
	if known && !c.Role.AtLeast(need) {
		return fmt.Errorf(
			"this token carries %s and %s needs %s. The token limits the session "+
				"even though %s holds more in general — issue a wider token, or use "+
				"one you already have",
			c.Role, action, need, c.Name)
	}
	if c.Scope != "" && !coversPath(c.Scope, resource) {
		return fmt.Errorf(
			"this token is scoped to %s and does not reach %s", c.Scope, resource)
	}
	return nil
}

// coversPath mirrors the policy's segment-aware containment, so "/blog" does
// not cover "/blog-drafts" here either. Two different answers to the same
// question would be worse than one wrong one.
func coversPath(scope, target string) bool {
	scope, target = normalisePath(scope), normalisePath(target)
	if scope == "/" || scope == target {
		return true
	}
	return strings.HasPrefix(target, scope+"/")
}

func normalisePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for strings.HasSuffix(p, "/") && len(p) > 1 {
		p = p[:len(p)-1]
	}
	return p
}

// auditRecord builds a record carrying whatever was actually established.
func (c *Caller) auditRecord(action, resource string, outcome audit.Outcome,
	detail map[string]string) audit.Record {

	if detail == nil {
		detail = map[string]string{}
	}
	if !c.Verified {
		// Written into the record rather than left to be inferred from a false
		// flag, so a reader scanning entries sees it without checking a field.
		detail["identity"] = "unverified: " + c.Why
	}
	return audit.Record{
		Action: action, Resource: resource, Outcome: outcome,
		Principal: c.Name, Kind: c.Kind, Verified: c.Verified, Detail: detail,
	}
}
