// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oauthas"
	"github.com/quilzo/quilzo/internal/saml"
	"github.com/quilzo/quilzo/internal/ssf"
)

// What a verified security event does. There is no rule engine and nothing
// to configure: each event Quilzo asks for has one fixed meaning here, and
// every one of them takes access away or gives back only what this took.
//
//	session-revoked, sessions-revoked, credential-change (update, revoke,
//	delete)                      the provider's sessions for them end
//	credential-compromise,       those end, and every other session they
//	account-credential-change-   have must confirm it is them; the security
//	required                     contact is told
//	account-disabled,            suspended as SCIM suspends: every token,
//	account-purged               every app they connected, and a deny over
//	                             the whole site that sign-in refuses
//	account-enabled              only this receiver's own deny is lifted
//
// Who an event is about is read the way the bound provider names people
// at sign-in and no other way (subjectPrincipal), and has to be somebody
// the access policy already knows. Anything else is counted as unmatched
// and nothing is done: a guess about whose access to take away is the
// wrong way round to be wrong.
//
// It replaces the templates an operator had to add before any of this
// happened, and the hourly limit they ran under: twenty people an hour,
// then the security contact is told. An event past that is accepted, so
// the transmitter does not send it again, and is never acted on; whoever
// is told has to act on the rest by hand. A provider offboarding a team
// stays inside that; a stolen transmitter key signing everybody out does
// not get past it.

// signalsCap is how many people the receiver acts on in an hour.
const signalsCap = 20

// signalsAction is what an event does to the person it is about.
type signalsAction int

const (
	signalsNothing signalsAction = iota
	signalsEndSessions
	signalsStepUp
	signalsSuspend
	signalsRestore
)

// actionFor is an event's fixed meaning.
func actionFor(set *ssf.SET) signalsAction {
	switch set.Short {
	case "session-revoked", "sessions-revoked":
		return signalsEndSessions
	case "credential-change":
		// A credential added is nobody's session gone wrong; one changed,
		// revoked or removed means the sessions it opened may be someone
		// else's.
		switch set.Text("change_type") {
		case "update", "revoke", "delete":
			return signalsEndSessions
		}
		return signalsNothing
	case "credential-compromise", "account-credential-change-required":
		return signalsStepUp
	case "account-disabled", "account-purged":
		return signalsSuspend
	case "account-enabled":
		return signalsRestore
	}
	return signalsNothing
}

// signalsKey is how the receiver's own file names somebody: a digest, so
// signals.json says nothing about who was acted on.
func signalsKey(principal string) string { return ssf.Digest(strings.ToLower(principal)) }

// signalsDeliver acts on one verified event. An error is one the
// transmitter should send the event again for: the store could not be read
// or written.
func signalsDeliver(root string, set *ssf.SET, now time.Time) error {
	c, err := loadSignals(root)
	if err != nil {
		return err
	}
	// Turned off between the push being read and acted on: accepted, and
	// nothing done.
	if !c.connected() {
		return nil
	}
	count := func(f func(*signalsCounts)) error {
		return updateSignals(root, func(s *signalsConfig) error {
			s.Counts.Received++
			s.Counts.LastAt, s.Counts.LastType = now.UTC(), set.Short
			if f != nil {
				f(&s.Counts)
			}
			return nil
		})
	}
	base := map[string]string{"type": set.Short, "jti": set.JTI, "issuer": set.Issuer}
	switch set.Short {
	case "verification":
		return signalsVerification(root, c, set, base, now)
	case "stream-updated":
		status, _ := set.Claims["status"].(string)
		switch status {
		case "enabled", "paused", "disabled":
		default:
			return count(nil)
		}
		if err := updateSignals(root, func(s *signalsConfig) error {
			s.Status = status
			s.Counts.Received++
			s.Counts.LastAt, s.Counts.LastType = now.UTC(), set.Short
			return nil
		}); err != nil {
			return err
		}
		d := cloneDetail(base)
		d["status"] = status
		signalsRecord(root, "signals.stream-status", audit.Success, d)
		return nil
	}

	act := actionFor(set)
	if act == signalsNothing {
		return count(nil)
	}
	principal, err := subjectPrincipal(root, c, set)
	if err != nil {
		return err
	}
	if principal == "" {
		return count(func(n *signalsCounts) { n.Unmatched++ })
	}
	key := signalsKey(principal)
	// An account-enabled no newer than the last event acted on for them is
	// one that arrived late or again: a suspension made after it stands.
	// Kept in the file, so a restart, which forgets the ids already seen,
	// does not make an old one new.
	if act == signalsRestore && set.IssuedAt.Unix() <= c.LastActed[key] {
		if err := count(func(n *signalsCounts) { n.Refused++; n.Unnoted++ }); err != nil {
			return err
		}
		signalsNoteRefusals(root, now)
		return nil
	}
	if capped, first := signalsOverCap(c, key, now); capped {
		if err := updateSignals(root, func(s *signalsConfig) error {
			s.Counts.Received++
			s.Counts.Capped++
			s.Counts.LastAt, s.Counts.LastType = now.UTC(), set.Short
			if first {
				s.Hour.Noted = true
			}
			return nil
		}); err != nil {
			return err
		}
		if first {
			d := cloneDetail(base)
			d["count"] = fmt.Sprint(signalsCap)
			signalsRecord(root, "signals.capped", audit.Denied, d)
			signalsTell(root, "", fmt.Sprintf("The identity provider's security events have acted on %d people "+
				"within an hour, which is as many as Quilzo acts on in one. Events about anybody else this hour "+
				"are accepted and never acted on, and the provider will not send them again: if this is an "+
				"offboarding you expected, the provider's own log says whom it disabled, and the rest are "+
				"suspended by hand here (quilzo auth deny WHO reader). If it is not, the transmitter's key or "+
				"the stream may be in somebody else's hands: quilzo signals off stops it.", signalsCap))
		}
		return nil
	}

	d := cloneDetail(base)
	d["subject"] = principal
	switch act {
	case signalsEndSessions:
		n, err := endProviderSessions(root, principal, c.Provider, now)
		if err != nil {
			return err
		}
		d["count"] = fmt.Sprint(n)
		signalsRecord(root, "signals.sessions-ended", audit.Success, d)
	case signalsStepUp:
		n, held, err := stepUpAfterCompromise(root, principal, c.Provider, now)
		if err != nil {
			return err
		}
		d["count"] = fmt.Sprint(n + held)
		signalsRecord(root, "signals.step-up", audit.Success, d)
		signalsTell(root, principal, fmt.Sprintf("The identity provider reported %s's credential compromised (%s). "+
			"Their %s sessions here were ended, and %s of theirs must confirm it is them before doing "+
			"anything: Sign-ins, in the admin.", principal, set.Short, c.Provider,
			plural2(held, "the other session", "other sessions")))
	case signalsSuspend:
		n, denied, err := suspendOnSignal(root, principal, now)
		if err != nil {
			return err
		}
		d["count"] = fmt.Sprint(n)
		if !denied {
			// The last person who can grant access is not shut out of
			// the site on anybody's word: their sessions end, and a
			// person decides the rest.
			signalsRecord(root, "signals.suspended", audit.Failure, d)
			signalsTell(root, principal, fmt.Sprintf("The identity provider disabled %s's account (%s). %s is the "+
				"only person who can grant access here, so no deny was added, and %s of theirs ended. Check "+
				"with them, and suspend them by hand if it is right.", principal, set.Short, principal,
				plural2(n, "the one session", "sessions")))
		} else {
			signalsRecord(root, "signals.suspended", audit.Success, d)
		}
	case signalsRestore:
		n, err := restoreOnSignal(root, principal)
		if err != nil {
			return err
		}
		if n > 0 {
			d["count"] = fmt.Sprint(n)
			signalsRecord(root, "signals.restored", audit.Success, d)
		}
	}
	return updateSignals(root, func(s *signalsConfig) error {
		s.Counts.Received++
		s.Counts.Acted++
		s.Counts.LastAt, s.Counts.LastType = now.UTC(), set.Short
		if s.LastActed == nil {
			s.LastActed = map[string]int64{}
		}
		if iat := set.IssuedAt.Unix(); iat > s.LastActed[key] {
			s.LastActed[key] = iat
		}
		if now.Sub(s.Hour.Start) >= time.Hour {
			s.Hour = signalsHour{Start: now.UTC()}
		}
		if !slices.Contains(s.Hour.Who, key) {
			s.Hour.Who = append(s.Hour.Who, key)
		}
		return nil
	})
}

// signalsOverCap reports whether acting on somebody would pass the hour's
// cap, and whether this is the first time this hour it has.
func signalsOverCap(c *signalsConfig, key string, now time.Time) (capped, first bool) {
	if now.Sub(c.Hour.Start) >= time.Hour || slices.Contains(c.Hour.Who, key) || len(c.Hour.Who) < signalsCap {
		return false, false
	}
	return true, !c.Hour.Noted
}

// signalsVerification marks the stream verified when the transmitter sends
// back the state it was asked with. Anything else, an unasked one or one
// carrying some other state, proves nothing about this stream.
func signalsVerification(root string, c *signalsConfig, set *ssf.SET, base map[string]string, now time.Time) error {
	state, _ := set.Claims["state"].(string)
	verified := false
	if err := updateSignals(root, func(s *signalsConfig) error {
		s.Counts.Received++
		s.Counts.LastAt, s.Counts.LastType = now.UTC(), set.Short
		ours := set.Subject.Format != "opaque" || set.Subject.ID == "" || set.Subject.ID == s.Stream
		if ours && signalsMatches(state, s.State) {
			s.Verified, s.State, verified = now.UTC(), "", true
		}
		return nil
	}); err != nil {
		return err
	}
	if verified {
		signalsRecord(root, "signals.verified", audit.Success, cloneDetail(base))
	}
	return nil
}

// signalsRefused counts a delivery that did not prove itself, and writes
// the hour's summary when one is due.
func signalsRefused(root string, now time.Time) {
	_ = updateSignals(root, func(s *signalsConfig) error {
		if !s.connected() {
			return atomicfile.ErrUnchanged
		}
		s.Counts.Refused++
		s.Counts.Unnoted++
		return nil
	})
	signalsNoteRefusals(root, now)
}

// signalsNoteRefusals writes one signals.refused record for the refusals
// since the last, at most once an hour, and says whether it wrote one.
// One a refusal could not write, because none came after it in the hour,
// is written by the server's upkeep.
func signalsNoteRefusals(root string, now time.Time) int {
	n := 0
	err := updateSignals(root, func(s *signalsConfig) error {
		if s.Counts.Unnoted == 0 || now.Sub(s.Counts.RefusedNoted) < time.Hour {
			return atomicfile.ErrUnchanged
		}
		n, s.Counts.Unnoted, s.Counts.RefusedNoted = s.Counts.Unnoted, 0, now.UTC()
		return nil
	})
	if err != nil || n == 0 {
		return 0
	}
	signalsRecord(root, "signals.refused", audit.Denied, map[string]string{"count": fmt.Sprint(n)})
	return 1
}

func cloneDetail(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// signalsRecord writes what the receiver did, as itself.
func signalsRecord(root, action string, outcome audit.Outcome, detail map[string]string) {
	record(root, audit.Record{Action: action, Resource: "/", Outcome: outcome,
		Principal: signalsBy, Kind: audit.KindService, Verified: true, Detail: detail})
}

// signalsTell mails the security contact in the background, so no push
// waits on a mail server, and records whether it reached them.
func signalsTell(root, principal, summary string) {
	inBackground(func() {
		did, err := tellSecurity(root, summary)
		detail := map[string]string{"did": did}
		if principal != "" {
			detail["subject"] = principal
		}
		outcome := audit.Success
		if err != nil {
			detail["error"], outcome = onOneLine(err.Error()), audit.Failure
		}
		signalsRecord(root, "signals.told", outcome, detail)
	})
}

// subjectPrincipal is who an event is about, read by the bound provider's
// own rule for naming people at sign-in (oidcauth.go principalFor,
// saml.Config.PrincipalOf), or empty when it names nobody the access
// policy knows, or more than one.
//
//	OIDC, claim email or preferred_username   an address: an email or
//	                                          acct: subject, or the user
//	                                          of a complex subject, or the
//	                                          one address aliases agree on
//	OIDC, claim sub                           a plain iss_sub, from the
//	                                          OIDC issuer itself
//	SAML                                      an address, and only when the
//	                                          provider names people by one
func subjectPrincipal(root string, c *signalsConfig, set *ssf.SET) (string, error) {
	pol, err := loadPolicy(root)
	if err != nil {
		return "", err
	}
	known := pol.Principals()
	addressed := func(addr string, domains []string) string {
		if addr == "" || (len(domains) > 0 && !addressIn(addr, domains)) {
			return ""
		}
		// An address is matched as sign-in compares it, without case; two
		// principals that differ only by case are two people as far as
		// the policy says, and choosing one is guessing.
		one := ""
		for _, p := range known {
			if strings.EqualFold(p, addr) {
				if one != "" {
					return ""
				}
				one = p
			}
		}
		return one
	}
	switch {
	case c.Provider == "oidc":
		oc, err := loadOIDC(root)
		if err != nil || oc == nil {
			return "", err
		}
		if oc.Claim == "sub" {
			iss, sub := set.Subject.IssSub()
			// The issuer the subject names must be the one that signs
			// people in, compared as oidc.json keeps it: without a
			// trailing slash.
			if sub == "" || strings.TrimSuffix(iss, "/") != strings.TrimSuffix(oc.Issuer, "/") {
				return "", nil
			}
			if slices.Contains(known, sub) {
				return sub, nil
			}
			return "", nil
		}
		return addressed(set.Subject.Person(), oc.Domains), nil
	case strings.HasPrefix(c.Provider, "saml:"):
		sc, err := samlNamed(root, strings.TrimPrefix(c.Provider, "saml:"))
		if err != nil {
			// The provider was removed after the stream was connected:
			// there is nobody it signs in, so nobody to act on.
			return "", nil
		}
		if !samlNamesByAddress(sc) {
			return "", nil
		}
		return addressed(set.Subject.Person(), sc.Domains), nil
	}
	return "", nil
}

// addressIn reports whether an address is in one of the organisation's
// domains, which is where its provider signs people in from.
func addressIn(addr string, domains []string) bool {
	_, d, ok := strings.Cut(addr, "@")
	return ok && slices.ContainsFunc(domains, func(want string) bool { return strings.EqualFold(d, want) })
}

// samlNamesByAddress reports whether a SAML provider's principals are
// addresses: when it has to name people in the organisation's domains, or
// names them by an email NameID. A provider naming people by an attribute
// or an opaque NameID is not matched by address at all, because the
// address an event gives is not what it signs people in as.
func samlNamesByAddress(c *saml.Config) bool {
	if len(c.Domains) > 0 {
		return true
	}
	return (c.Principal == "" || c.Principal == "nameid") && c.NameIDFormat == saml.FormatEmail
}

// providerPrefix is the start of the name of every session a provider
// signed somebody in to (oidcauth.go, samlauth.go): "oidc:" or
// "saml:NAME:".
func providerPrefix(provider string) string {
	return provider + ":"
}

// endProviderSessions ends somebody's live sessions that the bound
// provider signed them in to, and only those: a passkey session, a
// long-lived token and an app's grant are not the provider's to end.
func endProviderSessions(root, principal, provider string, now time.Time) (int, error) {
	ts, err := loadTokens(root)
	if err != nil {
		return 0, err
	}
	prefix := providerPrefix(provider)
	n := 0
	for _, t := range ts.Snapshot() {
		if t.Revoked || !t.IsSession() || t.Expired(now) || !strings.EqualFold(t.Principal, principal) ||
			!strings.HasPrefix(t.Name, prefix) {
			continue
		}
		if _, err := ts.Revoke(t.ID); err == nil {
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, saveTokens(root, ts)
}

// stepUpAfterCompromise ends the provider's sessions for somebody whose
// credential it reports compromised, and holds every other session they
// have until they prove it is them: a passkey, or a fresh sign-in at a
// provider that has dealt with it.
func stepUpAfterCompromise(root, principal, provider string, now time.Time) (ended, held int, err error) {
	if ended, err = endProviderSessions(root, principal, provider, now); err != nil {
		return 0, 0, err
	}
	ts, err := loadTokens(root)
	if err != nil {
		return ended, 0, err
	}
	held = ts.RequireStepUpFor(principal, "the identity provider reported their credential compromised", now)
	if held == 0 {
		return ended, 0, nil
	}
	return ended, held, saveTokens(root, ts)
}

// lastGranter reports whether somebody is the only principal who can grant
// access to the whole site.
func lastGranter(p *auth.Policy, who string) bool {
	if !p.Evaluate(who, auth.ActGrant, "/").Allowed {
		return false
	}
	for _, other := range p.Principals() {
		if !strings.EqualFold(other, who) && p.Evaluate(other, auth.ActGrant, "/").Allowed {
			return false
		}
	}
	return true
}

// suspendOnSignal does what provisioning does when the identity provider
// deactivates somebody (scimSync): a deny over the whole site, which
// sign-in by passkey and single sign-on both refuse, every token they
// hold, and every app they connected. It reports how many tokens ended and
// whether the deny was added: it is not for the last person who can grant
// access, whose sessions end and nothing more.
func suspendOnSignal(root, principal string, now time.Time) (int, bool, error) {
	// The deny first, so a sign-in in the moment between is refused.
	//
	// Whether they are the last who can grant is decided inside the same
	// change, on the policy as it is stored when the deny is written. Read
	// a moment before, two administrators disabled at once (two admins on a
	// shared store, each taking one push) each saw the other able to grant,
	// both were denied, and nobody could grant access to anybody.
	//
	// Appended rather than granted: Grant takes a binding the same shape
	// as one already there to be that one, and SCIM's suspension is the
	// same shape. Each keeps its own deny, so the provider enabling the
	// account through one lifts only what that one added.
	last := false
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		if lastGranter(p, principal) {
			last = true
			return atomicfile.ErrUnchanged
		}
		for _, b := range p.Bindings {
			if b.GrantedBy == signalsBy && b.Deny && strings.EqualFold(b.Principal, principal) && b.Live(now) {
				return atomicfile.ErrUnchanged
			}
		}
		p.Bindings = append(p.Bindings, auth.Binding{Principal: principal, Role: auth.RoleReader, Resource: "/",
			Deny: true, GrantedBy: signalsBy, GrantedAt: now.Unix(),
			Note: "suspended: the identity provider disabled their account"})
		return nil
	}); err != nil && !errors.Is(err, atomicfile.ErrUnchanged) {
		return 0, false, err
	}
	if last {
		ts, err := loadTokens(root)
		if err != nil {
			return 0, false, err
		}
		n := 0
		for _, t := range ts.Snapshot() {
			if !t.Revoked && t.IsSession() && !t.Expired(now) && strings.EqualFold(t.Principal, principal) {
				if _, err := ts.Revoke(t.ID); err == nil {
					n++
				}
			}
		}
		if n > 0 {
			if err := saveTokens(root, ts); err != nil {
				return 0, false, err
			}
		}
		return n, false, nil
	}
	ts, err := loadTokens(root)
	if err != nil {
		return 0, true, err
	}
	n := 0
	for _, t := range ts.Snapshot() {
		if !t.Revoked && strings.EqualFold(t.Principal, principal) {
			if _, err := ts.Revoke(t.ID); err == nil {
				n++
			}
		}
	}
	if n > 0 {
		if err := saveTokens(root, ts); err != nil {
			return 0, true, err
		}
	}
	// After the tokens are saved, because ending a connection revokes its
	// tokens in the same file.
	by := &Caller{Name: signalsBy, Kind: audit.KindService, Verified: true}
	appsServer(root, by).EndWhere(func(g oauthas.Grant) bool { return strings.EqualFold(g.Principal, principal) },
		signalsBy, "the identity provider disabled their account")
	return n, true, nil
}

// restoreOnSignal lifts the deny this receiver added for somebody, and no
// other: SCIM's, and any a person added, stay where they are.
func restoreOnSignal(root, principal string) (int, error) {
	n := 0
	_, err := updatePolicy(root, func(p *auth.Policy) error {
		kept := p.Bindings[:0]
		for _, b := range p.Bindings {
			if b.GrantedBy == signalsBy && b.Deny && strings.EqualFold(b.Principal, principal) {
				n++
				continue
			}
			kept = append(kept, b)
		}
		p.Bindings = kept
		if n == 0 {
			return atomicfile.ErrUnchanged
		}
		return nil
	})
	if err != nil && !errors.Is(err, atomicfile.ErrUnchanged) {
		return 0, err
	}
	return n, nil
}
