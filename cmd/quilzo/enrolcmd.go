// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/enrol"
	"github.com/quilzo/quilzo/internal/shield"
)

// Enrolment links: how a person gets their first passkey (internal/enrol).

func enrolPath(root string) string { return filepath.Join(root, "enrolments.json") }

func enrolStore(root string) *enrol.Store { return &enrol.Store{Path: enrolPath(root)} }

// enrolURL is where a link is opened: the admin's address when one is set,
// and otherwise quilzo serve's default, named localhost because a browser
// refuses an IP address as the site a passkey belongs to. A passkey belongs
// to the address it was made on, so the link has to be opened at the admin
// people will sign in to.
func enrolURL(root, secret string) string {
	base := "http://localhost:8080"
	if c, err := loadConfig(root); err == nil && c.Raw("admin.base_url") != "" {
		base = strings.TrimSuffix(c.Raw("admin.base_url"), "/")
	}
	return base + "/enrol/" + secret
}

// enrolBlocked is why links may not be used now: a lockdown in force,
// during which nothing new is let in.
func enrolBlocked(root string) func(time.Time) string {
	return func(now time.Time) string {
		if p, on := shield.Find(root, shield.Lockdown, "", now); on {
			return fmt.Sprintf("the admin is locked down until about %s; enrolment links wait until it lifts",
				p.Until.UTC().Format("15:04 UTC"))
		}
		return ""
	}
}

// authEnrol is `quilzo auth enrol NAME [--for 24h] [--revoke]`.
func authEnrol(root string, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: quilzo auth enrol NAME [--for 24h] | quilzo auth enrol NAME --revoke")
	}
	name := args[0]
	fs := flag.NewFlagSet("auth enrol", flag.ContinueOnError)
	life := flagDuration(fs, "for", enrol.MaxLife, "how long the link waits to be used, at most a day")
	revoke := fs.Bool("revoke", false, "end the link waiting for this person")
	if err := parseFlags(fs, args[1:], nil, 0); err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	if *revoke {
		gone, err := enrolStore(root).Revoke(name, time.Now())
		if err != nil {
			return err
		}
		if !gone {
			w.Human("no enrolment link was waiting for %s\n", name)
			return nil
		}
		w.Human("the enrolment link for %s no longer works\n", name)
		return recordE(root, caller.auditRecord("enrol.revoked", "/", audit.Success, map[string]string{"for": name}))
	}
	pol, err := loadPolicy(root)
	if err != nil {
		return err
	}
	if !holdsAny(pol, name) {
		return fmt.Errorf("%s has no access here, so a passkey would sign them in to nothing. "+
			"Grant them a role first: quilzo auth grant %s author", name, name)
	}
	// A link for somebody who administers anything waits for a second
	// administrator and goes to whoever asked (quilzo pending redeem), as
	// an administrator's token does: whoever opens it signs in as them from
	// then on, so one administrator could otherwise give themselves a
	// second administrator's sign-in and approve their own requests as her.
	if *life <= 0 || *life > enrol.MaxLife {
		return fmt.Errorf("an enrolment link lasts more than nothing and at most %s", enrol.MaxLife)
	}
	if dual.Privileged(heldBy(pol, name)) {
		apply, err := proposeSecondFor(root, caller, name, dual.Enrol, "a passkey enrolment link for "+name,
			dual.EnrolChange{Principal: name, For: *life}, "")
		if err != nil || !apply {
			return err
		}
	}
	return issueEnrolment(root, name, caller.Name, *life, caller)
}

// heldBy is what name holds that is not a deny.
func heldBy(pol *auth.Policy, name string) []auth.Binding {
	var out []auth.Binding
	for _, b := range pol.Bindings {
		if !b.Deny && strings.EqualFold(b.Principal, name) {
			out = append(out, b)
		}
	}
	return out
}

// redeemEnrolment gives whoever asked for an approved enrolment link the
// link: quilzo pending redeem, for an Enrol request.
func redeemEnrolment(root string, r dual.Request, c *Caller, now time.Time) error {
	var ch dual.EnrolChange
	if err := json.Unmarshal(r.Payload, &ch); err != nil {
		return err
	}
	pol, err := loadPolicy(root)
	if err != nil {
		return err
	}
	if !holdsAny(pol, ch.Principal) {
		return fmt.Errorf("%s holds nothing here now, so a passkey would sign them in to nothing", ch.Principal)
	}
	if _, err := dualStore(root).Redeem(r.ID, c.Name, now); err != nil {
		return err
	}
	if err := recordE(root, c.auditRecord("dual.redeemed", "/", audit.Success,
		map[string]string{"request": r.ID, "for": ch.Principal, "approved_by": r.DecidedBy})); err != nil {
		return err
	}
	life := ch.For
	if life <= 0 {
		life = enrol.MaxLife
	}
	return issueEnrolment(root, ch.Principal, c.Name, life, c)
}

// enteredBefore reports whether anybody has held a credential for this
// store: a token or session, one that ended, or a passkey. Unreadable is
// taken as yes, which refuses rather than hands out a way in.
func enteredBefore(root string) bool {
	ts, err := loadTokens(root)
	if err != nil || len(ts.Tokens) > 0 || len(ts.Ended) > 0 {
		return true
	}
	pk := &admin.Passkeys{}
	if err := loadJSON(passkeysPath(root), pk); err != nil {
		return true
	}
	return len(pk.Credentials) > 0
}

// initFlags reads `quilzo init`'s line, one declaration for runInit, which
// reads it before it makes anything, and initAdmin, which acts on it: a
// flag mistyped was refused only after the store's folders had been, and
// the store was then taken for one already in use. A word after init is
// refused, with where a store goes (runInit).
func initFlags(args []string) (*string, error) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	admin := fs.String("admin", "", "make this person the first administrator and print the link that adds their passkey")
	var pos []string
	if err := parseFlags(fs, args, &pos, 1); err != nil {
		return nil, err
	}
	if len(pos) > 0 {
		return nil, errMisused{fmt.Errorf("usage: quilzo init [--admin NAME]\n"+
			"  the store goes where --root says, not where a word after init does: quilzo --root %s init", pos[0])}
	}
	return admin, nil
}

// nobodyHasBeenHere reports whether a store has never had a person: no
// binding in its policy, so nobody the admin would let in. Unreadable is
// taken as somebody, which keeps whatever grace was given.
//
// A credential does not make somebody a person here. It also asked that
// none had ever been held (enteredBefore), and a token issued before any
// grant, which signs in to nothing and is answered with "grant one: quilzo
// auth grant owner admin", made the store it was issued on one already in
// use: the grant, or `init --admin`, that followed left it the grace.
func nobodyHasBeenHere(root string) bool {
	pol, err := loadPolicy(root)
	return err == nil && len(pol.Bindings) == 0
}

// twoFactorsFromNow makes two factors compulsory at root from now, for a
// store nobody has had access to. A date that has passed is kept; a grace
// still running is ended, since nobody is there to need it.
func twoFactorsFromNow(root string) error {
	now := time.Now()
	return atomicfile.Update(mfaPath(root), func(st *mfaState) error {
		if !st.EnforcedFrom.IsZero() && !st.EnforcedFrom.After(now) {
			return atomicfile.ErrUnchanged
		}
		st.EnforcedFrom = now.UTC()
		return nil
	})
}

// holdsAny reports whether name holds anything that is not a deny.
func holdsAny(pol *auth.Policy, name string) bool {
	for _, b := range pol.Bindings {
		if !b.Deny && strings.EqualFold(b.Principal, name) {
			return true
		}
	}
	return false
}

// issueEnrolment makes the link, records it (never the secret), and
// prints it once.
func issueEnrolment(root, name, by string, life time.Duration, caller *Caller) error {
	secret, l, err := enrolStore(root).Issue(name, by, life, time.Now())
	if err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord("enrol.issued", "/", audit.Success, map[string]string{
		"for": name, "expires": l.Expires.Format(time.RFC3339)})); err != nil {
		_, _ = enrolStore(root).Revoke(name, time.Now())
		return err
	}
	if w.JSON(map[string]any{"for": name, "link": enrolURL(root, secret), "expires": l.Expires}) {
		return nil
	}
	w.Human("%s\n", enrolURL(root, secret))
	w.Human("  %sopened once, by %s, before %s: it adds their passkey and does nothing else.\n"+
		"  Give it to them the way you would give a key; anybody who opens it first adds theirs instead%s\n",
		dim, name, l.Expires.UTC().Format("15:04 UTC on 2 January"), reset)
	if c, err := loadConfig(root); err != nil || c.Raw("admin.base_url") == "" {
		w.Human("  %sthat is quilzo serve's own address; an admin anywhere else is set with "+
			"quilzo config set admin.base_url https://...%s\n", dim, reset)
	}
	return nil
}

// initAdmin is `quilzo init --admin NAME`: the first administrator, and the
// link that gives them their passkey. A new store has two factors from its
// first day; the grace an upgraded installation gets is for people who were
// already signing in with a token.
func initAdmin(root string, args []string, created bool) error {
	admin, err := initFlags(args)
	if err != nil {
		return err
	}
	// New is a store nobody has had access to, not only one this run made
	// the folders of. `quilzo demo`, `quilzo log`, or `init --admni` with a
	// typo, make the folders, and the `init --admin` after them took the
	// store for an upgraded installation: the first `quilzo serve` then
	// wrote the grace, and for two weeks a token alone opened the admin of
	// a store a day old. Nobody here yet means nobody signing in with a
	// token to be locked out, so a grace already written is ended too.
	if created || nobodyHasBeenHere(root) {
		if err := twoFactorsFromNow(root); err != nil {
			return err
		}
	}
	if *admin == "" {
		return nil
	}
	pol, err := loadPolicy(root)
	if err != nil {
		return err
	}
	if len(pol.Principals()) > 0 && !holdsAny(pol, *admin) {
		return fmt.Errorf("this store already has people; another administrator grants %s and gives the link: "+
			"quilzo auth grant %s admin, then quilzo auth enrol %s", *admin, *admin, *admin)
	}
	// Run again, it gives the first administrator a fresh link, for a
	// store nobody has signed in to yet: nobody holds anything to escalate
	// from, as with the first token (bootstrapIssue). Once anybody has a
	// credential, a link is quilzo auth enrol's, which asks who is giving
	// it and waits for a second administrator. This asked nothing, so on a
	// store in use anybody at the machine, with no credential at all, was
	// printed a link that signed in as an existing administrator.
	if len(pol.Principals()) > 0 && enteredBefore(root) {
		return fmt.Errorf("somebody has already signed in to this store, so a link for %s is given "+
			"by an administrator: quilzo auth enrol %s", *admin, *admin)
	}
	if !holdsAny(pol, *admin) {
		if _, err := updatePolicy(root, func(p *auth.Policy) error {
			return p.Grant(auth.Binding{Principal: *admin, Role: auth.RoleAdmin, Resource: "/",
				GrantedBy: "quilzo init", Note: "the first administrator"})
		}); err != nil {
			return err
		}
	}
	w.Human("The first administrator is %s. Start the admin (quilzo serve) and open this, once, to add their passkey:\n", *admin)
	return issueEnrolment(root, *admin, "quilzo init", enrol.MaxLife, resolveCaller(root, ""))
}
