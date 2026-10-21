// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
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
	life := fs.Duration("for", enrol.MaxLife, "how long the link waits to be used, at most a day")
	revoke := fs.Bool("revoke", false, "end the link waiting for this person")
	if err := fs.Parse(args[1:]); err != nil {
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
	return issueEnrolment(root, name, caller.Name, *life, caller)
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
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	admin := fs.String("admin", "", "make this person the first administrator and print the link that adds their passkey")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if created {
		now := time.Now()
		if err := atomicfile.Update(mfaPath(root), func(st *mfaState) error {
			if !st.EnforcedFrom.IsZero() {
				return atomicfile.ErrUnchanged
			}
			st.EnforcedFrom = now.UTC()
			return nil
		}); err != nil {
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
