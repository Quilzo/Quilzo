// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/shield"
)

// "Forgot password" for a system with no passwords.
//
// The request asked for password reset and lockout-with-delay. Two of those
// three map straight onto what is here; the middle one does not, and building
// it anyway would be the wrong answer.
//
// There is no password in this program. Sign-in is a bearer token or an
// identity provider, which was a deliberate decision: no password storage, no
// reset email, no reset link that is a bearer credential in somebody's inbox,
// no credential-stuffing surface, and no phishing target. Adding a password so
// that a password could be reset would introduce every one of those to build a
// recovery path for a problem the design does not have.
//
// So what does an enterprise actually need when somebody cannot get in?
//
//	They forgot their password        → they have none. Their IdP handles it.
//	They lost their token             → an admin issues another. Thirty seconds.
//	Their token was compromised       → revoke, cascade, reissue.
//	Every admin token is lost         → this. The break-glass.
//
// Only the last is missing, and it is a genuine hole: a store where access
// control is configured and no usable admin token remains cannot be
// administered again. There is no "email the owner" here — no mail server, no
// registered address, and inventing one would be a worse recovery path than
// the one below.
//
// The honest observation is that recovery is already possible for anyone who
// can read the store directory: policy.json is a file, and an attacker with
// filesystem access can edit it. Making it a command changes nothing about who
// can do it and changes everything about whether anybody finds out — the
// hand-edit leaves no record at all, and this leaves one in a log written by a
// different account.

func cmdRecover(root string, args []string) error {
	var principal, reason string
	confirmed := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--principal" && i+1 < len(args):
			principal = args[i+1]
			i++
		case args[i] == "--reason" && i+1 < len(args):
			reason = args[i+1]
			i++
		case args[i] == "--i-have-filesystem-access":
			confirmed = true
		}
	}

	toks, err := loadTokens(root)
	if err != nil {
		return err
	}

	// Usable means: not revoked, not expired, carrying admin, and not
	// refused by a lockdown in force, which would refuse it at the admin
	// however alive it is here.
	usable := 0
	now := time.Now()
	lock, locked := shield.Find(root, shield.Lockdown, "", now)
	for i := range toks.Tokens {
		t := &toks.Tokens[i]
		if ok, _ := t.Usable(now); !ok || t.Role != auth.RoleAdmin {
			continue
		}
		if locked && shield.LockedOut(lock, t.CreatedAt, t.Session) {
			continue
		}
		usable++
	}
	if locked && usable == 0 {
		fmt.Fprintf(os.Stderr, "the admin is locked down until about %s; lifting it is quicker than this:\n"+
			"    quilzo shield lift %s\n", lock.Until.UTC().Format("15:04 UTC"), lock.ID)
	}

	if usable > 0 {
		// Refused, and this is the important half of the command.
		//
		// A break-glass that works while an ordinary path exists is not a
		// break-glass, it is a second front door. While one admin token is
		// alive, recovery is somebody with that token issuing another — which
		// is authenticated, authorised and takes half a minute.
		return fmt.Errorf(
			"%d admin token(s) are still usable, so this is not needed.\n"+
				"  Ask whoever holds one to issue you another:\n"+
				"    quilzo auth grant you admin\n"+
				"    quilzo token issue you --principal you --role admin\n"+
				"  This command exists only for a store nobody can administer "+
				"at all", usable)
	}

	if !confirmed || strings.TrimSpace(reason) == "" || principal == "" {
		return errBlocked{fmt.Errorf(
			"no usable admin token remains, so this store cannot be " +
				"administered.\n\n" +
				"  Recovery is possible because you can read this directory — " +
				"and\n  anyone who can read it could already edit policy.json " +
				"by hand. Doing\n  it here changes nothing about who can, and " +
				"everything about whether\n  it is recorded: a hand edit " +
				"leaves no trace, this leaves one in a log\n  written by a " +
				"different account.\n\n" +
				"    quilzo auth recover --principal WHO --reason \"why\" " +
				"--i-have-filesystem-access\n")}
	}

	// The grant, and a token to use it with. Both, because granting a role to
	// somebody who then cannot authenticate is the lockout this exists to end.
	//
	// The grant only when they do not hold it. The store's first
	// administrator, made by `quilzo init --admin`, holds it and has a
	// passkey and no token, and is the person most likely to lose the one
	// way in; the recovery refused them, "that binding already exists".
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		for _, b := range p.Snapshot() {
			if b.Principal == principal && b.Role == auth.RoleAdmin && b.Permission == "" &&
				b.Resource == "/" && !b.Deny && b.Via == "" {
				return atomicfile.ErrUnchanged
			}
		}
		return p.Grant(auth.Binding{Principal: principal, Role: auth.RoleAdmin, Resource: "/"})
	}); err != nil {
		return err
	}

	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	// Deliberately short. A break-glass credential should be used to fix the
	// situation and then be gone; one that lasts a month is one somebody is
	// still carrying at Christmas.
	ttl := 1 * time.Hour
	if d := cfg.Dur("token.api.ttl.default"); d > 0 && d < ttl {
		ttl = d
	}
	secret, tok, err := toks.Issue("break-glass", principal, auth.RoleAdmin,
		"/", ttl, auth.RoleAdmin)
	if err != nil {
		return err
	}
	if err := saveTokens(root, toks); err != nil {
		return err
	}

	// Recorded as the operating system user, not as the principal being
	// granted. The record has to say who was at the keyboard, and the whole
	// premise here is that nobody has authenticated.
	record(root, audit.Record{
		Action: "auth.break-glass", Resource: "/",
		Outcome: audit.Success, Principal: osUser(),
		Kind: audit.KindHuman, Verified: false,
		Detail: map[string]string{
			"granted": principal,
			"why":     reason,
			"note": "no usable admin token remained; recovered by an account " +
				"with filesystem access to the store",
		},
	})
	tellOfRecovery(root, principal, reason, ttl)

	fmt.Println(secret)
	fmt.Fprintf(os.Stderr, "\n  %sid %s · admin on / · expires in %s%s\n",
		dim, tok.ID, ttl, reset)
	fmt.Fprintf(os.Stderr, "  %sthis is the only time it is shown%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "\n  %sit is deliberately short-lived: use it to "+
		"issue a proper token%s\n", yellow, reset)
	fmt.Fprintf(os.Stderr, "  %sand to find out why every admin credential "+
		"was lost%s\n", yellow, reset)
	fmt.Fprintf(os.Stderr, "  %sthe recovery is in the audit log, where it cannot "+
		"be removed, and the security contact is told of it%s\n", dim, reset)
	return nil
}

// tellOfRecovery mails the security contact that a break-glass made
// somebody an administrator, in the background, and records whether it
// reached them. A recovery is also what an intruder holding the store's
// files would run, and it used to be written to the audit log and nowhere
// else: nobody heard of it until somebody read the log. The credential it
// printed is never in the message.
func tellOfRecovery(root, principal, reason string, ttl time.Duration) {
	summary := fmt.Sprintf("Break-glass: %s, on the machine that holds the store, made %s an administrator of "+
		"everything with a token that lasts %s, because %q. No usable admin token remained. If nobody expected "+
		"this, somebody who can read the store's files has taken it over.", osUser(), principal, ttl, reason)
	inBackground(func() {
		did, err := tellSecurity(root, summary)
		detail := map[string]string{"about": "break-glass", "did": did}
		outcome := audit.Success
		if err != nil {
			detail["error"], outcome = err.Error(), audit.Failure
		}
		record(root, audit.Record{Action: "auth.told", Resource: "/", Outcome: outcome,
			Principal: "quilzo", Kind: audit.KindService, Verified: true, Detail: detail})
	})
}
