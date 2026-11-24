// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/lockout"
)

// Smart lockout at the admin's door (internal/lockout), from the command
// line: how a store whose only administrator is locked out gets them back.

func lockoutStore(root string) *lockout.Store {
	return &lockout.Store{Path: filepath.Join(root, "lockout.json")}
}

// heldAs is the account Unlock(name) would let in again now, by the name
// the lockout record keeps it under, and whether one is held. A record
// that cannot be read holds nobody here, and Unlock then says why it
// cannot be read.
//
// The record finds an account by its name in any case (strings.EqualFold),
// which folds more than auth.SamePerson does: the long s, ſ (U+017F), is
// an s to it. So `quilzo auth unlock roſs` let ross in again while the
// check that it was not his own lockout compared "roſs" with "ross" and
// saw two people. Who is asked about is the account that would be
// unlocked, not how its name was typed.
func heldAs(root, name string, now time.Time) (string, bool) {
	held, _ := lockoutStore(root).Held(now)
	for _, a := range held {
		if strings.EqualFold(a.Name, name) {
			return a.Name, true
		}
	}
	return "", false
}

// authUnlock is `quilzo auth unlock NAME`.
//
// Not your own lockout while another administrator is there to ask, as on
// the Sign-ins screen: a lockout is somebody else looking at why an
// account failed so often before it is let in again. The command asked
// only whether the caller may grant access, so a locked-out administrator,
// or whoever held their token, unlocked themselves with a second
// administrator a message away. The only administrator there is still
// does, which is what this command is for, and the record says it was
// done alone; not for a day after another administrator stopped being
// one, like everything else one administrator does alone (aloneRefusal),
// or removing the other one would be the way round it.
func authUnlock(root string, args []string) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return errMisused{errors.New("usage: quilzo auth unlock NAME")}
	}
	name := args[0]
	caller := resolveCaller(root, "")
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	now := time.Now()
	acct, held := heldAs(root, name, now)
	if held {
		name = acct
	}
	detail := map[string]string{"for": name}
	if caller.Verified && held && (auth.SamePerson(acct, caller.Name) || strings.EqualFold(acct, caller.Name)) {
		const own = "somebody else has to unlock you: that is the point of a lockout"
		if rm := aloneRefusal(root, caller.Name, now); rm != nil {
			_ = refuseAlone(root, caller, rm, map[string]string{"for": name, "command": "auth unlock"})
			return errBlocked{fmt.Errorf("%s. You are the only administrator left, and unlock yourself once "+
				"it is a day after another stopped being one: after %s", own,
				rm.Until().UTC().Format("15:04 MST on 2 Jan 2006"))}
		}
		if !onlyAdministrator(root, caller.Name) {
			record(root, caller.auditRecord("account.unlocked", "/", audit.Denied,
				map[string]string{"for": name, "why": "their own lockout, with another administrator to ask"}))
			return errBlocked{fmt.Errorf("%s. Another administrator can, with quilzo auth unlock %s or on "+
				"the Sign-ins screen", own, name)}
		}
		detail["alone"] = "true"
	}
	held, err := lockoutStore(root).Unlock(name, now)
	if err != nil {
		return err
	}
	if held {
		if err := recordE(root, caller.auditRecord("account.unlocked", "/", audit.Success, detail)); err != nil {
			return err
		}
	}
	if w.JSON(map[string]any{"for": name, "unlocked": held}) {
		return nil
	}
	if !held {
		w.Human("%s is not locked out\n", name)
		return nil
	}
	w.Human("%s can sign in again from anywhere\n", name)
	return nil
}
