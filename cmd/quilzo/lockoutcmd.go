// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
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

// authUnlock is `quilzo auth unlock NAME`.
func authUnlock(root string, args []string) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: quilzo auth unlock NAME")
	}
	name := args[0]
	caller := resolveCaller(root, "")
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	held, err := lockoutStore(root).Unlock(name, time.Now())
	if err != nil {
		return err
	}
	if held {
		if err := recordE(root, caller.auditRecord("account.unlocked", "/", audit.Success,
			map[string]string{"for": name})); err != nil {
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
