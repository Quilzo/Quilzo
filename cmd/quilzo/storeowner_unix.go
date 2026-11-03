// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// storeOwnedByMe is whether the store's directory belongs to this process's
// effective user, or this process is the superuser. Ownership of the
// directory is what decides who can rewrite the policy inside it, so it is
// the fact a server's start is decided on. A store that cannot be read is
// nobody's: the gate falls through to asking for a token.
func storeOwnedByMe(root string) bool {
	owner, ok := storeUID(root)
	if !ok {
		return false
	}
	euid := os.Geteuid()
	return euid == 0 || uint64(euid) == owner
}

func storeUID(root string) (uint64, bool) {
	fi, err := os.Stat(root)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Uid), true
}

// storeOwnerHint says who may start a server without a token, for the
// refusal somebody else gets.
func storeOwnerHint(root string) string {
	owner, ok := storeUID(root)
	if !ok {
		return "  the store could not be read to see whose it is"
	}
	who := "uid " + strconv.FormatUint(owner, 10)
	if u, err := user.LookupId(strconv.FormatUint(owner, 10)); err == nil {
		who = u.Username + " (" + who + ")"
	}
	return fmt.Sprintf("  or start it as the account the store belongs to, %s; this is uid %d", who, os.Geteuid())
}
