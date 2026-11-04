// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Keeping a long-running server's credentials current.
//
// The store is one directory shared by several processes: the admin, the
// public site, and every CLI invocation. Each loaded the token file once at
// startup, so revoking a credential through the admin left the site accepting
// it until that process restarted — and "revoked" became a claim about a file
// rather than a fact about a credential.
//
// Found by running two containers against one volume and revoking a token in
// the first while the second kept answering 200. A single-process test cannot
// see it, because there is only ever one copy of the store in memory.
//
// A stat rather than a watch. fsnotify is a dependency this program does not
// have, and a poll on a timer has a staleness window by construction. A stat
// is a few microseconds, happens on the request that is about to make a
// decision, and reloads only when the file has actually changed — so the
// common case costs one syscall and no parsing.
func tokenReloader(root string, ts *auth.TokenStore) func() {
	return reloadOnChange(tokensPath(root), func(path string) bool {
		var fresh auth.TokenStore
		if err := loadJSON(path, &fresh); err != nil {
			// A half-written file, most likely: another process is mid-save.
			// Keeping what we have and trying again next request is right —
			// the write is atomic, so the next stat will see the finished one.
			return false
		}
		ts.Replace(fresh.Tokens)
		return true
	})
}

// policyReloader is tokenReloader for the access rules, which are the same
// kind of shared file.
//
// The content API was given the policy loaded at startup and nothing else, so
// under `quilzo serve` a reader granted on the command line was refused at
// /api/v1 while the admin's screens and /mcp served them, and a revoked grant
// kept reading pages there until the admin restarted. Found on the reference
// stack, where every grant had to be followed by a restart before the API
// could be tested.
func policyReloader(root string, p *auth.Policy) func() {
	return reloadOnChange(policyPath(root), func(path string) bool {
		var fresh auth.Policy
		if err := loadJSON(path, &fresh); err != nil {
			return false
		}
		p.Replace(fresh.Bindings)
		return true
	})
}

// reloadOnChange calls load when the file at path has changed since it last
// succeeded, one stat per call otherwise.
func reloadOnChange(path string, load func(path string) bool) func() {
	var (
		mu      sync.Mutex
		lastMod time.Time
		lastLen int64
	)
	return func() {
		mu.Lock()
		defer mu.Unlock()

		fi, err := os.Stat(path)
		if err != nil {
			// Gone or unreadable. Deliberately not clearing what is in
			// memory: a store whose token file has been deleted should keep
			// enforcing what it last knew, because the alternative is that
			// removing a file is a way to make every credential invalid and
			// lock everybody out at once.
			return
		}
		// Size as well as time. A same-second write of a same-size file is the
		// case mtime alone misses, and revocation writes a file that is very
		// nearly the same size as the one before it.
		if fi.ModTime().Equal(lastMod) && fi.Size() == lastLen {
			return
		}
		if !load(path) {
			return
		}
		lastMod, lastLen = fi.ModTime(), fi.Size()
	}
}
