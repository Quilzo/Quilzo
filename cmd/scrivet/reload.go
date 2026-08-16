package main

import (
	"os"
	"sync"
	"time"

	"github.com/lithoform/lithoform/internal/auth"
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
	var (
		mu      sync.Mutex
		lastMod time.Time
		lastLen int64
	)
	path := tokensPath(root)
	return func() {
		mu.Lock()
		defer mu.Unlock()

		fi, err := os.Stat(path)
		if err != nil {
			// Gone or unreadable. Deliberately not clearing the in-memory
			// set: a store whose token file has been deleted should keep
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
		var fresh auth.TokenStore
		if err := loadJSON(path, &fresh); err != nil {
			// A half-written file, most likely: another process is mid-save.
			// Keeping what we have and trying again next request is right —
			// the write is atomic, so the next stat will see the finished one.
			return
		}
		lastMod, lastLen = fi.ModTime(), fi.Size()
		ts.Replace(fresh.Tokens)
	}
}
