// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"sync"

	"github.com/quilzo/quilzo/internal/store"
)

// Reading a commit's pages once, not once per caller.
//
// # What it cost
//
// PagesAt read every page from disk, twice (once to learn it is not a tree,
// once to decode it), verified each against its hash and unmarshalled it, on
// every call. The admin calls it on almost every screen, and the Structure
// screen calls it for the draft and again for the live site: about 75 MB
// allocated per request on a store of two thousand pages. Each request in
// flight held its own decode, so memory rose by some twenty megabytes for
// every request at once, and a burst against the admin, the API and the
// agent interface, which share one process, ended with it killed for memory
// at twelve gigabytes. The public site had decoded once per commit all along
// (internal/public/pagecache.go).
//
// # Why it can never be stale
//
// For the reason the public site's can't: the key is the commit, a commit is
// the hash of a tree of hashes of the bytes, and nothing is edited in place.
// A save or a publish moves a ref to a different commit, and the next read of
// the ref is a different key. The integrity check is not skipped either: the
// bytes were verified when they were read, and changed bytes would be another
// commit.
//
// # Why every caller still gets its own
//
// Because callers change what they are given. The editor adds the page being
// saved to the map it read and writes the map back; a bulk edit rewrites
// fields inside a page. One decode handed to all of them would be one
// caller's edit showing up in another's screen, or in another's commit. So
// each call gets fresh maps and slices, and shares only the strings, which Go
// does not let anybody change and which are most of the bytes.

// memoEntries is how many commits are remembered at once, across stores:
// the draft and the live site, with room for a history view or two. Not
// one, because the Structure screen reads two commits a request and one
// entry would decode both every time; not unbounded, because a decode is
// the size of the site.
const memoEntries = 8

// decoded is one commit's pages, or the decode of them in progress.
type decoded struct {
	s      *store.Store
	commit string
	// ready is closed when pages and err are set. A caller that finds the
	// entry waits for it rather than decoding the same commit beside it,
	// which is what a burst after a save would otherwise be.
	ready chan struct{}
	pages map[string]any
	err   error
}

// pageMemo is the commits remembered, most recently used last.
type pageMemo struct {
	mu      sync.Mutex
	entries []*decoded
}

var memo pageMemo

// at is commit's pages in s, decoded by read at most once while remembered.
// A store is its own key, not its directory: two opened on one directory
// may hold different keys, and one without the key must not be handed what
// the other decrypted.
func (m *pageMemo) at(s *store.Store, commit string,
	read func() (map[string]any, error)) (map[string]any, error) {
	m.mu.Lock()
	for i, e := range m.entries {
		if e.s == s && e.commit == commit {
			m.entries = append(append(m.entries[:i:i], m.entries[i+1:]...), e)
			m.mu.Unlock()
			<-e.ready
			return e.pages, e.err
		}
	}
	e := &decoded{s: s, commit: commit, ready: make(chan struct{})}
	m.entries = append(m.entries, e)
	if len(m.entries) > memoEntries {
		m.entries = append(m.entries[:0:0], m.entries[len(m.entries)-memoEntries:]...)
	}
	m.mu.Unlock()

	e.pages, e.err = read()
	if e.err != nil {
		// Not remembered: a read that failed may succeed once a key is
		// supplied, and an error is no answer to hold on to.
		m.mu.Lock()
		for i, x := range m.entries {
			if x == e {
				m.entries = append(m.entries[:i:i], m.entries[i+1:]...)
				break
			}
		}
		m.mu.Unlock()
	}
	close(e.ready)
	return e.pages, e.err
}

// copyPages is pages with fresh maps and slices all the way down, so a
// caller may change anything it is given. Strings, numbers and booleans are
// shared: nothing can change them.
func copyPages(pages map[string]any) map[string]any {
	out := make(map[string]any, len(pages))
	for name, body := range pages {
		out[name] = copyValue(body)
	}
	return out
}

func copyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = copyValue(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = copyValue(x)
		}
		return out
	default:
		return v
	}
}
