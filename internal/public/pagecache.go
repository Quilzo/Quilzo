// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"time"

	"github.com/quilzo/quilzo/internal/site"
)

// Reading the published content set once instead of twice per request.
//
// # What it cost
//
// pages() walks the live commit: a ref read, a commit read, a tree read, and
// then a read of every published page. Each object read is an os.ReadFile, a
// full SHA-256 verification that the bytes hash to the name they are filed
// under, and a JSON unmarshal.
//
// It was called twice per page request. Once by the page handler and again,
// sixty lines later, by the context builder that handler calls — two functions
// that did not know about each other. So a two-hundred-page site did roughly
// four hundred file reads, four hundred hash verifications and four hundred
// unmarshals to serve one page, and did it again for the next request for the
// same URL. Measured on the demo shop: 2.8 ms per request, and throughput that
// stopped rising at about eight concurrent requests while latency climbed
// thirty-five fold — which is the signature of a server queueing rather than
// working.
//
// # Why a cache here can never be wrong
//
// Because the key is the content. A commit is the hash of a tree of hashes of
// bytes, publishing moves a ref, and nothing is ever edited in place. So the
// answer for a given commit is the answer forever, and there is no
// invalidation, no expiry and nothing to purge. That is the one thing a CDN is
// never allowed to assume about an origin, and it is true here by
// construction.
//
// # What it does not weaken
//
// The integrity check. store.read verifies that every object still hashes to
// its own name, and that is a tamper control rather than an optimisation.
// Caching does not skip it: the bytes were verified when they were first read,
// and they cannot have changed since, because changed bytes are a different
// name and therefore a different commit and therefore a different key.
//
// # Why the publish window is not cached with them
//
// Because it depends on the clock and not on the commit. A page embargoed
// until noon is in the tree all morning and must not be served, and a set
// filtered once and reused would keep it hidden all afternoon — or worse,
// reveal it early. So the expensive half is memoised and the cheap half is
// asked every time: the decode is commit-derived, the date comparison is not.

// pageSet is one commit's decoded pages, and what can be said about them
// without looking at a clock.
type pageSet struct {
	commit string
	// bodies is every page in the tree, decoded, including the ones a publish
	// window currently hides. Filtering here would make the memo
	// time-dependent, which is the thing it must not be.
	bodies map[string]any
	// oids is each page's object id, which is what a caller gets as the
	// second return and what the ETag is built from.
	oids map[string]string
	// window is each page's parsed publish window. Parsed once because the
	// dates are content; asked per request because the answer is not.
	window map[string]site.Window
	// hidden is the pages whose window could not be parsed. A malformed date
	// hides the page — failing closed, because the alternative is a typo
	// silently lifting an embargo.
	hidden map[string]bool
}

// decoded returns the memo for a commit, building it at most once.
//
// The build happens under the lock, which serialises two requests that both
// arrive for a commit nobody has decoded yet. That is the right trade and the
// same one internal/collection makes for its record index: the alternative is
// both of them doing the same expensive read, and the second one throwing its
// answer away.
func (st *Site) decoded(commit string) (*pageSet, error) {
	st.pageMu.Lock()
	defer st.pageMu.Unlock()

	if st.pageSet != nil && st.pageSet.commit == commit {
		return st.pageSet, nil
	}

	c, err := st.Store.GetCommit(commit)
	if err != nil {
		return nil, err
	}
	tree, err := st.Store.GetTree(c.Tree)
	if err != nil {
		return nil, err
	}

	set := &pageSet{
		commit: commit,
		bodies: make(map[string]any, len(tree)),
		oids:   make(map[string]string, len(tree)),
		window: make(map[string]site.Window, len(tree)),
		hidden: map[string]bool{},
	}
	for name, oid := range tree {
		var body any
		if err := st.Store.GetBlob(oid, &body); err != nil {
			continue
		}
		set.bodies[name] = body
		set.oids[name] = oid
		if wnd, werr := site.WindowOf(body); werr != nil {
			set.hidden[name] = true
		} else {
			set.window[name] = wnd
		}
	}

	// One commit, not a history. The previous one is of no use the moment the
	// ref moves, and holding a map of them would be a cache whose size is
	// decided by how often somebody publishes.
	st.pageSet = set
	return set, nil
}

// visibleAt is the published set as it stands at one moment.
//
// A fresh pair of maps per call, so a caller holding them cannot be surprised
// by a later publish and cannot disturb the memo by writing into them. The
// bodies inside are shared and are treated as immutable everywhere — which is
// what content addressing means, and what internal/render's decorator relies
// on when it copies a page body before adding anything to it.
func (s *pageSet) visibleAt(now time.Time) (map[string]any, map[string]string) {
	out := make(map[string]any, len(s.bodies))
	visible := make(map[string]string, len(s.bodies))
	for name, body := range s.bodies {
		// The publish window, evaluated here rather than by a scheduler.
		//
		// Every read path on this server goes through this function — the
		// page, the sitemap, the search index, the machine-readable listing —
		// so filtering once is what stops a page being excluded from one and
		// linked from another. A page the sitemap advertises and the page
		// handler 404s is worse than either alone.
		if s.hidden[name] || !s.window[name].Public(now) {
			continue
		}
		out[name] = body
		visible[name] = s.oids[name]
	}
	return out, visible
}
