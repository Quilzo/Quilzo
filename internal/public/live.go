// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Live updates: a thread's readers see a new post without reloading.
//
// # How
//
// A Server-Sent Events stream per thread, at /live/board/NAME/PAGE, that
// says "changed" whenever the thread's version does. The version is read
// every couple of seconds rather than pushed, because a post can be approved
// or deleted in the admin, which is another process: reading what is stored
// sees every writer, wherever it runs, with nothing to keep in step.
//
// The page's script (live.js) then fetches the page again and swaps only
// the list of posts, leaving the form and whatever somebody is typing in it
// alone. It runs by its hash, like the static chatbot's: the same bytes on
// every response, so a page answered "not modified" from a cache still has
// a policy that permits it.
//
// # Bounds
//
// A stream lasts ten minutes and then closes, and the browser opens another
// if the page is still there. One address may hold a handful at once and the
// server a few hundred in all; past either, a stream is refused and the page
// simply does not update by itself, which is what it did before.

//go:embed live.js
var liveJS string

var liveHash = func() string {
	sum := sha256.Sum256([]byte(liveJS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

// Limits on streams, and how often a thread is looked at.
const (
	livePerSource = 6
	liveTotal     = 400
	liveLife      = 10 * time.Minute
	liveEvery     = 2 * time.Second
	livePing      = 25 * time.Second
)

// CopyHeader is set on the requests a static copy is built from, so a page
// leaves out what only works with this server behind it.
const CopyHeader = "Quilzo-Copy"

// liveScript is the markup that runs live.js on a page, or nothing.
func liveScript() string {
	return "<script>" + liveJS + "</script>\n"
}

// liveOn reports whether a page's posts should update by themselves.
func (st *Site) liveOn(r *http.Request, body any) bool {
	return st.boardsOn() && r.Header.Get(CopyHeader) == "" && len(commentsOn(body)) > 0
}

func (st *Site) liveAcquire(source string) bool {
	st.liveMu.Lock()
	defer st.liveMu.Unlock()
	if st.liveBy == nil {
		st.liveBy = map[string]int{}
	}
	if st.liveN >= liveTotal || st.liveBy[source] >= livePerSource {
		return false
	}
	st.liveN++
	st.liveBy[source]++
	return true
}

func (st *Site) liveRelease(source string) {
	st.liveMu.Lock()
	defer st.liveMu.Unlock()
	st.liveN--
	if st.liveBy[source]--; st.liveBy[source] <= 0 {
		delete(st.liveBy, source)
	}
}

// live streams one thread's changes: GET /live/board/NAME/PAGE.
func (st *Site) live(w http.ResponseWriter, r *http.Request) {
	if !st.boardsOn() || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/live/board/")
	name, page, ok := strings.Cut(rest, "/")
	if !ok || name == "" || page == "" {
		http.NotFound(w, r)
		return
	}
	set, err := st.Boards.Set()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if _, declared := set.Get(name); !declared {
		http.NotFound(w, r)
		return
	}
	_, member := st.signedIn(r)
	if !st.pageShowsBoard(page, name, member) {
		http.NotFound(w, r)
		return
	}
	source := sourceOf(r)
	if !st.liveAcquire(source) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many live updates from here", http.StatusTooManyRequests)
		return
	}
	defer st.liveRelease(source)

	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	// For a proxy in front that would otherwise hold the stream back.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(s string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := fmt.Fprint(w, s); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	// Retry after five seconds when the stream ends, rather than at once.
	if !send("retry: 5000\n\n") {
		return
	}
	version := st.Boards.Store.Version(name, page)
	tick := time.NewTicker(liveEvery)
	defer tick.Stop()
	ping := time.NewTicker(livePing)
	defer ping.Stop()
	end := time.NewTimer(liveLife)
	defer end.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-end.C:
			return
		case <-ping.C:
			if !send(": still here\n\n") {
				return
			}
		case <-tick.C:
			if v := st.Boards.Store.Version(name, page); v != version {
				version = v
				if !send("event: changed\ndata: " + v + "\n\n") {
					return
				}
			}
		}
	}
}
