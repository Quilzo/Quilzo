// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/site"
)

// The paths every visitor and every publish takes leave no goroutine behind.
//
// A goroutine that is never going to finish passes every test that does not
// count goroutines: the page is served, the publish succeeds, and the
// goroutine waits on a channel nobody will send on, holding what it closed
// over. On a public site that is one per request until the process runs out
// of memory, and nothing before that says so. A leak was looked for once by
// hand, with Go 1.27's goroutineleak profile over 16 visitors and three
// publishes, and none was found; this keeps it looked for, on every pull
// request and under the race detector every night.
//
// Two checks, because they see different leaks. The runtime's goroutineleak
// profile names goroutines blocked on something no running code can reach,
// which can never wake: the classic leak. It cannot see one waiting on
// something still reachable, a ticker or a channel held by the site, so the
// goroutines that the hot paths started are also counted, and any of them
// still alive once the work has had time to finish is reported with its
// stack.
func TestTheHotPathsLeakNoGoroutines(t *testing.T) {
	root, tpl, _ := installedDemo(t)
	design, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	run := testRun(t, root)
	run.baseURL = "https://shop.example"
	st, err := run.build(design, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := st.Handler()

	// What a visitor reads, as the measurement did: pages, the home page,
	// the shop, the sitemap, search, the catalogue and a page that is not
	// there. The demonstration has no journal, so no feed; the feed is read
	// through the same listings as the catalogue.
	routes := map[string]int{
		"/":                    http.StatusOK,
		"/shop":                http.StatusOK,
		"/product":             http.StatusOK,
		"/sitemap.xml":         http.StatusOK,
		"/search.json?q=paper": http.StatusOK,
		"/catalogue.json":      http.StatusOK,
		"/robots.txt":          http.StatusOK,
		"/no-such-page-here":   http.StatusNotFound,
	}
	for name := range pagesIn(t, root, site.RefLive) {
		if _, ok := routes["/"+name]; !ok && name != "index" && len(routes) < 14 {
			routes["/"+name] = 0
		}
	}
	visit := func() {
		for path, want := range routes {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://shop.example"+path, nil))
			if want != 0 && rec.Code != want {
				t.Errorf("GET %s answered %d, want %d: the hot path was not the one measured", path, rec.Code, want)
			}
		}
	}
	edits := 0
	hotPaths := func(visitors, rounds int) {
		var wg sync.WaitGroup
		for range visitors {
			wg.Go(func() {
				for range rounds {
					visit()
				}
			})
		}
		wg.Wait()
		// A publish with every gate, and the first visit after it, which
		// builds the search index of the new live commit.
		edits++
		addOwnPage(t, root, tpl, "leak-check", map[string]any{
			"title": "Leak check", "body": "Edit " + strconv.Itoa(edits) + " of a page about paper.",
		})
		visit()
	}

	// Once first, so whatever is started once and kept for the life of the
	// process is running before the count begins and is not mistaken for a
	// leak.
	hotPaths(2, 1)
	if t.Failed() {
		t.FailNow()
	}
	before := goroutineSnapshot()
	for range 3 {
		hotPaths(8, 3)
	}

	// Work the paths handed to the background is given time to end.
	var started []goroutineRecord
	for deadline := time.Now().Add(10 * time.Second); ; {
		after := goroutineSnapshot()
		started = after.startedSince(before)
		if len(started) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Each is counted and the first few are shown: a leak per request is
	// dozens of identical stacks, and one of them says where it starts.
	var leaked, running []goroutineRecord
	for _, g := range started {
		if g.leaked {
			leaked = append(leaked, g)
		} else {
			running = append(running, g)
		}
	}
	report := func(gs []goroutineRecord, what string) {
		if len(gs) == 0 {
			return
		}
		var b strings.Builder
		for _, g := range gs[:min(len(gs), 3)] {
			b.WriteString("\n" + g.stack + "\n")
		}
		t.Errorf("%d goroutine(s) started by the hot paths %s; the first of them:\n%s", len(gs), what, b.String())
	}
	report(leaked, "can never finish: the goroutineleak profile found them blocked on something nothing can reach")
	report(running, "were still running 10 s after the paths ended")
}

// goroutineRecord is one goroutine in a dump of all of them.
type goroutineRecord struct {
	id, parent int
	// leaked is the runtime's own verdict, from the goroutineleak profile.
	leaked bool
	stack  string
}

// goroutineState is every goroutine at one moment, and which of them took
// the snapshot.
type goroutineState struct {
	self int
	all  map[int]goroutineRecord
}

var goroutineHeader = regexp.MustCompile(`^goroutine (\d+) \[([^\]]*)\]`)
var goroutineParent = regexp.MustCompile(`(?m)^created by .* in goroutine (\d+)$`)

// goroutineSnapshot is every goroutine now, after the garbage collector has
// looked for leaks.
//
// The goroutineleak profile is written first because writing it is what
// runs the collection that finds leaked goroutines; until the next such
// collection, a dump of every goroutine marks them "(leaked)".
func goroutineSnapshot() goroutineState {
	if err := pprof.Lookup("goroutineleak").WriteTo(io.Discard, 1); err != nil {
		panic(err)
	}
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	s := goroutineState{all: map[int]goroutineRecord{}}
	for i, block := range bytes.Split(buf, []byte("\n\n")) {
		m := goroutineHeader.FindSubmatch(block)
		if m == nil {
			continue
		}
		g := goroutineRecord{stack: string(block)}
		g.id, _ = strconv.Atoi(string(m[1]))
		g.leaked = strings.Contains(string(m[2]), "(leaked)")
		if p := goroutineParent.FindSubmatch(block); p != nil {
			g.parent, _ = strconv.Atoi(string(p[1]))
		}
		// runtime.Stack puts the calling goroutine first.
		if i == 0 {
			s.self = g.id
		}
		s.all[g.id] = g
	}
	return s
}

// startedSince is the goroutines alive now that the hot paths started after
// before was taken.
//
// One not alive then was started since: a goroutine's id is never given to
// another. Ids are not in the order goroutines start, because each processor
// hands them out from a batch of its own, so "higher than any then" would
// miss some. A new goroutine is the hot paths' if the test started it, or if
// its parent was itself new. Tests that ran before this one can leave
// goroutines of their own running, and what those start meanwhile is theirs,
// not a leak here.
func (s goroutineState) startedSince(before goroutineState) []goroutineRecord {
	var out []goroutineRecord
	for id, g := range s.all {
		if _, old := before.all[id]; old || id == s.self {
			continue
		}
		if _, oldParent := before.all[g.parent]; g.parent == before.self || !oldParent {
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(a, b goroutineRecord) int { return a.id - b.id })
	return out
}
