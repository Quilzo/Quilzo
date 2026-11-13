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

	"github.com/quilzo/quilzo/internal/shield"
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
	// Before any of this test has run, so that what earlier tests left
	// running is told apart from what this one starts (startedSince). Taken
	// after the setup below, a worker that building the site or the reloader
	// started and kept was counted as an earlier test's, and with it every
	// goroutine it started for a request.
	origin := goroutineSnapshot()
	root, tpl, _ := installedDemo(t)
	design, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	run := testRun(t, root)
	run.baseURL = "https://shop.example"
	run.shield.where = shield.Site
	st, err := run.build(design, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Served as `quilzo site` serves it (site.go): the edge, the shield's
	// guard, and the reloader, which builds the site again on the first
	// visit after a publish. The site's own handler alone left all three
	// out, and with them what every publish does to a running server, which
	// is to build the site again: a goroutine started per rebuild, or per
	// request by the guard, was never run here, so it passed.
	rl := newSiteReloader(root, tpl, run.store, site.RefLive, design, st, run.build)
	rl.say = func(string, ...any) {}
	h := edge(root, "site.trusted_proxy", run.shield.guard.Wrap(shield.Site, rl))

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
		// builds the site again and the search index of the new live commit.
		edits++
		was := rl.Site()
		addOwnPage(t, root, tpl, "leak-check", map[string]any{
			"title": "Leak check", "body": "Edit " + strconv.Itoa(edits) + " of a page about paper.",
		})
		visit()
		if rl.Site() == was {
			t.Errorf("publish %d was served without building the site again: the rebuild was not measured", edits)
		}
	}

	// Once first, so whatever is started once and kept for the life of the
	// process is running before the count begins and is not mistaken for a
	// leak. What it starts later is still counted: origin is the moment
	// before this test had started anything at all.
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
		started = after.startedSince(before, origin)
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
// before was taken. origin is a snapshot from before the test started
// anything.
//
// One not alive then was started since: a goroutine's id is never given to
// another. Ids are not in the order goroutines start, because each processor
// hands them out from a batch of its own, so "higher than any then" would
// miss some. A new goroutine is the hot paths' if its line of parents leads
// to the test before it reaches a goroutine that was already running at
// origin. Tests that ran before this one can leave goroutines of their own
// running, and what those start meanwhile, and what that starts, is theirs,
// not a leak here. A parent seen in no snapshot ended between them, and its
// line cannot be followed; it is counted as the hot paths', the direction
// that reports a leak rather than hides one.
//
// The whole line, not the parent alone. Asking only whether the parent was
// new since before hid everything started by a worker the warm-up started
// and kept, which is where a leak per request is most often started from:
// such a worker starting one goroutine per request to /sitemap.xml, each
// sleeping an hour, passed with 75 of them running. It also counted what an
// earlier test's goroutine started through a goroutine of its own.
func (s goroutineState) startedSince(before, origin goroutineState) []goroutineRecord {
	ours := func(id int) bool {
		// A line ends at the test or at origin; the bound only stops a
		// dump that could not be read from going round for ever.
		for range 1000 {
			if id == s.self {
				return true
			}
			if _, old := origin.all[id]; old {
				return false
			}
			g, ok := s.all[id]
			if !ok {
				g, ok = before.all[id]
			}
			if !ok {
				return true
			}
			id = g.parent
		}
		return true
	}
	var out []goroutineRecord
	for id, g := range s.all {
		if _, old := before.all[id]; old || id == s.self {
			continue
		}
		if ours(g.parent) {
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(a, b goroutineRecord) int { return a.id - b.id })
	return out
}

// A goroutine is the hot paths' however many goroutines lie between it and
// the work that started it, and not theirs when the line leads to one that
// was running before they began.
//
// startedSince asked only whether a goroutine's parent was new since the
// count began. A worker the warm-up started and kept is not new, so every
// goroutine it started afterwards went uncounted: one started per request
// to /sitemap.xml by such a worker, sleeping for an hour, passed the leak
// test 75 times over. And a goroutine left by an earlier test that started
// one, which started another, had that last one counted as a leak here.
func TestALeakIsCountedThroughAWorkerTheWarmUpKept(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	ready := make(chan struct{})
	block := func() {
		ready <- struct{}{}
		<-stop
	}

	// An earlier test's goroutine, still running, which starts one that
	// starts another whenever it is told to.
	start := goroutineSnapshot()
	theirs := make(chan struct{})
	defer close(theirs)
	go func() {
		for range theirs {
			go func() {
				go block()
				block()
			}()
		}
	}()
	origin := goroutineSnapshot()

	// The warm-up starts a worker and keeps it.
	jobs := make(chan struct{})
	defer close(jobs)
	go func() {
		for range jobs {
			go block()
		}
	}()
	before := goroutineSnapshot()

	// The counted rounds hand the worker two jobs, and the earlier test's
	// goroutine starts two of its own meanwhile.
	jobs <- struct{}{}
	jobs <- struct{}{}
	theirs <- struct{}{}
	for range 4 {
		<-ready
	}
	// The one goroutine the test started between two snapshots.
	startedBetween := func(from, to goroutineState) int {
		for id, g := range to.all {
			if _, old := from.all[id]; !old && g.parent == to.self {
				return id
			}
		}
		t.Fatal("a goroutine the test started is not in the snapshot taken after it")
		return 0
	}
	earlier, worker := startedBetween(start, origin), startedBetween(origin, before)

	// Only these two lines are looked at. Anything else in the process can
	// start a goroutine meanwhile, a timer's among them, whose line cannot
	// be followed and is counted, and this asks about the rule, not the
	// process.
	now := goroutineSnapshot()
	mine := 0
	for _, g := range now.startedSince(before, origin) {
		if g.parent == worker {
			mine++
		}
		if g.parent == earlier || now.all[g.parent].parent == earlier {
			t.Errorf("goroutine %d was counted, and the earlier test's goroutine %d started its line", g.id, earlier)
		}
	}
	if mine != 2 {
		t.Errorf("counted %d of the two goroutines the worker %d started", mine, worker)
	}
}
