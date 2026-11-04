// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assistant"
)

// Today lists what waits first, what cannot be taken back before what
// only reads, and then counts what is happening, each figure a link to
// the records it counts.
func TestTodayPutsWhatWaitsFirstAndLinksEveryFigure(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	now := time.Now()
	read := agent.Action{Op: "read_page", Input: map[string]any{"page": "x"}}
	waitingRun(st, "run-20261014-000000c1", "librarian", read, "it asks first", now.Add(-time.Hour))
	pay := agent.Action{Op: "browser_click", Input: map[string]any{"ref": "e9"}}
	waitingRun(st, "run-20261014-000000c2", "buyer", pay,
		`it presses button "Pay now" on shop.example.com, and it is called "Pay now"`, now)
	st.runs["run-20261014-000000c3"] = agent.Keep("run-20261014-000000c3", "dana", "m", now,
		agent.Trace{Agent: "tidy", Goal: "tidy", Complete: true}, agent.Receipt{Did: 1})
	st.runs["run-20261014-000000c4"] = agent.Keep("run-20261014-000000c4", "dana", "m", now.Add(-48*time.Hour),
		agent.Trace{Agent: "tidy", Goal: "tidy", Complete: true}, agent.Receipt{Did: 1})

	body := get(t, srv, "/today", token).Body.String()
	whole(t, body)
	buyer, librarian := strings.Index(body, ">buyer<"), strings.Index(body, ">librarian<")
	if buyer < 0 || librarian < 0 || buyer > librarian {
		t.Errorf("a payment waiting is not listed before a read that waited longer (%d, %d)", buyer, librarian)
	}
	if !strings.Contains(body, `<dt>Agent run finished in the last day</dt><dd><a href="/agents">1</a></dd>`) {
		t.Errorf("the finished run is not counted once, as a link:\n%s", firstLines(body[strings.Index(body, "happening"):], 8))
	}
	if !strings.Contains(body, `href="/today"`) {
		t.Error("Today is not in the menu")
	}
}

// Somebody whose work is one area sees Today, and no figure for a screen
// they cannot open.
func TestTodayCountsOnlyWhatSomebodyCanOpen(t *testing.T) {
	srv, token := asJob(t, "analyst")
	w := get(t, srv, "/today", token)
	if w.Code != http.StatusOK {
		t.Fatalf("an analyst cannot open Today: %d", w.Code)
	}
	body := w.Body.String()
	whole(t, body)
	for _, never := range []string{"Agent run", "changed in the draft", "Visitors waiting"} {
		if strings.Contains(body, never) {
			t.Errorf("an analyst is shown %q", never)
		}
	}
	if !strings.Contains(body, `href="/today"`) {
		t.Error("Today is not in an analyst's menu")
	}
}

// Somebody chooses where a sign-in lands, and can choose again.
func TestWhereSomebodyStartsIsTheirChoice(t *testing.T) {
	srv, token := setup(t)
	w := postForm(t, srv, "/today/start", token, url.Values{"to": {"pages"}}.Encode())
	var set *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == StartCookie {
			set = c
		}
	}
	if w.Code != http.StatusSeeOther || set == nil || set.Value != "pages" || !set.HttpOnly {
		t.Fatalf("%d %+v", w.Code, set)
	}
	r := requestFor(t, "/today")
	r.AddCookie(set)
	if startPath(r) != "/" {
		t.Error("choosing Pages did not move the start")
	}
	w = postForm(t, srv, "/today/start", token, url.Values{"to": {"today"}}.Encode())
	cleared := false
	for _, c := range w.Result().Cookies() {
		cleared = cleared || (c.Name == StartCookie && c.MaxAge < 0)
	}
	if !cleared {
		t.Error("choosing Today again did not clear the choice")
	}
	if w := postForm(t, srv, "/today/start", token, "to=elsewhere"); w.Code != http.StatusBadRequest {
		t.Errorf("an unknown start answered %d", w.Code)
	}
}

func requestFor(t *testing.T, path string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Every way to start something on Today lands where it is done. The
// buttons say what they do, "Upload a picture" and "Add a feature", and
// opened the top of Media, Make and Chatbots: a screen with another name,
// and on Make the form for a feature five sections down. Each now lands
// on the part of its screen that does it, as Write a page always did, or
// opens a screen whose name its own begins with.
func TestEveryStartLandsWhereItIsDone(t *testing.T) {
	srv, token := fullyWired(t)
	wireFeatures(srv)
	srv.Assistants = (&fakeAssistants{set: &assistant.Set{}}).wire()
	body := get(t, srv, "/today", token).Body.String()
	nav := regexp.MustCompile(`(?s)<nav class="glance-starts"[^>]*>(.*?)</nav>`).FindStringSubmatch(body)
	if nav == nil {
		t.Fatal("Today shows no way to start something")
	}
	link := regexp.MustCompile(`<a [^>]*href="([^"]+)"[^>]*>([^<]+)</a>`)
	heading := regexp.MustCompile(`(?s)<h1[^>]*>(.*?)</h1>`)
	starts := link.FindAllStringSubmatch(nav[1], -1)
	for _, m := range starts {
		href, label := html.UnescapeString(m[1]), html.UnescapeString(m[2])
		path, frag, _ := strings.Cut(href, "#")
		w := get(t, srv, path, token)
		if w.Code != http.StatusOK {
			t.Errorf("%q goes to %s, which answered %d", label, path, w.Code)
			continue
		}
		page := w.Body.String()
		if frag != "" {
			if !strings.Contains(page, `id="`+frag+`"`) {
				t.Errorf("%q goes to #%s, which %s does not have", label, frag, path)
			}
			continue
		}
		h1 := ""
		if h := heading.FindStringSubmatch(page); h != nil {
			h1 = strings.TrimSpace(h[1])
		}
		if h1 == "" || !strings.HasPrefix(label, h1) {
			t.Errorf("%q opens the top of a screen called %q", label, h1)
		}
	}
	if len(starts) < 5 {
		t.Fatalf("only %d ways to start something", len(starts))
	}
}
