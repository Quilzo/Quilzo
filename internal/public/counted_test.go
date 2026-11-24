// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/chatact"
	"github.com/quilzo/quilzo/internal/experiment"
	"github.com/quilzo/quilzo/internal/handoff"
)

const browser = "Mozilla/5.0 (X11; Linux x86_64) Chrome/149.0 Safari/537.36"

func TestOnlyPagesAreCountedAsViews(t *testing.T) {
	st, _ := askSite(t, shopBot)
	c, err := analytics.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Analytics = c
	h := map[string]string{"User-Agent": browser}
	for _, path := range []string{"/", "/returns", "/site.css", "/no-such-page", "/ask/help"} {
		get(st, path, h)
	}
	get(st, "/returns", map[string]string{"User-Agent": "Googlebot/2.1"})
	d := c.Today()
	if d.Views != 3 || d.Pages["/site.css"].Views != 0 || d.Pages["/no-such-page"].Views != 0 {
		t.Fatalf("views %d, pages %+v", d.Views, d.Pages)
	}
	// An answered question is a conversion for the chatbot.
	r := askPost(st, "help", "can I return opened ink?")
	_ = r
	if c.Today().Goals["chatbot:help"] != 0 {
		// askPost sends no user agent, which is not a browser, so not counted.
		t.Fatal("a request with no user agent converted")
	}
}

// TestARevisitAnswered304IsStillAView — found by driving the site: the second
// visit to a page came back Not Modified and was not counted.
func TestARevisitAnswered304IsStillAView(t *testing.T) {
	st, _ := askSite(t, shopBot)
	c, _ := analytics.Open(t.TempDir(), nil)
	st.Analytics = c
	first := get(st, "/returns", map[string]string{"User-Agent": browser})
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Skip("pages carry no ETag")
	}
	again := get(st, "/returns", map[string]string{"User-Agent": browser,
		"If-None-Match": etag, "Sec-Fetch-Dest": "document"})
	if again.Code != 304 {
		t.Fatalf("the revisit answered %d", again.Code)
	}
	// A stylesheet revalidating is not a view.
	get(st, "/returns", map[string]string{"User-Agent": browser,
		"If-None-Match": etag, "Sec-Fetch-Dest": "style"})
	if d := c.Today(); d.Views != 2 {
		t.Fatalf("views %d, want 2", d.Views)
	}
}

// A chatbot conversation's address, and the page an agent request waits
// on, are counted without what makes them somebody's.
//
// A conversation's address carries the secret that is the only key to it:
// whoever has it reads the conversation, writes in it as the visitor and
// ends it. Counted by its path, every one a visitor opened went into the
// day's totals in clear, where `quilzo analytics` shows them to anybody who
// may read content; and a request's page, which shows what an agent found
// for one visitor, the same.
func TestAConversationAndARequestAreCountedWithoutTheirAddresses(t *testing.T) {
	st, _, _ := handoffSite(t)
	const asked = "0123456789abcdef0123456789abcdef"
	st.Assistants.Answer = func(id string) (chatact.Result, bool, bool) {
		return chatact.Result{}, false, id == asked
	}
	dir := t.TempDir()
	c, err := analytics.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Analytics = c
	loc := start(t, st, "my order 123 is late")
	secret := strings.TrimPrefix(loc, "/ask/help/c/")
	h := map[string]string{"User-Agent": browser}
	for _, p := range []string{loc, "/ask/help/act/" + asked} {
		if w := get(st, p, h); w.Code != http.StatusOK {
			t.Fatalf("%s answered %d", p, w.Code)
		}
	}
	// And one that has ended, and a request that is not there, which are
	// the site's own 404.
	ended, _, _ := handoff.NewSecret()
	const gone = "fedcba9876543210fedcba9876543210"
	for _, p := range []string{"/ask/help/c/" + ended, "/ask/help/act/" + gone} {
		if w := get(st, p, h); w.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d", p, w.Code)
		}
	}

	d := c.Today()
	if d.Views != 2 || d.Pages["/ask/help/c/"].Views != 1 || d.Pages["/ask/help/act/"].Views != 1 {
		t.Fatalf("views %d, pages %+v", d.Views, d.Pages)
	}
	keys := []string{secret, asked, ended, gone}
	for path := range d.Pages {
		for _, k := range keys {
			if strings.Contains(path, k) {
				t.Errorf("the day's pages hold %q", path)
			}
		}
	}
	for path := range d.Missing {
		for _, k := range keys {
			if strings.Contains(path, k) {
				t.Errorf("the day's missing addresses hold %q", path)
			}
		}
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	_ = filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, _ := os.ReadFile(path)
		for _, k := range keys {
			if strings.Contains(string(b), k) {
				t.Errorf("%s holds %q", filepath.Base(path), k)
			}
		}
		return nil
	})
}

// A browser's report of a policy violation on a conversation's page names
// the page as analytics does, without the secret in its address.
func TestAViolationOnAConversationsPageDoesNotNameItsSecret(t *testing.T) {
	secret, _, _ := handoff.NewSecret()
	body := `{"csp-report":{"document-uri":"https://shop.example/ask/help/c/` + secret +
		`","blocked-uri":"inline","violated-directive":"script-src 'none'"}}`
	got := parseViolations([]byte(body), "shop.example")
	if len(got) != 1 || got[0].Page != "/ask/help/c/" {
		t.Fatalf("kept %+v", got)
	}
}

// A browser's report of a policy violation on this site names its page by
// the address analytics counts the page under, which is one for one page.
//
// A report named its page by the path analytics counts it under, and
// analytics came to count /about/ and /about as the one page they are, and
// the home page reached by its name as /: the two rules were written apart
// and a report kept the address as asked. A violation is counted by how
// many networks report the same thing on the same page, so one page's was
// two things, each reported by some of them.
func TestAViolationIsOnThePageAnalyticsCountsItUnder(t *testing.T) {
	st := published(t, map[string]any{"index": map[string]any{"title": "Home"},
		"about": map[string]any{"title": "About"}})
	var got []string
	st.OnViolation = func(v Violation, r *http.Request) { got = append(got, v.Group()) }
	secret, _, _ := handoff.NewSecret()
	for _, at := range []string{"/about", "/about/", "/", "/index", "/index/", "/ask/help/c/" + secret} {
		req := httptest.NewRequest(http.MethodPost, "http://shop.example"+ReportsPath, strings.NewReader(
			`{"csp-report":{"document-uri":"https://shop.example`+at+
				`","blocked-uri":"inline","violated-directive":"script-src 'none'"}}`))
		req.Header.Set("Content-Type", "application/csp-report")
		st.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	want := []string{"script-src inline /about", "script-src inline /about", "script-src inline /",
		"script-src inline /", "script-src inline /", "script-src inline /ask/help/c/"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("reported on %q, want %q", got, want)
	}
}

// TestOnePageIsCountedUnderOneAddress — found by driving the site: /about,
// /about/ and /about%2f are one page with one canonical link, and analytics
// kept them as three, so the page's views were split and a link brought in
// from WordPress, which ends in a slash, counted somewhere nobody looked. The
// home page reached by its own name is the home page too.
func TestOnePageIsCountedUnderOneAddress(t *testing.T) {
	st, c := experimentSite(t)
	for i, path := range []string{"/thanks", "/thanks/", "/thanks%2f", "/", "/index", "/index/"} {
		if w := visitAs(st, path, fmt.Sprintf("203.0.113.%d", i)); w.Code != 200 {
			t.Fatalf("%s answered %d", path, w.Code)
		}
	}
	d := c.Today()
	if d.Pages["/thanks"].Views != 3 || d.Pages["/"].Views != 3 {
		t.Fatalf("one page counted under several addresses: %+v", d.Pages)
	}
	for p := range d.Pages {
		if p != "/thanks" && p != "/" {
			t.Errorf("counted under %q", p)
		}
	}
}

// TestAPageGoalIsReachedWithATrailingSlash — found by driving the site: an
// experiment whose goal was page:/delivery reported nobody converting when
// every visitor reached /delivery/, the same page; and a goal written with
// the slash missed every visitor who came without it.
func TestAPageGoalIsReachedWithATrailingSlash(t *testing.T) {
	for _, tc := range []struct{ goal, reached string }{
		{"page:/thanks", "/thanks/"},
		{"page:/thanks", "/thanks%2f"},
		{"page:/thanks/", "/thanks"},
		{"page:/", "/index"},
		{"page:/index", "/"},
	} {
		st, c := experimentSite(t)
		set, _ := st.Experiments()
		set.Experiments[0].Goal = tc.goal
		for i := 0; i < 10; i++ {
			ip := fmt.Sprintf("198.51.100.%d", i)
			visitAs(st, "/pricing", ip)
			visitAs(st, tc.reached, ip)
		}
		d := c.Today()
		won := d.Goals[experiment.WonKey("price", "a")] + d.Goals[experiment.WonKey("price", "b")]
		if won != 10 {
			t.Errorf("goal %s reached at %s: %d of 10 converted", tc.goal, tc.reached, won)
		}
	}
}

// TestAConversationWithAPersonIsCountedWithoutItsKey — a handoff
// conversation's address carries the only key to it (handoff.go). Counted
// by its path, every conversation a visitor opened went into the day's pages
// in clear, on the disk and on the admin's analytics screen, for anybody who
// could read either to open; and every wrong or ended one into the
// addresses not found. They are counted together, under the prefix.
func TestAConversationWithAPersonIsCountedWithoutItsKey(t *testing.T) {
	st, _, _ := handoffSite(t)
	dir := t.TempDir()
	c, err := analytics.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Analytics = c
	loc := start(t, st, "hello")
	secret := strings.TrimPrefix(loc, "/ask/help/c/")
	h := map[string]string{"User-Agent": browser}

	// The conversation still opens, and is a view.
	w := get(st, loc, h)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "hello") {
		t.Fatalf("the conversation answered %d", w.Code)
	}
	// One nobody has, and addresses that are not one, are the site's 404.
	const guess = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, path := range []string{"/ask/help/c/" + guess, "/ask/help/c/" + guess + "x",
		"/ask/help/c/" + secret + "/more"} {
		if w := get(st, path, h); w.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d", path, w.Code)
		}
	}

	d := c.Today()
	if d.Views != 1 || d.Pages["/ask/help/c/"].Views != 1 {
		t.Errorf("views %d, pages %+v", d.Views, d.Pages)
	}
	for path := range d.Pages {
		if strings.Contains(path, secret) {
			t.Errorf("the day's pages hold a conversation's key: %q", path)
		}
	}
	for path := range d.Missing {
		if strings.Contains(path, secret) || strings.Contains(path, guess) {
			t.Errorf("the day's missing addresses hold a conversation's key: %q", path)
		}
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	_ = filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		if b, _ := os.ReadFile(path); strings.Contains(string(b), secret) {
			t.Errorf("%s holds a conversation's key", filepath.Base(path))
		}
		return nil
	})
}
