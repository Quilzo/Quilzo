// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"fmt"
	"testing"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/experiment"
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
