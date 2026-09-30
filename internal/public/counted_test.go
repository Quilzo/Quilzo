// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"testing"

	"github.com/quilzo/quilzo/internal/analytics"
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
