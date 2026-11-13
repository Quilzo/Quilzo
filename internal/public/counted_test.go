// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
