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
	"github.com/quilzo/quilzo/internal/chatact"
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
