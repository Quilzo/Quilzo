// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/analytics"
)

// A shared draft is served marked not to be indexed, stored or referred
// onward, with a note saying what it is; a link that is not live is the
// site's own 404.
func TestASharedDraftIsMarkedAndNotKept(t *testing.T) {
	st := published(t, map[string]any{"index": map[string]any{"title": "Home"}})
	const id = "0123456789abcdef0123456789abcdef"
	st.Shared = func(got string) (string, bool) {
		if got != id {
			return "", false
		}
		return `<!doctype html><html><body class="x"><h1>The draft offer</h1></body></html>`, true
	}
	h := st.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/shared/"+id, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%d", w.Code)
	}
	for k, want := range map[string]string{"X-Robots-Tag": "noindex", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"} {
		if !strings.Contains(w.Header().Get(k), want) {
			t.Errorf("%s: %q", k, w.Header().Get(k))
		}
	}
	body := w.Body.String()
	if !strings.Contains(body, `<body class="x">`+sharedNote) || !strings.Contains(body, "The draft offer") {
		t.Fatalf("%s", body)
	}
	for _, path := range []string{"/shared/ffffffffffffffffffffffffffffffff", "/shared/", "/shared/../index"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "draft offer") {
			t.Errorf("%s: served", path)
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/shared/"+id, nil))
	if w.Code == http.StatusOK {
		t.Error("a POST was answered")
	}
}

// A shared draft is counted without the address that opens it.
//
// The secret in a link's address is the only key to the draft, and the
// store keeps a digest of it so that nobody who reads the store, or a
// backup, can open the draft. The site's analytics counted each view by
// its path, so every link anybody opened went into the day's totals in
// clear, on the disk and on the admin's analytics screen.
func TestASharedDraftIsCountedWithoutItsAddress(t *testing.T) {
	st := published(t, map[string]any{"index": map[string]any{"title": "Home"}})
	const id = "0123456789abcdef0123456789abcdef"
	st.Shared = func(got string) (string, bool) {
		if got != id {
			return "", false
		}
		return `<!doctype html><html><body><h1>The draft offer</h1></body></html>`, true
	}
	dir := t.TempDir()
	c, err := analytics.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Analytics = c
	h := map[string]string{"User-Agent": browser}
	if w := get(st, "/shared/"+id, h); w.Code != http.StatusOK {
		t.Fatalf("the link answered %d", w.Code)
	}
	// And one that has ended, which is the site's own 404.
	const ended = "fedcba9876543210fedcba9876543210"
	get(st, "/shared/"+ended, h)

	d := c.Today()
	if d.Views != 1 {
		t.Fatalf("the shared draft was counted %d time(s)", d.Views)
	}
	for path := range d.Pages {
		if strings.Contains(path, id) {
			t.Errorf("the day's pages hold a link's secret: %q", path)
		}
	}
	for path := range d.Missing {
		if strings.Contains(path, ended) {
			t.Errorf("the day's missing addresses hold a link's secret: %q", path)
		}
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	_ = filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		if b, _ := os.ReadFile(path); strings.Contains(string(b), id) {
			t.Errorf("%s holds a link's secret", filepath.Base(path))
		}
		return nil
	})
}
