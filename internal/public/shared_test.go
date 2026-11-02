// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
