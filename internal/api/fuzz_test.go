package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Everything reachable before authentication decides anything: the paths, the
// query string, and the conditional-request headers.
func FuzzRequest(f *testing.F) {
	f.Add("/api/v1/pages", "limit=10", `"abc"`)
	f.Add("/api/v1/pages/x", "after=y&limit=1", "*")
	f.Add("/api/v1/pages/../../etc/passwd", "", "")
	f.Add("/api/v1/pages/%2e%2e%2f", "limit=-1", "W/\"x\"")
	f.Add("/api/v1/pages/a\x00b", "limit=99999999999999999999", "")

	// The same server the unit tests use, built once — the fuzzer runs this
	// millions of times and a store per execution measures disk speed.
	srv, token, _ := setupFuzz(f)
	h := srv.Handler()
	f.Fuzz(func(t *testing.T, path, query, match string) {
		// httptest.NewRequest panics on a URL net/url will not parse, which is
		// the harness refusing the input rather than the server doing so.
		raw := "http://h" + path + "?" + query
		if !strings.HasPrefix(path, "/") {
			return
		}
		if _, err := url.Parse(raw); err != nil {
			return
		}
		// httptest.NewRequest builds a request line and re-parses it, so any
		// control character or space panics inside the harness before the
		// server sees anything. That is the harness refusing the input, not a
		// finding, so those bytes are filtered here rather than counted.
		for _, c := range []byte(path + query) {
			if c < 0x20 || c == 0x7f || c == ' ' {
				return
			}
		}
		req := httptest.NewRequest("GET", raw, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if match != "" {
			req.Header.Set("If-None-Match", match)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code >= 500 {
			t.Errorf("%s?%s gave %d", path, query, w.Code)
		}
		// No response may ever carry a filesystem path or a token.
		body := w.Body.String()
		for _, leak := range []string{"/home/", "/etc/passwd", "qz_", "goroutine "} {
			if strings.Contains(body, leak) {
				t.Errorf("%s?%s leaked %q in: %s", path, query, leak, body)
			}
		}
		if w.Code == http.StatusOK && w.Header().Get("Content-Type") == "" {
			t.Errorf("%s?%s answered 200 with no content type", path, query)
		}
	})
}
