package admin

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The preference toggle must not become an open redirect.
//
// It was one. The host check passed — the host really was this server — and
// the returned path began "//", which a browser reads as protocol-relative and
// follows to another origin. Found by CodeQL, confirmed live, fixed here.
func TestBackToRefusesEverythingThatIsNotALocalPath(t *testing.T) {
	// The property, not a table of strings: whatever comes back must be a
	// path on this server. "//evil.example.com/x" collapsing to
	// "/evil.example.com/x" is a correct outcome — that is a local path that
	// will 404, not a redirect to another origin — and an earlier version of
	// this test asserted the literal "/" and failed the fix for being right.
	for _, in := range []string{
		"/media", "/pages", "//evil.example.com/x", "///evil.example.com",
		`\\evil.example.com`, `/\evil.example.com`, "/a/../../etc", "",
		"/", "/https://evil.example.com", "//", "/..//..", "\\/evil.com",
		"/\t//evil.com", "//evil.com\\@good.com",
	} {
		got := safeLocalPath(in, "")
		if !strings.HasPrefix(got, "/") {
			t.Errorf("safeLocalPath(%q) = %q, which is not rooted", in, got)
		}
		if strings.HasPrefix(got, "//") {
			t.Errorf("safeLocalPath(%q) = %q, which a browser reads as "+
				"protocol-relative and follows off this origin", in, got)
		}
		if strings.ContainsAny(got, "\\") {
			t.Errorf("safeLocalPath(%q) = %q, which still carries a backslash "+
				"— some browsers normalise it to a slash before deciding "+
				"what the authority is", in, got)
		}
		// And it must parse as a bare path, with nothing that reads as an
		// origin left in it.
		u, err := url.Parse(got)
		if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
			t.Errorf("safeLocalPath(%q) = %q, which parses with scheme=%q "+
				"host=%q", in, got, u.Scheme, u.Host)
		}
	}

	// The ordinary cases still work, or the toggle stops returning people to
	// where they were.
	for in, want := range map[string]string{"/media": "/media", "": "/", "/": "/"} {
		if got := safeLocalPath(in, ""); got != want {
			t.Errorf("safeLocalPath(%q) = %q, want %q", in, got, want)
		}
	}
	if got := safeLocalPath("/pages", "sort=name"); got != "/pages?sort=name" {
		t.Errorf("the query was lost: %q", got)
	}
}

// And the same through the handler, because the unit above is only the half
// that was wrong — the host comparison is the other half and still has to hold.
func TestTheThemeToggleRedirectsOnlyToThisServer(t *testing.T) {
	srv, token := setup(t)
	for name, referer := range map[string]string{
		"another origin":    "https://evil.example.com/x",
		"protocol relative": "http://example.test//evil.example.com/x",
		"no referer":        "",
	} {
		req := httptest.NewRequest("POST", "/theme",
			strings.NewReader("to=dark"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)

		loc := w.Header().Get("Location")
		if strings.HasPrefix(loc, "//") || strings.Contains(loc, "evil.example.com") {
			t.Errorf("%s: redirected to %q, which leaves this origin", name, loc)
		}
	}
}
