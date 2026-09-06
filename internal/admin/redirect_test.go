package admin

import (
	"net/url"
	"strings"
	"testing"
)

// A destination taken from a request must not leave this origin.
//
// CodeQL reports the prefix test in safeLocalPath as an insufficient redirect
// check, which is a fair thing to say about that line alone: a "/" prefix does
// not make a URL local, because "//evil.test" has one. The function does not
// rely on it alone — there are four layers — but "there are four layers" is an
// assertion, and this is the evidence.
//
// Every one of these has been a real open-redirect somewhere.
func TestARedirectCannotLeaveThisOrigin(t *testing.T) {
	hostile := []string{
		"//evil.test",
		"//evil.test/path",
		"///evil.test",
		"\\\\evil.test",
		"/\\evil.test",
		"https://evil.test",
		"http://evil.test",
		"javascript:alert(1)",
		"//evil.test/../../x",
		"/..//evil.test",
		"\\/evil.test",
		"//\\evil.test",
	}
	for _, path := range hostile {
		got := safeLocalPath(path, "")

		// The property is not that the result is "/" — it is that the result
		// stays on this origin. "//evil.test" cleans to "/evil.test", which a
		// browser resolves against this host and is a perfectly ordinary
		// local path. Demanding "/" would be testing a stricter rule than
		// the one that matters, and would fail on correct behaviour.
		if !strings.HasPrefix(got, "/") {
			t.Errorf("safeLocalPath(%q) = %q, which is not a rooted path",
				path, got)
			continue
		}
		if strings.HasPrefix(got, "//") {
			t.Errorf("safeLocalPath(%q) = %q, which a browser reads as an "+
				"authority — that is the open redirect", path, got)
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Errorf("safeLocalPath(%q) = %q, which does not parse: %v",
				path, got, err)
			continue
		}
		if u.Scheme != "" || u.Host != "" || u.Opaque != "" {
			t.Errorf("safeLocalPath(%q) = %q, which names scheme %q host %q",
				path, got, u.Scheme, u.Host)
		}
	}
}

// And an ordinary destination still works, or somebody removes the guard to
// make the interface usable again.
func TestAnOrdinaryDestinationSurvives(t *testing.T) {
	for path, want := range map[string]string{
		"/design":     "/design",
		"/page/index": "/page/index",
		"/media":      "/media",
		"/design/../": "/",
		"":            "/",
	} {
		if got := safeLocalPath(path, ""); got != want {
			t.Errorf("safeLocalPath(%q) = %q, want %q", path, got, want)
		}
	}
	if got := safeLocalPath("/search", "q=indigo"); got != "/search?q=indigo" {
		t.Errorf("a query was lost: %q", got)
	}
}
