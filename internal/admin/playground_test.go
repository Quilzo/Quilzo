package admin

import (
	"net/http"
	"time"

	"github.com/lithoform/lithoform/internal/auth"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The playground is the first script this program has ever served, so the
// property that matters is that it did not cost the admin its policy.
func TestThePlaygroundUsesANonceRatherThanWideningThePolicy(t *testing.T) {
	body, headers := fetchPlayground(t)
	csp := headers.Get("Content-Security-Policy")

	if !strings.Contains(csp, "script-src 'nonce-") {
		t.Fatalf("the playground does not use a nonce: %s", csp)
	}
	for _, forbidden := range []string{
		"'unsafe-inline'", "'unsafe-eval'", "https:", "*", "'self' 'unsafe",
	} {
		if strings.Contains(csp, "script-src") &&
			strings.Contains(scriptSrc(csp), forbidden) {
			t.Errorf("script-src permits %q: %s", forbidden, scriptSrc(csp))
		}
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") ||
		!strings.Contains(csp, "base-uri 'none'") {
		t.Errorf("the page lost a directive it had before: %s", csp)
	}

	// The nonce in the header must be the one on the tag, or nothing runs.
	n := regexp.MustCompile(`'nonce-([A-Za-z0-9+/]+)'`).FindStringSubmatch(csp)
	if len(n) != 2 {
		t.Fatalf("no nonce in %s", csp)
	}
	if !strings.Contains(body, `<script nonce="`+n[1]+`">`) {
		t.Error("the script tag does not carry the nonce from the header")
	}
}

// A nonce reused across responses is one an attacker reads from one page and
// uses in an injection into another, which is the same as not having one.
func TestTheNonceIsFreshPerResponse(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		_, h := fetchPlayground(t)
		n := regexp.MustCompile(`'nonce-([A-Za-z0-9+/]+)'`).
			FindStringSubmatch(h.Get("Content-Security-Policy"))
		if len(n) != 2 {
			t.Fatal("no nonce")
		}
		if seen[n[1]] {
			t.Fatal("a nonce was reused across responses")
		}
		seen[n[1]] = true
		if len(n[1]) < 20 {
			t.Errorf("the nonce is only %d characters", len(n[1]))
		}
	}
}

// Everything else in the admin keeps default-src 'none' with no script at all.
// A page that can run script is a decision made once, for one page.
func TestTheRestOfTheAdminStillForbidsScriptEntirely(t *testing.T) {
	s, tok := setup(t)
	r := httptest.NewRequest("GET", "http://h/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	csp := w.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "script-src") {
		t.Errorf("the main admin page now has a script-src: %s", csp)
	}
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("the main admin page lost default-src 'none': %s", csp)
	}
}

// It is behind the same authentication as everything else.
func TestThePlaygroundNeedsAuthentication(t *testing.T) {
	s, _ := setup(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://h/playground", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", w.Code)
	}
}

// The console must not put a working credential into somebody's clipboard,
// from where it reaches a terminal history and a support ticket.
func TestTheCurlHelperDoesNotEmitTheSessionCredential(t *testing.T) {
	body, _ := fetchPlayground(t)
	if strings.Contains(body, "document.cookie") {
		t.Error("the script reads the session cookie")
	}
	if !strings.Contains(body, "$SCRIVET_TOKEN") {
		t.Error("the curl helper does not use a placeholder for the token")
	}
}

// No eval, no innerHTML: the response is content somebody wrote, and this page
// lives in the admin's origin.
func TestTheScriptUsesNoDangerousSinks(t *testing.T) {
	body, _ := fetchPlayground(t)
	script := body[strings.Index(body, "<script"):]
	for _, sink := range []string{"innerHTML", "outerHTML", "eval(",
		"document.write", "new Function", "setTimeout(\""} {
		if strings.Contains(script, sink) {
			t.Errorf("the playground script uses %s", sink)
		}
	}
}

// It loads nothing from anywhere else, which is what lets connect-src stay
// 'self' and script-src stay nonce-only.
func TestThePlaygroundLoadsNothingExternal(t *testing.T) {
	body, _ := fetchPlayground(t)
	for _, ext := range []string{"http://", "https://", "//cdn", "integrity="} {
		if strings.Contains(body, ext) {
			t.Errorf("the page references something external: %q", ext)
		}
	}
}

// The route list is hand-written, which is a real limitation: a route added to
// the API and not added here is invisible. This is the test that keeps the two
// from diverging silently.
func TestEveryPlaygroundRouteIsUsable(t *testing.T) {
	s, _ := setup(t)
	for _, rt := range s.playgroundRoutes() {
		if !strings.HasPrefix(rt.Path, "/api/v1/") {
			t.Errorf("%s is not an API path", rt.Path)
		}
		if rt.Method != "GET" && rt.Method != "PUT" {
			t.Errorf("%s %s uses a method the API does not serve",
				rt.Method, rt.Path)
		}
		if len(rt.Summary) < 8 {
			t.Errorf("%s has no summary", rt.Path)
		}
		if rt.Method == "PUT" {
			if rt.Body == "" {
				t.Errorf("%s is a write with no example body", rt.Path)
			}
			if !strings.Contains(rt.Note, "If-Match") {
				t.Errorf("%s does not warn about If-Match, so the first "+
					"attempt will be a confusing 428", rt.Path)
			}
		}
	}
}

func fetchPlayground(t *testing.T) (string, http.Header) {
	t.Helper()
	s, tok := setup(t)
	r := httptest.NewRequest("GET", "http://h/playground", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("playground gave %d: %s", w.Code, w.Body.String())
	}
	return w.Body.String(), w.Header()
}

func scriptSrc(csp string) string {
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "script-src") {
			return part
		}
	}
	return ""
}

// The body field must be hidden for a GET.
//
// It was not, and no unit test could have caught it: `hidden` works through a
// user-agent rule that any explicit `display` beats, and .pg-row is
// display:flex. The bug was in the stylesheet, the symptom was in the layout,
// and it took a screenshot to see. This asserts the rule that fixes it, which
// is the closest a test in this package can get to asserting the rendering.
func TestTheHiddenRuleSurvivesTheFlexLayout(t *testing.T) {
	body, _ := fetchPlayground(t)
	if !strings.Contains(body, ".pg-row[hidden]") {
		t.Error("nothing overrides display:flex for a hidden row, so the " +
			"request body field will show for GET requests")
	}
	// And the page must still offer a way back, or it is a dead end.
	if !strings.Contains(body, `href="/"`) {
		t.Error("the playground has no link back to the admin")
	}
}

// -- people and credentials ---------------------------------------------------

// The bug this page exists to prevent an administrator from believing they
// have avoided: removing a grant does not invalidate a token already in
// somebody's hand, because the token carries its own role.
func TestRemovingAGrantDoesNotRevokeTheirCredential(t *testing.T) {
	s, _ := setup(t)
	tok, _, err := s.Tokens.Issue("theirs", "sam", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	s.Policy.Grant(auth.Binding{Principal: "sam", Role: auth.RoleAuthor,
		Resource: "/"})
	s.Policy.Revoke("sam", auth.RoleAuthor, "/")

	if _, err := s.Tokens.Authenticate(tok, time.Now()); err != nil {
		t.Fatal("the token stopped authenticating, which is not what a policy " +
			"change does")
	}
	// Which is exactly why the page shows both, and says so.
	body, _ := fetchPeople(t, s)
	if !strings.Contains(body, "Credentials they hold") {
		t.Error("the page does not show credentials alongside grants")
	}
	if !strings.Contains(body, "does not invalidate a token") {
		t.Error("the page does not warn that removing a grant is not enough")
	}
}

// Somebody holding a credential but named in no binding must still appear.
// A person invisible on this screen is a person nobody removes.
func TestSomebodyWithNoGrantsStillAppears(t *testing.T) {
	s, _ := setup(t)
	if _, _, err := s.Tokens.Issue("orphan", "ghost", auth.RoleReader, "/",
		time.Hour, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	body, _ := fetchPeople(t, s)
	if !strings.Contains(body, "ghost") {
		t.Error("a principal with a credential and no binding is not listed")
	}
}

// The write handlers are POST-only and authorised, like everything else that
// changes state here.
func TestThePeopleWritesAreGuarded(t *testing.T) {
	s, tok := setup(t)
	for _, path := range []string{"/people/grant", "/people/revoke",
		"/sessions/revoke"} {
		// GET is refused.
		r := httptest.NewRequest("GET", "http://h"+path, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s gave %d, want 405", path, w.Code)
		}
		// Unauthenticated POST is refused.
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "http://h"+path, nil))
		if w.Code == http.StatusSeeOther {
			t.Errorf("POST %s acted without authentication", path)
		}
	}
}

// fetchPeople renders the page for an admin.
func fetchPeople(t *testing.T, s *Server) (string, int) {
	t.Helper()
	tok, _, err := s.Tokens.Issue("admin-view", "dana", auth.RoleAdmin, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	s.Policy.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin,
		Resource: "/"})
	r := httptest.NewRequest("GET", "http://h/people", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/people gave %d: %s", w.Code, w.Body.String())
	}
	return w.Body.String(), w.Code
}

// -- the check that refused a real sign-in -----------------------------------

// Sec-Fetch-Site is set by the browser and a page cannot forge it, so when it
// says same-origin that is a stronger statement than Origin can make. Checking
// Origin as well could only ever produce disagreements — and it did: signing
// in from a privacy-hardened browser failed with "this request came from
// another origin" while the identical POST from curl succeeded.
func TestSecFetchSiteDecidesWhenItIsPresent(t *testing.T) {
	s, tok := setup(t)
	for _, tc := range []struct {
		name   string
		fetch  string
		origin string
		want   bool // allowed
	}{
		{"browser says same-origin, odd Origin", "same-origin", "null", true},
		{"browser says same-origin, no Origin", "same-origin", "", true},
		{"direct navigation", "none", "", true},
		{"browser says cross-site", "cross-site", "http://h", false},
		{"no fetch metadata, matching Origin", "", "http://h", true},
		{"no fetch metadata, foreign Origin", "", "https://evil.example", false},
	} {
		r := httptest.NewRequest("POST", "http://h/signin", strings.NewReader(
			"token="+tok))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if tc.fetch != "" {
			r.Header.Set("Sec-Fetch-Site", tc.fetch)
		}
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)

		blocked := w.Code == http.StatusForbidden
		if blocked == tc.want {
			t.Errorf("%s: got %d, allowed=%v want allowed=%v",
				tc.name, w.Code, !blocked, tc.want)
		}
	}
}

// A refusal has to say what it saw, because "another origin" gives somebody
// staring at a blank page nothing to act on.
func TestTheOriginRefusalNamesBothSides(t *testing.T) {
	s, _ := setup(t)
	r := httptest.NewRequest("POST", "http://h/signin", nil)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	body := w.Body.String()
	if !strings.Contains(body, "evil.example") || !strings.Contains(body, "\"h\"") {
		t.Errorf("the refusal does not name what it compared: %s", body)
	}
}
