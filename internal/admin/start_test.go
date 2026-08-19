package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Signing in for the first time lands on the getting started screen.
func TestSigningInTheFirstTimeLandsOnGettingStarted(t *testing.T) {
	srv, token := setup(t)

	r := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token="+token))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if got := w.Header().Get("Location"); got != "/start" {
		t.Errorf("signing in sent them to %q, want /start", got)
	}
}

// And having finished with it, they land on their work instead.
//
// The redirect hangs off signing in rather than off "/", which was the first
// attempt: making the landing page answer differently depending on a cookie
// means a bookmark, a shared link and every script that fetches the root get a
// redirect instead of the thing they asked for.
func TestSigningInAfterwardsLandsOnTheWork(t *testing.T) {
	srv, token := setup(t)

	r := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token="+token))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(&http.Cookie{Name: StartDismissedCookie, Value: "1"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if got := w.Header().Get("Location"); got != "/" {
		t.Errorf("a returning person was sent to %q, want /", got)
	}
}

// The root stays the root, whatever the onboarding cookie says.
func TestTheLandingPageIsNotConditional(t *testing.T) {
	srv, token := setup(t)
	if w := get(t, srv, "/", token); w.Code != http.StatusOK {
		t.Errorf("GET / gave %d with no onboarding cookie; the root must not "+
			"depend on it", w.Code)
	}
}

// The checklist reports what is in the store, not a fixed script.
//
// The whole reason this screen reads the store is that a tour cannot say
// anything true about an installation it has not looked at. If the steps stop
// reflecting state, it has become the carousel it was written to avoid.
func TestTheChecklistReadsTheStore(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/start", token).Body.String()

	// setup() puts two pages in the draft and publishes nothing.
	if !strings.Contains(body, "2 pages") {
		t.Error("the first step does not report the two pages in the store")
	}
	// Nothing is live, so publishing is not done.
	if strings.Contains(body, `<span class="tag tag-ok">live</span>`) {
		t.Error("the publish step reports done on a store with no live ref")
	}
	// And the gates are named before somebody meets one.
	for _, gate := range []string{"Accessibility", "Provenance"} {
		if !strings.Contains(body, gate) {
			t.Errorf("the screen never mentions the %s gate, so the first "+
				"refusal will be a surprise", gate)
		}
	}
}

// Dismissing it is a state change on this origin, so it is POST-only and
// authenticated.
func TestDismissingGettingStartedIsGuarded(t *testing.T) {
	srv, _ := setup(t)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/start/done", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /start/done gave %d, want 405", w.Code)
	}

	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/start/done", nil))
	for _, c := range w.Result().Cookies() {
		if c.Name == StartDismissedCookie {
			t.Error("an unauthenticated request dismissed the screen")
		}
	}
}
