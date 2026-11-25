// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
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

// And having finished with it, they land on Today, or on Pages when they
// chose to start there.
//
// The redirect hangs off signing in rather than off "/", which was the first
// attempt: making the landing page answer differently depending on a cookie
// means a bookmark, a shared link and every script that fetches the root get a
// redirect instead of the thing they asked for.
func TestSigningInAfterwardsLandsOnTheWork(t *testing.T) {
	srv, token := setup(t)
	for start, want := range map[string]string{"": "/today", "pages": "/"} {
		r := httptest.NewRequest(http.MethodPost, "/signin",
			strings.NewReader("token="+token))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.AddCookie(&http.Cookie{Name: StartDismissedCookie, Value: "1"})
		if start != "" {
			r.AddCookie(&http.Cookie{Name: StartCookie, Value: start})
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)

		if got := w.Header().Get("Location"); got != want {
			t.Errorf("a returning person starting at %q was sent to %q, want %s", start, got, want)
		}
	}
}

// The button that finishes Get started names the screen it goes to.
//
// It said "Got it — go to my pages" and went to Today, which is where a
// sign-in lands for everybody who has not chosen to start on Pages.
func TestFinishingGetStartedSaysWhereItGoes(t *testing.T) {
	srv, token := setup(t)
	for start, want := range map[string]struct{ says, goes string }{
		"":      {"Got it — go to Today", "/today"},
		"pages": {"Got it — go to my pages", "/"},
	} {
		ask := func(method, path string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, path, nil)
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			if start != "" {
				r.AddCookie(&http.Cookie{Name: StartCookie, Value: start})
			}
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, r)
			return w
		}
		button := regexp.MustCompile(`<button type="submit">([^<]*)</button>`).FindStringSubmatch(ask(http.MethodGet, "/start").Body.String())
		goes := ask(http.MethodPost, "/start/done").Header().Get("Location")
		if button == nil || button[1] != want.says || goes != want.goes {
			t.Errorf("starting at %q, the button says %q and goes to %q; want %q, to %s", start, button, goes, want.says, want.goes)
		}
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

// Every step's link opens a screen. "Publish it" pointed at /publish, which
// only takes a form's POST, so the one link on Getting started that matters
// most answered 405 "POST only".
func TestEveryStepOpensAScreen(t *testing.T) {
	srv, token := setup(t)
	p, err := srv.authenticate(func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/start", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}())
	if err != nil {
		t.Fatal(err)
	}
	// 503 is a screen too: this test's server has no content types wired
	// in, and Types says so rather than pretending there are none.
	for _, st := range srv.startState(p) {
		if w := get(t, srv, st.Where, token); w.Code != http.StatusOK &&
			w.Code != http.StatusServiceUnavailable {
			t.Errorf("%q links to %s, which answers %d", st.Title, st.Where, w.Code)
		}
	}
}

// Get started links each step to the screen that does it only for somebody
// who may open that screen, and names the screen for everybody else.
//
// Its last step, deciding who else may do what, linked People for every
// reader, author and publisher the screen is for, and People refused each of
// them: who may do what is an administrator's to change.
func TestGetStartedLinksOnlyWhereItsReaderMayGo(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleReader, auth.RoleAuthor, auth.RolePublisher, auth.RoleAdmin} {
		srv, token := asRole(t, role)
		w := get(t, srv, "/start", token)
		if w.Code != http.StatusOK {
			t.Fatalf("somebody with the %s role opened Get started and was answered %d", role, w.Code)
		}
		steps := regexp.MustCompile(`(?s)<ol class="steps-list">(.*?)</ol>`).FindStringSubmatch(w.Body.String())
		if steps == nil {
			t.Fatal("Get started lists no steps")
		}
		if !strings.Contains(steps[1], "People") {
			t.Errorf("somebody with the %s role is not told where who may do what is decided", role)
		}
		links := regexp.MustCompile(`href="(/[^"]*)"`).FindAllStringSubmatch(steps[1], -1)
		if len(links) < 3 {
			t.Fatalf("only %d steps are linked for somebody with the %s role", len(links), role)
		}
		for _, m := range links {
			if code := get(t, srv, m[1], token).Code; code != http.StatusOK {
				t.Errorf("somebody with the %s role is linked to %s, which answered them %d", role, m[1], code)
			}
		}
		if role == auth.RoleAdmin && !strings.Contains(steps[1], `href="/people"`) {
			t.Error("an administrator is not linked to People")
		}
	}
}

// Get started says what Quilzo is, and its steps reach an agent.
//
// It is the first screen of a first sign-in, and it introduced a content
// store: immutable content and a template language, then four steps that
// wrote, typed and published a page and shared the store, and never named
// an agent. What it opens is the self-hosted AI agent platform, and the
// README's Quickstart declares and runs an agent before anything else.
func TestGetStartedSaysWhatQuilzoIsAndReachesAnAgent(t *testing.T) {
	srv, token := setup(t)
	declared := map[string]agent.Manifest{}
	srv.Agents = &Agents{Load: func() (map[string]agent.Manifest, error) { return declared, nil }}

	body := get(t, srv, "/start", token).Body.String()
	if !strings.Contains(body, "The self-hosted AI agent platform") {
		t.Error("Get started does not say what Quilzo is")
	}
	step := regexp.MustCompile(`(?s)<li class="step[^"]*">\s*<div class="step-head">\s*<h3>Declare an agent</h3>(.*?)</li>`)
	m := step.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no step of Get started declares an agent")
	}
	if !strings.Contains(m[1], `href="/agents"`) || !strings.Contains(m[1], "not yet") {
		t.Errorf("the agent step does not link the studio, or is done with none declared:\n%s", m[1])
	}
	steps := regexp.MustCompile(`<li class="step`).FindAllString(body, -1)
	if counted := regexp.MustCompile(`<h2>(\w+) things, in order</h2>`).FindStringSubmatch(body); counted == nil ||
		counted[1] != map[int]string{4: "Four", 5: "Five", 6: "Six"}[len(steps)] {
		t.Errorf("the checklist says %v and lists %d steps", counted, len(steps))
	}

	// Done is read from the agents this store declares.
	declared["helper"] = agent.Manifest{Name: "helper", Kind: agent.KindRetrieval}
	m = step.FindStringSubmatch(get(t, srv, "/start", token).Body.String())
	if m == nil || !strings.Contains(m[1], "1 agent") {
		t.Errorf("the agent step does not read the declared agent: %v", m)
	}
}
