package admin

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rsh1k/scrivet/internal/auth"
)

// Each role gets what it needs to do its job, and nothing above it.
//
// The new screens were gated one at a time, by hand, and nothing checked the
// result. That is the same shape as every gap this project has had: a decision
// made correctly in nineteen places and forgotten in the twentieth, invisible
// because the twentieth still renders.
//
// So the expectation is written out per role, and the test drives a real
// server as that role. A screen added later fails here until somebody decides
// which roles it is for — which is the point.
func TestEachRoleReachesItsOwnWorkAndNoMore(t *testing.T) {
	// What each role should be able to open. Cumulative: the ladder means a
	// publisher gets everything an author gets, so each row lists only what
	// that rung adds.
	adds := map[auth.Role][]string{
		auth.RoleReader: {
			"/", "/records", "/types", "/media", "/languages",
			"/review", "/publishing", "/history", "/transfer",
			"/provenance", "/playground", "/docs", "/profile",
		},
		auth.RoleAuthor:    {"/assist", "/settings"},
		auth.RolePublisher: {},
		auth.RoleAdmin: {
			"/security", "/security/scan", "/security/policy",
			"/security/inventory", "/security/integrity", "/security/agents",
			"/logs", "/people", "/access", "/integrations",
		},
	}

	// Everything, so "and no more" can be checked rather than assumed.
	var everything []string
	for _, paths := range adds {
		everything = append(everything, paths...)
	}

	ladder := []auth.Role{
		auth.RoleReader, auth.RoleAuthor, auth.RolePublisher, auth.RoleAdmin,
	}
	for i, role := range ladder {
		want := map[string]bool{}
		for _, r := range ladder[:i+1] {
			for _, path := range adds[r] {
				want[path] = true
			}
		}

		t.Run(string(role), func(t *testing.T) {
			srv, token := asRole(t, role)
			for _, path := range everything {
				w := get(t, srv, path, token)
				allowed := w.Code == http.StatusOK ||
					w.Code == http.StatusServiceUnavailable
				switch {
				case want[path] && !allowed:
					t.Errorf("a %s cannot open %s (%d), and needs to",
						role, path, w.Code)
				case !want[path] && allowed:
					t.Errorf("a %s can open %s and should not", role, path)
				}
			}
		})
	}
}

// The navigation shows a person only what they can open.
//
// The other half of the same rule. A menu entry that answers "you cannot do
// that here" is a door drawn on a wall, and it is also a list of the
// administrative screens worth going after.
func TestTheNavigationOffersNothingThatWouldBeRefused(t *testing.T) {
	for _, role := range []auth.Role{
		auth.RoleReader, auth.RoleAuthor, auth.RolePublisher, auth.RoleAdmin,
	} {
		t.Run(string(role), func(t *testing.T) {
			srv, token := asRole(t, role)
			body := get(t, srv, "/profile", token).Body.String()

			for _, d := range destinations {
				offered := strings.Contains(body, `href="`+d.Path+`"`)
				w := get(t, srv, d.Path, token)
				reachable := w.Code == http.StatusOK ||
					w.Code == http.StatusServiceUnavailable
				if offered && !reachable {
					t.Errorf("the navigation offers %s to a %s and it answers %d",
						d.Path, role, w.Code)
				}
				if !offered && reachable {
					t.Errorf("a %s can open %s and is never shown a link to it",
						role, d.Path)
				}
			}
		})
	}
}

// A reader cannot write, by any route.
//
// Checked against the write endpoints rather than the screens, because the
// screens hiding a button is presentation and the handler refusing is the
// control. A product that only hides the button has no control at all.
func TestAReaderIsRefusedByEveryWriteEndpoint(t *testing.T) {
	srv, token := asRole(t, auth.RoleReader)

	writes := []string{
		"/save", "/publish", "/rollback",
		"/types/save", "/types/delete", "/types/bind", "/types/field/remove",
		"/records/save", "/records/delete",
		"/media/upload", "/media/delete",
		"/publishing/promote", "/publishing/environment",
		"/publishing/schedule", "/publishing/lock/release",
		"/languages/add", "/languages/translated",
		"/integrations/webhook", "/integrations/extension", "/integrations/siem",
		"/transfer/import", "/transfer/starter",
		"/assist/accept",
		"/people/grant", "/people/revoke", "/sessions/revoke",
		"/settings/save", "/security/verify",
	}
	sort.Strings(writes)

	for _, path := range writes {
		w := post(t, srv, path, token)
		if w.Code == http.StatusOK || w.Code == http.StatusSeeOther {
			t.Errorf("a reader posted to %s and was not refused (%d)",
				path, w.Code)
		}
	}
}

// asRole builds a server and a credential for one rung of the ladder.
func asRole(t *testing.T, role auth.Role) (*Server, string) {
	t.Helper()
	srv, _ := fullyWired(t)

	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "someone", Role: role, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	secret, _, err := ts.Issue("test", "someone", role, "/", time.Hour, role)
	if err != nil {
		t.Fatal(err)
	}
	srv.Policy, srv.Tokens = pol, ts
	return srv, secret
}

// post makes a state-changing request the way a browser would.
//
// Sec-Fetch-Site is set because the CSRF middleware refuses anything without
// it, and a test that got 403 from the middleware would pass while telling us
// nothing about the permission underneath.
func post(t *testing.T, srv *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path,
		strings.NewReader("name=x&type=x&page=x&key=x&id=x&to=dark"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}
