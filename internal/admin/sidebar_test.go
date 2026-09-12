// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The control has to survive a navigation, which is the whole reason it is a
// cookie and a round trip rather than a checkbox and a CSS sibling rule. The
// CSS-only version passes a test that renders one page and fails the moment
// somebody clicks a link.
func TestHidingTheNavigationSurvivesTheNextPage(t *testing.T) {
	s, token := setup(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/sidebar",
		strings.NewReader("to=hidden"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /sidebar returned %d: %s", rec.Code, rec.Body.String())
	}

	var set *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == SidebarCookie {
			set = c
		}
	}
	if set == nil {
		t.Fatal("no preference cookie was set, so the choice lasts one page")
	}
	if !set.HttpOnly || set.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie is HttpOnly=%t SameSite=%v; a preference cookie on "+
			"this origin should be both", set.HttpOnly, set.SameSite)
	}

	// Now a different page, carrying the cookie.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.AddCookie(set)
	s.Handler().ServeHTTP(rec2, req2)
	body := rec2.Body.String()
	if !strings.Contains(body, `class="nav-hidden"`) {
		t.Error("a later page did not carry the hidden state, so the sidebar " +
			"came back on the first click")
	}
	if !strings.Contains(body, `value="shown"`) {
		t.Error("the control does not offer to show the navigation again")
	}
}

// Hiding the navigation must not hide the way to get it back. The control is
// in the top bar for exactly this reason, and a change that moved it into the
// sidebar would strand somebody with a cookie to clear.
func TestTheControlIsStillThereWhenTheNavigationIsHidden(t *testing.T) {
	s, token := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.AddCookie(&http.Cookie{Name: SidebarCookie, Value: "hidden"})
	s.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	bar := body
	if i := strings.Index(body, `<div class="sidenav`); i >= 0 {
		bar = body[:i]
	}
	if !strings.Contains(bar, `action="/sidebar"`) {
		t.Fatal("the control is not above the sidebar in the document, so " +
			"hiding the sidebar could hide the only way back")
	}
}

// A named target rather than a flip. A control that toggles whatever it finds
// is not idempotent: going back and re-submitting lands in the opposite state
// from the one the form asked for.
func TestTheControlNamesTheStateItWants(t *testing.T) {
	s, token := setup(t)
	for _, c := range []struct {
		cookie, want string
	}{
		{"", "hidden"},
		{"hidden", "shown"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if c.cookie != "" {
			req.AddCookie(&http.Cookie{Name: SidebarCookie, Value: c.cookie})
		}
		s.Handler().ServeHTTP(rec, req)
		if !strings.Contains(rec.Body.String(),
			`name="to" value="`+c.want+`"`) {
			t.Errorf("with cookie %q the form does not ask for %q",
				c.cookie, c.want)
		}
	}
}

func TestAnUnknownSidebarValueIsRefused(t *testing.T) {
	s, token := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/sidebar",
		strings.NewReader("to=collapse"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown value returned %d, want 400", rec.Code)
	}
}

// It sets a cookie on this origin, so it is authenticated like everything
// else. A preference toggle is exactly the sort of endpoint nobody thinks to
// check.
func TestTheSidebarPreferenceNeedsAuthentication(t *testing.T) {
	s, _ := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/sidebar", strings.NewReader("to=hidden"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("an unauthenticated request set a preference cookie")
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == SidebarCookie && c.Value == "hidden" {
			t.Fatal("an unauthenticated request set the sidebar cookie")
		}
	}
}

func TestGetOnTheSidebarPreferenceIsRefused(t *testing.T) {
	s, token := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/sidebar", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /sidebar returned %d, want 405", rec.Code)
	}
}

// A toggle returns you to the screen you pressed it on.
//
// Both preference toggles redirected to "/" from every screen, which meant
// pressing "Hide menu" anywhere hid the menu and moved you to Pages. The
// preference was recorded correctly; the screen you were reading was not the
// one you got back.
//
// The cause was an interaction between two things that are each right on their
// own. backTo read Referer, and every admin response sets
// `Referrer-Policy: no-referrer` — so there was no Referer to read and backTo
// took its fallback. Nothing was broken in either half, which is why no test
// caught it: the redirect tests all set a Referer by hand, and a browser never
// sends one here.
//
// So this test does the thing a browser does, which is send no Referer at all,
// and both toggles are checked because they share the function.
func TestAPreferenceToggleComesBackToTheScreenItWasPressedOn(t *testing.T) {
	s, token := setup(t)

	for _, c := range []struct{ action, form, want string }{
		{"/sidebar", "to=hidden&back=%2Flogs", "/logs"},
		{"/sidebar", "to=shown&back=%2Fmedia", "/media"},
		{"/theme", "to=dark&back=%2Fsettings", "/settings"},
		// A query is part of where somebody was. Landing on an unfiltered
		// list after hiding the menu is the same complaint in a smaller form.
		{"/sidebar", "to=hidden&back=%2Flogs%3Fseq%3D12", "/logs?seq=12"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", c.action, strings.NewReader(c.form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		// No Referer, which is what a browser sends here.
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("POST %s returned %d: %s", c.action, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Location"); got != c.want {
			t.Errorf("POST %s with %s redirected to %q, so pressing it moved "+
				"somebody off the screen they were reading; want %q",
				c.action, c.form, got, c.want)
		}
	}
}

// The field is not a way to be sent somewhere else.
//
// It is posted by a form and is therefore as forgeable as the header it
// replaced, so it goes through the same check. The protocol-relative case is
// the one that mattered before — browsers read //evil.example.com as an
// origin — and it is checked here for the new source as well as the old.
func TestTheReturnFieldCannotLeaveThisServer(t *testing.T) {
	s, token := setup(t)

	for _, back := range []string{
		"https://evil.test/x",
		"//evil.test/x",
		"/%2F%2Fevil.test/x",
		`\\evil.test\x`,
		"http://evil.test",
		"javascript:alert(1)",
		"/../../etc/passwd",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/sidebar",
			strings.NewReader("to=hidden&back="+url.QueryEscape(back)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		s.Handler().ServeHTTP(rec, req)
		loc := rec.Header().Get("Location")
		// The property is the shape, not the hostname. "/evil.test/x" names a
		// path on this server and 404s; what must never appear is something
		// the browser can read as another origin. Asserting on the shape is
		// also what stops this passing for the wrong reason when a future
		// domain happens not to be called evil.test.
		u, err := url.Parse(loc)
		if err != nil || !strings.HasPrefix(loc, "/") ||
			strings.HasPrefix(loc, "//") || u.Scheme != "" || u.Host != "" ||
			u.Opaque != "" {
			t.Errorf("back=%q redirected to %q, which is not a single rooted "+
				"path on this server — an open redirect through a preference "+
				"toggle", back, loc)
		}
	}
}

// Every screen tells the toggles where it is.
//
// The field is set in render, so no handler has to remember it — and this is
// what says so. A screen that renders the shell and no Here sends back="",
// which falls through to the Referer branch and from there to "/", which is
// the bug this fixed, reappearing on one screen instead of all of them.
func TestEveryScreenTellsTheToggleWhereItIs(t *testing.T) {
	s, token := setup(t)

	for _, path := range []string{"/", "/logs", "/media", "/settings", "/people"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			continue
		}
		want := `name="back" value="` + path + `"`
		if n := strings.Count(rec.Body.String(), want); n != 2 {
			t.Errorf("%s carries %d of %s; both toggles need it, so a %d "+
				"means one of them still goes to the wrong screen",
				path, n, want, n)
		}
	}
}
