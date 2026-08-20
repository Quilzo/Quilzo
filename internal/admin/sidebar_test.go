package admin

import (
	"net/http"
	"net/http/httptest"
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
