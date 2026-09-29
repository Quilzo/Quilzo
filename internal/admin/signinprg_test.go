// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/throttle"
)

// signInPost submits the form from one address, as a browser on this site.
func signInPost(srv *Server, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token="+url.QueryEscape(token)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.RemoteAddr = "203.0.113.9:5555"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// TestAThrottledSignInLeavesNothingToResubmit.
//
// The reported bug. Somebody pasted the right token while throttled and got
// the "too many attempts" page — rendered as the answer to their POST. Once
// the wait was over they pressed reload, the browser sent the same POST
// again with the token still in it, and they were signed in without typing
// anything. The server was right both times; the page was the problem.
//
// So no refusal answers the POST with a page. Each one is a redirect, and a
// redirect followed by a GET is what a reload repeats.
func TestAThrottledSignInLeavesNothingToResubmit(t *testing.T) {
	srv, token := setup(t)
	srv.Throttle = throttle.New(throttle.Default())

	for i := 0; i < 30; i++ {
		signInPost(srv, "qz_wrong")
	}
	w := signInPost(srv, token)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("a throttled sign-in answered %d; any page rendered here "+
			"is a page the browser will offer to resubmit", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/signin?e=throttled" {
		t.Fatalf("redirected to %q", loc)
	}
	if strings.Contains(loc, token) || strings.Contains(w.Body.String(), token) {
		t.Fatal("the token was echoed back")
	}
	if len(w.Result().Cookies()) > 0 {
		t.Fatal("a throttled sign-in set a cookie")
	}
}

// TestEveryRefusalIsARedirect covers the other two reasons.
func TestEveryRefusalIsARedirect(t *testing.T) {
	srv, _ := setup(t)
	for token, want := range map[string]string{
		"not-a-token": "/signin?e=format",
		"qz_nonsense": "/signin?e=refused",
		"":            "/signin?e=format",
	} {
		w := signInPost(srv, token)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
			t.Errorf("%q: %d to %q, want 303 to %q", token, w.Code,
				w.Header().Get("Location"), want)
		}
	}
}

// TestTheFormSaysOnlyWhatItWasWritten.
//
// The reason arrives in a query string anybody can write. It selects a
// sentence from a closed list; it never is one. Otherwise this is a
// phishing page with the site's own name and certificate on it.
func TestTheFormSaysOnlyWhatItWasWritten(t *testing.T) {
	srv, _ := setup(t)
	for _, e := range []string{
		"Your+account+is+locked.+Call+0800+000",
		"<script>alert(1)</script>",
		"refused%00",
	} {
		body := get(t, srv, "/signin?e="+e, "").Body.String()
		if strings.Contains(body, "0800") || strings.Contains(body, "alert(1)") {
			t.Errorf("the form printed what the link said: %q", e)
		}
		if strings.Contains(body, `role="alert"`) {
			t.Errorf("an unknown code produced an error at all: %q", e)
		}
	}
	body := get(t, srv, "/signin?e=refused", "").Body.String()
	if !strings.Contains(body, "That token was not accepted") {
		t.Fatal("a known code did not show its sentence")
	}
}

// TestSigningInWithTheRightTokenStillWorks, after all that.
func TestSigningInWithTheRightTokenStillWorks(t *testing.T) {
	srv, token := setup(t)
	w := signInPost(srv, token)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("answered %d", w.Code)
	}
	var session bool
	for _, c := range w.Result().Cookies() {
		if c.Name == "quilzo_token" && c.Value != "" {
			session = true
		}
	}
	if !session {
		t.Fatal("a correct token did not sign in")
	}
}
