// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/oidc"
)

// A sign-in's answer finishes only in the browser that started it: the
// callback address of somebody else's sign-in, opened in another browser,
// signs nobody in there.
func TestAnOIDCSignInFinishesOnlyWhereItStarted(t *testing.T) {
	o := &OIDC{RedirectURI: "https://cms.example/auth/callback"}
	req, err := oidc.NewRequest(o.RedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	secret := "the-starting-browsers-secret"
	pend := func() {
		o.pending = map[string]*oidcPending{req.State: {req: req, binding: sha256.Sum256([]byte(secret))}}
	}
	callback := func(cookie *http.Cookie) error {
		r := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+req.State+"&code=c", nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		_, err := o.callback(context.Background(), r, "quilzo_oidc")
		return err
	}
	for name, c := range map[string]*http.Cookie{
		"no cookie":         nil,
		"another browser's": {Name: "quilzo_oidc", Value: "somebody-elses"},
	} {
		pend()
		if err := callback(c); err == nil || !strings.Contains(err.Error(), "another browser") {
			t.Errorf("%s: %v", name, err)
		}
		if o.take(req.State) != nil {
			t.Errorf("%s: the state survived a refused answer", name)
		}
	}
}

// Starting a sign-in sets the cookie it is bound to, and keeps only the
// cookie's hash; the server names the cookie by whether TLS is in use.
func TestStartingAnOIDCSignInSetsItsCookie(t *testing.T) {
	o := &OIDC{RedirectURI: "https://cms.example/auth/callback", ClientID: "cms",
		Provider: &oidc.Provider{Discovery: oidc.Discovery{AuthorizationEndpoint: "https://idp.example/authorize"}}}
	w := httptest.NewRecorder()
	o.start(w, httptest.NewRequest(http.MethodGet, "/signin/oidc", nil), "quilzo_oidc")
	var set *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "quilzo_oidc" {
			set = c
		}
	}
	if set == nil || set.Value == "" || !set.HttpOnly || !set.Secure || set.SameSite != http.SameSiteLaxMode {
		t.Fatalf("the binding cookie is %+v", set)
	}
	if len(o.pending) != 1 {
		t.Fatalf("%d sign-ins pending", len(o.pending))
	}
	for _, p := range o.pending {
		if p.binding != sha256.Sum256([]byte(set.Value)) {
			t.Error("the pending sign-in is not bound to the cookie set")
		}
	}

	srv, _ := setup(t)
	if got := srv.oidcCookie(httptest.NewRequest(http.MethodGet, "http://cms.example/", nil)); got != "quilzo_oidc" {
		t.Errorf("without TLS: %q", got)
	}
	r := httptest.NewRequest(http.MethodGet, "https://cms.example/", nil)
	if got := srv.oidcCookie(r); got != "__Host-quilzo_oidc" {
		t.Errorf("with TLS: %q", got)
	}
}
