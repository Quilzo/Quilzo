// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/oidc"
)

// Finding your way: where the name goes, the way up from a screen, the way
// out of a message, where signing in returns to, and links that leave.
//
// Each of these sent people somewhere other than where they meant to go,
// and the owner reported it as "when I click something on the admin page it
// takes me to the pages".

// The name in the bar goes where signing in goes: Today, unless the person
// chose to start on Pages.
func TestTheNameGoesWhereSigningInGoes(t *testing.T) {
	srv, token := setup(t)
	brand := regexp.MustCompile(`<a class="brand" href="([^"]*)"`)

	body := get(t, srv, "/history", token).Body.String()
	if m := brand.FindStringSubmatch(body); m == nil || m[1] != "/today" {
		t.Errorf("the name goes to %v, not to Today, where signing in lands", m)
	}

	req := httptest.NewRequest(http.MethodGet, "/history", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.AddCookie(&http.Cookie{Name: StartCookie, Value: "pages"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if m := brand.FindStringSubmatch(w.Body.String()); m == nil || m[1] != "/" {
		t.Errorf("somebody who starts on Pages is sent to %v by the name", m)
	}
}

// A screen below a destination has a way up to it; a destination has none,
// because it would point at itself.
func TestAScreenBelowTheMenuHasAWayUp(t *testing.T) {
	srv, token := setup(t)
	crumbs := regexp.MustCompile(`<nav class="crumbs" aria-label="Breadcrumb"><svg.*?</svg><ol><li><a href="([^"]*)">([^<]*)</a></li></ol></nav>`)

	m := crumbs.FindStringSubmatch(get(t, srv, "/page/about", token).Body.String())
	if m == nil || m[1] != "/" || m[2] != "Pages" {
		t.Errorf("the page editor's way up is %v, not Pages", m)
	}
	for _, path := range []string{"/", "/today", "/history"} {
		if body := get(t, srv, path, token).Body.String(); strings.Contains(body, `class="crumbs"`) {
			t.Errorf("%s is in the menu and still shows a way up to itself", path)
		}
	}
}

// The way out of a message is where the person was, never the page list.
func TestAMessageGoesBackWhereItCameFrom(t *testing.T) {
	// A form that says where it was posted from goes back there.
	req := httptest.NewRequest(http.MethodPost, "/notes/add",
		strings.NewReader("back=%2Frecords%3Fcollection%3Dproducts"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	if got := wayBack(req, map[string]any{}); got.Path != "/records?collection=products" {
		t.Errorf("a message after a form goes back to %q", got.Path)
	}
	// One whose form names somewhere else is not followed there.
	for _, back := range []string{"https://elsewhere.example/", "//elsewhere.example/", `/\elsewhere.example`} {
		req = httptest.NewRequest(http.MethodPost, "/notes/add",
			strings.NewReader("back="+url.QueryEscape(back)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()
		if got := wayBack(req, map[string]any{}); !isLocalURL(got.Path) || strings.Contains(got.Path, "elsewhere") {
			t.Errorf("a message followed %q to %q", back, got.Path)
		}
	}
	// Otherwise the section the screen is in, and otherwise the start.
	req = httptest.NewRequest(http.MethodGet, "/agents/x", nil)
	if got := wayBack(req, map[string]any{"Crumb": crumb{Label: "Agents", Path: "/agents"}}); got.Path != "/agents" {
		t.Errorf("a message in Agents goes back to %q", got.Path)
	}
	if got := wayBack(req, map[string]any{}); got.Path != "/today" || got.Label != "Today" {
		t.Errorf("a message with nowhere better goes to %+v, not the start", got)
	}

	// And on a real refusal, the link is not to the page list.
	srv, token := setup(t)
	body := post(t, srv, "/checked/set", token).Body.String()
	if strings.Contains(body, "Back to pages") {
		t.Error(`a message still says "Back to pages" whatever it was about`)
	}
}

// Signing in returns to what was asked for.
func TestSigningInReturnsToWhatWasAskedFor(t *testing.T) {
	srv, token := setup(t)

	// The form answers at the address asked for, and carries it.
	w := get(t, srv, "/history?from=50", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an address asked for signed out answered %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `name="next" value="/history?from=50"`) {
		t.Error("the sign-in form does not carry the address that was asked for")
	}
	if !strings.Contains(w.Body.String(), `/signin/passkey?next=%2fhistory%3ffrom%3d50`) {
		t.Error("the passkey link does not carry the address that was asked for")
	}

	signIn := func(next string) string {
		form := url.Values{"token": {token}}
		if next != "" {
			form.Set("next", next)
		}
		req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("signing in answered %d", w.Code)
		}
		return unsigned(w.Header().Get("Location"))
	}
	if got := signIn("/history?from=50"); got != "/history?from=50" {
		t.Errorf("signing in went to %q, not to what was asked for", got)
	}
	// Nowhere but here, and never back to signing in.
	for _, next := range []string{
		"https://elsewhere.example/", "//elsewhere.example/", `/\elsewhere.example`,
		"/signin", "/signin/passkey", "/signout", "javascript:alert(1)", "history",
	} {
		if got := signIn(next); strings.Contains(got, "elsewhere") || strings.HasPrefix(got, "/signin") ||
			got == "/signout" || !isLocalURL(got) {
			t.Errorf("next=%q sent a sign-in to %q", next, got)
		}
	}
	// A refused attempt keeps where they were going.
	req := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token=qz_nonsense&next=%2Fhistory"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if loc := unsigned(w.Header().Get("Location")); loc != "/signin?e=refused&next=%2Fhistory" {
		t.Errorf("a refused sign-in went to %q and forgot where it was going", loc)
	}
	if body := get(t, srv, "/signin?next=%2Fhistory", "").Body.String(); !strings.Contains(body, `name="next" value="/history"`) {
		t.Error("the form shown again after a refusal does not carry the address")
	}
}

// Every link on every screen that leaves this origin opens a new tab and
// says so; every link that opens a new tab says so. Help is the case the
// owner asked for: pressed mid-form, a manual opening in the same tab
// replaces what was typed.
func TestEveryNewTabSaysSo(t *testing.T) {
	srv, token := fullyWired(t)
	// The frameworks screens link to each framework's published text.
	wirePosture(srv, true)
	anchor := regexp.MustCompile(`(?s)<a\s([^>]*)>(.*?)</a>`)
	attr := func(attrs, name string) (string, bool) {
		m := regexp.MustCompile(`\b` + name + `="([^"]*)"`).FindStringSubmatch(attrs)
		if m == nil {
			return "", false
		}
		return m[1], true
	}
	// Every destination, and every screen one link below one: the source
	// links on a framework's own screen were missed by a test that opened
	// only the menu.
	paths := []string{}
	seen := map[string]bool{}
	for _, d := range destinations {
		paths = append(paths, d.Path)
		seen[d.Path] = true
	}
	local := regexp.MustCompile(`href="(/[a-z][^"?#{]*)"`)
	// Two links deep: Security, then Frameworks, then one framework.
	for depth, from := 0, 0; depth < 2; depth++ {
		level := paths[from:]
		from = len(paths)
		for _, at := range level {
			for _, m := range local.FindAllStringSubmatch(get(t, srv, at, token).Body.String(), -1) {
				p := m[1]
				// Leaving is a GET here, and it would end the session the
				// rest of this test uses.
				if seen[p] || p == "/signout" || strings.HasPrefix(p, "/signin") {
					continue
				}
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	checked := 0
	for _, p := range paths {
		w := get(t, srv, p, token)
		if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
			continue
		}
		checked++
		d := destination{Path: p}
		for _, m := range anchor.FindAllStringSubmatch(w.Body.String(), -1) {
			href, _ := attr(m[1], "href")
			target, _ := attr(m[1], "target")
			rel, _ := attr(m[1], "rel")
			leaves := strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://")
			if leaves && target != "_blank" {
				t.Errorf("%s: a link to %s leaves the admin in the same tab", d.Path, href)
			}
			if target == "_blank" {
				if !strings.Contains(m[2], "(opens in a new tab)") {
					t.Errorf("%s: a link to %s opens a new tab without saying so", d.Path, href)
				}
				if !strings.Contains(rel, "noopener") {
					t.Errorf("%s: a link to %s opens a new tab with a handle on this one", d.Path, href)
				}
			}
		}
	}
	if checked < 25 {
		t.Fatalf("only %d screens answered; this checked almost nothing", checked)
	}
	body := get(t, srv, "/today", token).Body.String()
	if !strings.Contains(body, `target="_blank" rel="noopener noreferrer">Help with this screen`) {
		t.Error("Help with this screen does not open in a new tab")
	}
}

// A sign-on through an identity provider returns to what was asked for
// too: the destination is kept with the rest of the attempt, on this
// server, and checked again on the way out.
func TestSigningOnReturnsToWhatWasAskedFor(t *testing.T) {
	o := &OIDC{RedirectURI: "https://cms.example/auth/callback", ClientID: "cms",
		Provider: &oidc.Provider{Discovery: oidc.Discovery{AuthorizationEndpoint: "https://idp.example/authorize"}}}
	o.start(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet,
		"/signin/oidc?next=%2Fhistory%3Ffrom%3D50", nil), "quilzo_oidc", 8*time.Hour)
	o.start(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet,
		"/signin/oidc?next=https%3A%2F%2Felsewhere.example%2F", nil), "quilzo_oidc", 8*time.Hour)
	kept := map[string]bool{}
	for _, p := range o.pending {
		kept[p.next] = true
	}
	if !kept["/history?from=50"] || !kept[""] || len(kept) != 2 {
		t.Errorf("the pending sign-ins kept %v", kept)
	}

	srv, _ := setup(t)
	r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	if got := srv.ssoNext(r, "dana", ssoProof{MFA: true}, "/history"); got != "/history" {
		t.Errorf("a sign-on went to %q, not to what was asked for", got)
	}
	// One that has to be confirmed first takes the destination with it.
	if got := srv.ssoNext(r, "dana", ssoProof{}, "/history"); got != "/signin/verify?next=%2Fhistory" {
		t.Errorf("a sign-on to confirm went to %q and forgot where it was going", got)
	}
	if got := srv.ssoNext(r, "dana", ssoProof{MFA: true}, "//elsewhere.example/"); got != "/today" {
		t.Errorf("a sign-on followed a destination elsewhere to %q", got)
	}

	// The sign-in page hands it to every way of signing on.
	srv.OIDC = o
	body := get(t, srv, "/history", "").Body.String()
	if !strings.Contains(body, `href="/signin/oidc?next=%2fhistory"`) {
		t.Error("the single sign-on link does not carry the address that was asked for")
	}
}
