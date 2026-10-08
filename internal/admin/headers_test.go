// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"
	"testing"
)

// TestNoAdminPageIsCached, walking every screen.
//
// Five handlers said no-store and the rest said nothing, so the screens that
// list people, tokens, audit entries and security events were cacheable: on
// a shared machine, the back button after signing out showed them. The rule
// is now a default in the middleware, and this walks every route so a
// screen added later cannot slip past it.
func TestNoAdminPageIsCached(t *testing.T) {
	srv, token := fullyWired(t)
	// The two that are meant to be cached, and say for how long.
	cached := map[string]bool{"/style.css": true, "/admin.js": true, "/brand.css": true,
		"/fonts/quilzo-ui.woff2": true}
	for path := range servedRoutes(t) {
		if strings.HasSuffix(path, "/") || strings.Contains(path, "{") {
			continue
		}
		w := get(t, srv, path, token)
		cc := w.Header().Get("Cache-Control")
		if cached[path] {
			if cc == "no-store" {
				t.Errorf("%s is static and was marked no-store", path)
			}
			continue
		}
		if cc != "no-store" && !strings.HasPrefix(cc, "private") {
			t.Errorf("%s answered %d with Cache-Control %q", path, w.Code, cc)
		}
	}
	// And the sign-in page, which is reached without a credential.
	if cc := get(t, srv, "/signin", "").Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("/signin: Cache-Control %q", cc)
	}
}

// TestOnlyThePreviewMayBeFramed, and only by this origin.
//
// The editor shows /preview/NAME in a frame beside the form. The policy said
// frame-ancestors 'none' for every response, beside a comment saying this
// origin may frame itself — which 'none' forbids — so in Chrome the preview
// was an empty grey box on every page.
func TestOnlyThePreviewMayBeFramed(t *testing.T) {
	srv, token := setup(t)

	w := get(t, srv, "/preview/index", token)
	if w.Code != http.StatusOK {
		t.Fatalf("preview answered %d", w.Code)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'self'") {
		t.Errorf("the preview cannot be framed by the editor: %q", csp)
	}
	if xfo := w.Header().Get("X-Frame-Options"); xfo != "SAMEORIGIN" {
		t.Errorf("preview X-Frame-Options = %q", xfo)
	}
	if strings.Contains(csp, "script-src") || strings.Contains(csp, "*") {
		t.Errorf("framing the preview loosened something else: %q", csp)
	}

	for _, path := range []string{"/", "/signin", "/security", "/page/index"} {
		h := get(t, srv, path, token).Header()
		if !strings.Contains(h.Get("Content-Security-Policy"),
			"frame-ancestors 'none'") || h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s can be framed: %q / %q", path,
				h.Get("Content-Security-Policy"), h.Get("X-Frame-Options"))
		}
	}
}

// TestIsolationHeadersAreSent.
func TestIsolationHeadersAreSent(t *testing.T) {
	srv, token := setup(t)
	h := get(t, srv, "/", token).Header()
	for k, want := range map[string]string{
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	pp := h.Get("Permissions-Policy")
	for _, off := range []string{"camera=()", "microphone=()", "geolocation=()"} {
		if !strings.Contains(pp, off) {
			t.Errorf("Permissions-Policy leaves %s on: %q", off, pp)
		}
	}
	// Passkeys need credential access at this origin, so it is not listed.
	if strings.Contains(pp, "publickey-credentials") {
		t.Errorf("Permissions-Policy switches off passkeys: %q", pp)
	}
}

// TestAPreviewedPageShowsItsPictures.
//
// Pages link media at /media/<sha256>, the public site's address. The admin
// served the bytes at /media/file/ and had /media for the library screen,
// so every image in every preview was a broken link.
func TestAPreviewedPageShowsItsPictures(t *testing.T) {
	srv, token := setup(t)
	id := withPicture(t, srv)

	w := get(t, srv, "/media/"+id, token)
	if w.Code != http.StatusOK {
		t.Fatalf("/media/<hash> answered %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/") {
		t.Fatalf("Content-Type = %q", ct)
	}
	// Not without a credential.
	if w := get(t, srv, "/media/"+id, ""); w.Code == http.StatusOK {
		t.Fatal("media was served without signing in")
	}
	// A hash and nothing else.
	for _, bad := range []string{
		"/media/" + strings.ToUpper(id),
		"/media/" + id[:63],
		"/media/" + id + "0",
		"/media/../../etc/passwd",
		"/media/" + id[:60] + "%2e%2e",
		"/media/nothing",
	} {
		if w := get(t, srv, bad, token); w.Code == http.StatusOK {
			t.Errorf("%s was served", bad)
		}
	}
	// The library screen is still where it was.
	if w := get(t, srv, "/media", token); w.Code != http.StatusOK {
		t.Errorf("/media answered %d", w.Code)
	}
}
