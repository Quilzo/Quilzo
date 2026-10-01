// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"
)

// The preview draws a page in the site's own typeface.
//
// The site's stylesheet names /fonts/FAMILY.woff2, and this server answered
// 404 for it, so every preview fell back to a system face.
func TestThePreviewGetsTheSitesOwnFonts(t *testing.T) {
	srv, token := setup(t)
	face := []byte("wOF2 a face")
	srv.DesignSet = &Design{FontFile: func(name string) ([]byte, bool) {
		if name == "Satoshi-400..700.woff2" {
			return face, true
		}
		return nil, false
	}}

	w := get(t, srv, "/fonts/Satoshi-400..700.woff2", token)
	if w.Code != 200 || w.Body.String() != string(face) ||
		w.Header().Get("Content-Type") != "font/woff2" {
		t.Fatalf("the site's font: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	for _, path := range []string{"/fonts/Other.woff2", "/fonts/../tokens.json", "/fonts/a/b.woff2"} {
		// The mux answers a dotted path with a redirect to its clean form,
		// before any handler; what matters is that no font comes back.
		if w := get(t, srv, path, token); w.Code == 200 {
			t.Errorf("%s gave %d", path, w.Code)
		}
	}
	// Behind sign-in, like the preview that asks for it.
	if w := get(t, srv, "/fonts/Satoshi-400..700.woff2", ""); w.Code == 200 {
		t.Error("a site font was served to somebody not signed in")
	}
	// And the interface's own face is still its own.
	if w := get(t, srv, "/fonts/quilzo-ui.woff2", token); w.Code != 200 {
		t.Errorf("the interface's font: %d", w.Code)
	}
}

// A font the site serves can be chosen on the Design screen.
//
// The screen checked the theme against no fonts at all, so it reported the
// site's own typeface as one it does not serve, and refused to save it —
// while `quilzo theme set` accepted the same value.
func TestTheDesignScreenKnowsTheSitesFonts(t *testing.T) {
	srv, token := setup(t)
	saved := map[string]string{}
	srv.DesignSet = &Design{
		Tokens: func() (map[string]string, error) {
			out := map[string]string{}
			for k, v := range saved {
				out[k] = v
			}
			return out, nil
		},
		Save:  func(v map[string]string) error { saved = v; return nil },
		Fonts: func() []string { return []string{"Satoshi"} },
	}
	w := postForm(t, srv, "/design/save", token, "token=font-body&light=Satoshi")
	if w.Code >= 400 || saved["font-body"] != "Satoshi" {
		t.Fatalf("choosing the site's own font: %d, saved %v, %s", w.Code, saved,
			w.Header().Get("Location"))
	}
	if body := get(t, srv, "/design", token).Body.String(); strings.Contains(body, "does not serve") {
		t.Error("the screen says the site does not serve the font it serves")
	}
	// A family the site does not serve is still refused.
	w = postForm(t, srv, "/design/save", token, "token=font-display&light=Nonesuch")
	if _, set := saved["font-display"]; set {
		t.Errorf("a font the site does not serve was saved: %d", w.Code)
	}
}
