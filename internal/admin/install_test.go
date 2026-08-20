package admin

import (
	"encoding/json"
	"strings"
	"testing"
)

// The install manifest is the whole of the desktop story.
//
// There is no native wrapper to test, deliberately: the browser installs this
// origin from the file below. So these tests hold the file to the contract a
// platform reads it under, because the failure mode is silent — a manifest
// with a wrong field does not error, it just quietly refuses to install, and
// nobody finds out until somebody tries.

func manifest(t *testing.T) (map[string]any, string) {
	t.Helper()
	srv, token := setup(t)
	w := get(t, srv, "/manifest.webmanifest", token)
	if w.Code != 200 {
		t.Fatalf("GET /manifest.webmanifest gave %d, want 200", w.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the manifest is not JSON, so no platform will read it: %v", err)
	}
	return doc, w.Header().Get("Content-Type")
}

// A platform will not install an origin from a manifest missing any of these.
func TestTheManifestCarriesWhatMakesItInstallable(t *testing.T) {
	doc, ctype := manifest(t)

	if !strings.HasPrefix(ctype, "application/manifest+json") {
		t.Errorf("served as %q; a manifest has to be application/manifest+json "+
			"or the browser fetches it and ignores it", ctype)
	}
	for field, want := range map[string]string{
		"start_url": "/",
		"scope":     "/",
		"display":   "standalone",
	} {
		if got, _ := doc[field].(string); got != want {
			t.Errorf("%s = %q, want %q. An installed window that opens on one "+
				"screen, or that navigates out of the admin into a tab, is not "+
				"the application somebody thought they installed.",
				field, got, want)
		}
	}
	if name, _ := doc["name"].(string); name == "" {
		t.Error("no name, so the launcher entry has nothing to say")
	}
	// An icon, and it has to be one this origin actually answers for.
	//
	// This asserted the opposite until there was a logo: no icons array at
	// all, on the argument that a generated fallback beats a request that
	// 404s. The argument was about not having a mark rather than about icons,
	// and the risk it named is the one checked below — every declared source
	// is fetched, here, rather than discovered broken on somebody's desktop.
	icons, _ := doc["icons"].([]any)
	if len(icons) == 0 {
		t.Fatal("the manifest declares no icon, so an installed window gets " +
			"a generated one and the mark is not on it")
	}
	srv, token := setup(t)
	for _, entry := range icons {
		e, _ := entry.(map[string]any)
		src, _ := e["src"].(string)
		if src == "" {
			t.Errorf("an icon entry names no source: %v", e)
			continue
		}
		w := get(t, srv, src, token)
		if w.Code != 200 {
			t.Errorf("the manifest points at %s and this server answers %d. "+
				"A declared icon that 404s installs a broken image where a "+
				"generated one would have done", src, w.Code)
			continue
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/") {
			t.Errorf("%s is served as %q, which is not an image", src, ct)
		}
	}
}

// The mark is defined once, and every surface draws that one.
//
// Four places want it — the header, the sign-in page, the favicon and the
// installed icon — and four copies of a path string is four things to keep in
// step. The one that falls behind is always the one nobody looks at, which
// here is the sign-in page, seen only by people who are not signed in.
func TestEverySurfaceDrawsTheSameMark(t *testing.T) {
	if len(MarkPath) < 40 {
		t.Fatalf("MarkPath is %d characters; that is not a logo and every "+
			"check below would pass against nothing", len(MarkPath))
	}
	srv, token := setup(t)

	for _, page := range []struct{ path, token, what string }{
		{"/", token, "the header on a signed-in screen"},
		{"/signin", "", "the sign-in page, which nobody signed in ever sees"},
	} {
		body := get(t, srv, page.path, page.token).Body.String()
		if !strings.Contains(body, MarkPath) {
			t.Errorf("%s does not draw the mark from MarkPath, so it is a "+
				"copy that will fall behind", page.what)
		}
	}

	// And the file a browser fetches carries the same path.
	w := get(t, srv, "/icon.svg", token)
	if !strings.Contains(w.Body.String(), MarkPath) {
		t.Error("/icon.svg draws something other than MarkPath")
	}
	// The nib is a hole rather than a white shape, which is what lets one mark
	// work on the light theme, the dark theme and an operator's own accent.
	// Without evenodd the subpaths fill solid and the nib disappears.
	if !strings.Contains(w.Body.String(), "evenodd") {
		t.Error("the mark is not drawn with fill-rule=evenodd, so the nib is " +
			"filled in rather than knocked out and the shape is a blob")
	}
}

// The icon carries the operator's colour, not a hard-coded one.
func TestTheIconIsPaintedInTheBrandColour(t *testing.T) {
	if !strings.Contains(MarkSVG("#7a2618"), "#7a2618") {
		t.Error("MarkSVG ignores the colour it is given")
	}
	// And it never emits currentColor, which has nothing to inherit from in a
	// file fetched as an icon and renders as black.
	if strings.Contains(MarkSVG(""), "currentColor") {
		t.Error("the standalone icon uses currentColor; fetched as a favicon " +
			"there is no inherited colour and it paints black")
	}
}

// The colour the platform paints the window is the colour the stylesheet uses.
//
// Two paths to one answer is how a window ends up in last month's brand: the
// manifest reads configuration, the stylesheet reads the validated Brand, and
// a value one of them rejects reaches the other. Both read Brand.
func TestTheInstalledWindowUsesTheBrandTheInterfaceUses(t *testing.T) {
	s := &Server{}
	if got := s.themeColour(); got != "#00515f" {
		t.Errorf("with no brand configured the colour is %q, want the built-in "+
			"#00515f", got)
	}

	s.Brand = Brand{Name: "Acme", Colour: "#7a2618"}
	if got := s.themeColour(); got != "#7a2618" {
		t.Errorf("with a valid brand colour the window is %q, want #7a2618", got)
	}

	// The load-bearing half. A colour the stylesheet refuses must not reach
	// the platform either, or the installed window is painted with a value
	// that was rejected for being unsafe to interpolate.
	s.Brand = Brand{Name: "Acme", Colour: "red; --primary: black"}
	if s.Brand.Style() != "" {
		t.Fatal("Brand.Style accepted a colour that is not a hex literal; " +
			"this test is checking the wrong thing and the stylesheet has a " +
			"bigger problem than the manifest does")
	}
	if got := s.themeColour(); got != "#00515f" {
		t.Errorf("a colour the stylesheet refused was served to the platform "+
			"as %q. The manifest and the stylesheet have to agree about what "+
			"this deployment's colour is.", got)
	}
}

// Signed out, it answers nothing.
//
// Not because a manifest is secret, but because it names the operator. An
// unauthenticated endpoint that returns a company name turns an unfamiliar
// host into an identified one for anybody who can reach the port.
func TestTheManifestIsNotServedToStrangers(t *testing.T) {
	srv, _ := setup(t)
	if w := get(t, srv, "/manifest.webmanifest", ""); w.Code != 401 {
		t.Errorf("anonymous GET gave %d, want 401 — the manifest carries the "+
			"operator's branding", w.Code)
	}
}

// The link and the policy, together.
//
// Either one alone does nothing: a <link rel=manifest> the policy blocks is a
// fetch the browser refuses, and a manifest-src directive with nothing linking
// to the file permits a request that is never made. Both, or neither works.
func TestThePageLinksTheManifestAndThePolicyPermitsIt(t *testing.T) {
	srv, token := setup(t)
	w := get(t, srv, "/", token)

	if !strings.Contains(w.Body.String(), `rel="manifest" href="/manifest.webmanifest"`) {
		t.Error("no page links the manifest, so nothing is installable")
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "manifest-src 'self'") {
		t.Errorf("the policy has no manifest-src 'self', so the browser will "+
			"refuse the file the page links:\n  %s", csp)
	}
	// And the directive stayed as narrow as it was argued to be.
	if strings.Contains(csp, "manifest-src *") || strings.Contains(csp, "manifest-src 'self' ") {
		t.Errorf("manifest-src widened beyond this origin:\n  %s", csp)
	}
}

// The editor shows the real page beside the form, and the policy permits it.
//
// Both halves, because either alone does nothing: an iframe the policy blocks
// is an empty box, and a frame-src directive with nothing framing anything
// permits a request never made.
func TestTheEditorShowsThePageBesideTheForm(t *testing.T) {
	srv, token := setup(t)
	w := get(t, srv, "/page/index", token)
	if w.Code != 200 {
		t.Fatalf("GET the editor gave %d", w.Code)
	}
	body := w.Body.String()

	if !strings.Contains(body, `src="/preview/index"`) {
		t.Error("the editor does not show the page it is editing")
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src 'self'") {
		t.Errorf("the policy has no frame-src 'self', so the browser refuses "+
			"the preview the page embeds:\n  %s", csp)
	}
	// And it stayed as narrow as it was argued to be. frame-src * would let
	// this interface embed anything on the internet.
	if strings.Contains(csp, "frame-src *") ||
		strings.Contains(csp, "frame-src 'self' ") {
		t.Errorf("frame-src widened beyond this origin:\n  %s", csp)
	}
	// Nobody may frame this interface, which is a different directive and
	// must not have been relaxed by adding the one above.
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("frame-ancestors is no longer 'none', so this interface can "+
			"be framed by another origin:\n  %s", csp)
	}
	// Still no script, which is the claim the whole policy makes.
	if !strings.Contains(csp, "default-src 'none'") ||
		strings.Contains(csp, "script-src") {
		t.Errorf("the policy grew a script directive:\n  %s", csp)
	}
}

// The preview does not claim to be live.
//
// It cannot be — live preview needs script and this response permits none —
// and a label implying otherwise would have somebody typing into a form and
// believing the panel beside it.
func TestThePreviewSaysWhenItChanges(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/page/index", token).Body.String()
	if !strings.Contains(body, "not as you type") {
		t.Error("nothing tells the editor when the preview refreshes, so it " +
			"reads as live and is not")
	}
}
