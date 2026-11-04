// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/starter"
	"github.com/quilzo/quilzo/internal/theme"
)

// withLayer gives a faked design a style layer the screen can read and write.
func withLayer(srv *Server, layer *string) {
	srv.DesignSet.Layer = func() (string, error) { return *layer, nil }
	srv.DesignSet.SaveLayer = func(css string) error { *layer = css; return nil }
}

// The Design screen offers everything the commands do: the neon style beside
// the others, the corner and the schemes in the Look section, the glow and
// the veil in the token table, and the style layer.
func TestTheDesignScreenOffersWhatTheCommandsDo(t *testing.T) {
	srv, token := setup(t)
	designFake(srv, map[string]string{})
	layer := ""
	withLayer(srv, &layer)
	page := get(t, srv, "/design", token).Body.String()
	for _, want := range []string{
		`name="light" value="neon"`, `style-neon`,
		`name="token" value="corner"`, `name="light" value="chamfer"`,
		`name="token" value="scheme"`, `name="light" value="dark"`,
		"Glow and backdrops", `name="token" value="scrim-strength"`, `name="token" value="glow"`,
		`action="/design/layer"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the screen does not offer %s", want)
		}
	}
}

// A layer is saved from the browser only when it would be served, by a
// publisher, and each change is recorded.
func TestAStyleLayerIsSavedFromTheBrowserOnlyWhenItWouldBeServed(t *testing.T) {
	srv, token := setup(t)
	designFake(srv, map[string]string{})
	layer := ""
	withLayer(srv, &layer)
	var got []string
	srv.Audit = func(action, resource string, _ map[string]string) { got = append(got, action+" "+resource) }

	w := postForm(t, srv, "/design/layer", token, "layer="+url.QueryEscape(".hero { color: #ff00ff; }"))
	if layer != "" || w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a layer with a hex colour was saved: %d %q", w.Code, layer)
	}
	good := ".card:hover { box-shadow: 0 0 1rem color-mix(in srgb, var(--primary) 30%, transparent); }"
	postForm(t, srv, "/design/layer", token, "layer="+url.QueryEscape(good))
	if layer != good || !recorded(got, "theme.layer.set") {
		t.Fatalf("a layer that passes was not saved and recorded: %q %v", layer, got)
	}
	page := get(t, srv, "/design", token).Body.String()
	if !strings.Contains(page, "The saved layer is served") {
		t.Error("the screen does not say the layer is served")
	}
	postForm(t, srv, "/design/layer", token, "remove=1")
	if layer != "" || !recorded(got, "theme.layer.unset") {
		t.Fatalf("taking the layer away: %q %v", layer, got)
	}

	// An author edits drafts; a layer is on every page, which is a publisher's.
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	author, _, err := srv.Tokens.IssueSession("w", "writer", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if w := postForm(t, srv, "/design/layer", author, "layer="+url.QueryEscape(good)); w.Code != http.StatusForbidden || layer != "" {
		t.Errorf("an author set the style layer: %d %q", w.Code, layer)
	}
}

// A choice is part of no pair and can still break one, so a choice that
// makes a pair fail which did not fail before is refused.
func TestAChoiceThatBreaksAPairIsRefused(t *testing.T) {
	srv, token := setup(t)
	// Readable in dark, unreadable in light, on a site drawn in dark alone.
	saved := map[string]string{"scheme": "dark", "on-surface.light": "#f0f0f0"}
	designFake(srv, saved)
	w := postForm(t, srv, "/design/save", token, "token=scheme&light=both")
	if saved["scheme"] != "dark" || !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Errorf("drawing the site in both schemes, with an unreadable light one, was saved: %v", saved)
	}
	postForm(t, srv, "/design/save", token, "token=corner&light=chamfer")
	if saved["corner"] != "chamfer" {
		t.Errorf("a corner that breaks nothing was refused: %v", saved)
	}
}

// A backdrop goes behind a section from the Sections screen, the picker then
// offers pictures for it, and it comes away again.
func TestASectionGetsABackdropOnTheSectionsScreen(t *testing.T) {
	srv, token := setup(t)
	id := withLibrary(t, srv)
	base := srv.Store.GetRef(site.RefDraft)
	postForm(t, srv, "/sections/edit", token, "page=index&at=0&do=backdrop&base="+base)
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if on := section.On(pages["index"]); len(on) == 0 || !on[0].Backdrop {
		t.Fatalf("the section has no backdrop: %v", on)
	}
	html := get(t, srv, "/media/pick?page=index&at=0&path=backdrop_url", token).Body.String()
	if !strings.Contains(html, `value="/media/`+id+`"`) || !strings.Contains(html, "a picture or a silent video") {
		t.Error("the picker does not offer the library's pictures for a backdrop")
	}
	if !strings.Contains(get(t, srv, "/sections?page=index", token).Body.String(), "Take the backdrop away") {
		t.Error("the screen does not offer to take the backdrop away")
	}
	postForm(t, srv, "/sections/edit", token, "page=index&at=0&do=nobackdrop&base="+srv.Store.GetRef(site.RefDraft))
	pages, _ = site.PagesAt(srv.Store, site.RefDraft)
	if on := section.On(pages["index"]); on[0].Backdrop {
		t.Error("the backdrop is still there")
	}
}

// The browser's gate judges a backdrop as `quilzo publish` does: the words
// over it against the worst picture its veil could cover, on that page.
func TestTheBrowsersGateJudgesABackdropAsTheTerminalDoes(t *testing.T) {
	srv, _ := setup(t)
	id := withLibrary(t, srv)
	designFake(srv, map[string]string{"scrim-strength": "30%"})
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["about"] = map[string]any{"title": "About", "sections": []any{map[string]any{"prose": map[string]any{
		"title": "Us", "paragraphs": []any{"A studio."}, "surface": "media", "backdrop_url": "/media/" + id}}}}
	commit, err := site.SaveDraft(srv.Store, pages, "a backdrop", "test")
	if err != nil {
		t.Fatal(err)
	}
	srv.Layouts = mustLayouts(t)
	reports, err := srv.checkAll(commit)
	if err != nil {
		t.Fatal(err)
	}
	on := map[string]bool{}
	for _, r := range reports {
		for _, f := range r.Findings {
			if f.Rule == "backdrop-contrast" && f.Severity == a11y.Blocking {
				on[r.Page] = true
			}
		}
	}
	if len(on) != 1 || !on["about"] {
		t.Errorf("the weak veil was refused on %v, want about alone", on)
	}
}

// mustLayouts is the shipped sections layout, which draws backdrops.
func mustLayouts(t *testing.T) render.Layouts {
	t.Helper()
	shipped, err := starter.Layouts()
	if err != nil {
		t.Fatal(err)
	}
	l, err := render.NewLayouts(map[string]string{render.DefaultLayout: shipped["page"]})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// A layer inside the size bound saves from the browser however much of it a
// form has to encode.
//
// The body was bounded at the layer's size and sixteen kibibytes more, and a
// form sends every brace, colon, semicolon and line break as three bytes. So
// a sixty-kibibyte layer that `quilzo theme layer set` takes was refused here
// as too large, with the screen saying the bound it was inside.
func TestALayerInsideTheBoundSavesFromTheBrowser(t *testing.T) {
	srv, token := setup(t)
	designFake(srv, map[string]string{})
	layer := ""
	withLayer(srv, &layer)
	big := strings.Repeat(".a { color: var(--primary); }\n", 2000)
	if len(big) > theme.MaxLayer {
		t.Fatalf("the fixture is %d bytes, over the bound", len(big))
	}
	w := postForm(t, srv, "/design/layer", token, "layer="+url.QueryEscape(big))
	if layer != big {
		t.Errorf("a %d-byte layer was not saved: %s", len(big), w.Header().Get("Location"))
	}
	// Past the bound is still refused, and nothing is read without end.
	over := strings.Repeat(".a { color: var(--primary); }\n", 3*theme.MaxLayer/30)
	layer = ""
	postForm(t, srv, "/design/layer", token, "layer="+url.QueryEscape(over))
	if layer != "" {
		t.Error("a layer three times the bound was saved")
	}
}

// A page that switches its backdrop on in its own words is judged over the
// veil like any other. The layout draws a hero over its backdrop for
// "backdrop_on": "yes" as surely as for true, and the gate took only true.
func TestTheBrowsersGateSeesABackdropThePageSwitchedOnItself(t *testing.T) {
	srv, _ := setup(t)
	id := withLibrary(t, srv)
	designFake(srv, map[string]string{"scrim-strength": "30%"})
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["arena"] = map[string]any{"title": "Arena", "hero": map[string]any{
		"title": "Arena", "backdrop_url": "/media/" + id, "backdrop_on": "yes"}}
	commit, err := site.SaveDraft(srv.Store, pages, "a backdrop switched on by hand", "test")
	if err != nil {
		t.Fatal(err)
	}
	srv.Layouts = mustLayouts(t)
	reports, err := srv.checkAll(commit)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reports {
		for _, f := range r.Findings {
			if r.Page == "arena" && f.Rule == "backdrop-contrast" && f.Severity == a11y.Blocking {
				return
			}
		}
	}
	t.Error("a hero drawn over a backdrop under a 30% veil passed the gate")
}

// A refused layer comes back as it was written, with every refused rule
// named, rather than being replaced by the layer that was there. A redirect
// used to lose it: a page of CSS with one hex colour in it was gone, and the
// screen named only the first thing wrong with it.
func TestARefusedLayerIsGivenBackWithEveryRefusal(t *testing.T) {
	srv, token := setup(t)
	designFake(srv, map[string]string{})
	kept := ".card { border-color: var(--outline); }"
	layer := kept
	withLayer(srv, &layer)

	draft := ".hero { color: #ff00ff; }\n.lead { background: red; }\n.note { padding: 2rem; }"
	w := postForm(t, srv, "/design/layer", token, "layer="+url.QueryEscape(draft))
	if w.Code != http.StatusUnprocessableEntity || layer != kept {
		t.Fatalf("a refused layer: %d, saved %q", w.Code, layer)
	}
	page := w.Body.String()
	if !strings.Contains(page, ".note { padding: 2rem; }") || !strings.Contains(page, "#ff00ff") {
		t.Error("what was typed is not in the box")
	}
	if !strings.Contains(page, "Not saved.") || !strings.Contains(page, "2 rules are") ||
		!strings.Contains(page, "hex colour") || !strings.Contains(page, "named colour") {
		t.Errorf("the screen does not name both refused rules:\n%s", page)
	}
	if !strings.Contains(page, "The saved layer is served") {
		t.Error("the screen does not say the saved layer is still served")
	}
	// The layer is far down a long screen, so the top of it says so too.
	if !strings.Contains(page, `role="alert">The style layer was not saved`) || !strings.Contains(page, `href="#layer"`) {
		t.Error("the top of the screen does not say the layer was refused, or where")
	}
}

// Somebody who may edit the design but not publish is shown the layer and
// told who may change it, rather than a form that ends on a refusal.
func TestTheLayerIsReadOnlyToSomebodyWhoCannotPublish(t *testing.T) {
	srv, _ := setup(t)
	designFake(srv, map[string]string{})
	layer := ".card { border-color: var(--outline); }"
	withLayer(srv, &layer)
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	author, _, err := srv.Tokens.IssueSession("w", "writer", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	page := get(t, srv, "/design", author).Body.String()
	if strings.Contains(page, `action="/design/layer"`) {
		t.Error("an author is offered a form only a publisher can use")
	}
	if !strings.Contains(page, "border-color: var(--outline)") || !strings.Contains(page, "readonly") ||
		!strings.Contains(page, "takes whoever may publish") {
		t.Error("an author is not shown the layer, read-only, with who may change it")
	}
}
