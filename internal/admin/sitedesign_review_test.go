// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/find"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/site"
)

// Taking the layer away gives back what it held, in the box and unsaved, so
// one press of Save puts it back. It was one button with nothing after it: a
// page of somebody's CSS was gone, and the screen came back with an empty box.
func TestALayerTakenAwayIsGivenBackInTheBox(t *testing.T) {
	srv, token := setup(t)
	designFake(srv, map[string]string{})
	kept := ".card { border-color: var(--outline); }\n.hero { padding-block: 6rem; }"
	layer := kept
	withLayer(srv, &layer)

	w := postForm(t, srv, "/design/layer", token, "remove=1")
	if layer != "" {
		t.Fatalf("the layer was not taken away: %q", layer)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("taking the layer away answered %d", w.Code)
	}
	page := w.Body.String()
	if !strings.Contains(page, "padding-block: 6rem") || !strings.Contains(page, "border-color: var(--outline)") {
		t.Error("what the layer held is not in the box")
	}
	if !strings.Contains(page, "The style layer is gone") || !strings.Contains(page, "Save the layer puts it back") {
		t.Errorf("the screen does not say the layer is gone and how to have it back:\n%s", page)
	}
	if strings.Contains(page, "Take the layer away</button>") {
		t.Error("the screen offers to take away a layer that is not there")
	}

	// Saving what was given back is the way back.
	postForm(t, srv, "/design/layer", token, "layer="+url.QueryEscape(kept))
	if layer != kept {
		t.Errorf("the layer given back did not save: %q", layer)
	}

	// Pressed again with nothing there, it says so rather than drawing an
	// empty box as though something had been given back.
	layer = ""
	w = postForm(t, srv, "/design/layer", token, "remove=1")
	if w.Code != http.StatusSeeOther {
		t.Errorf("taking away a layer that is not there answered %d", w.Code)
	}
}

// The words somebody looking for the new design would type find the screen
// that has it: a dark site, the neon style and a glow on the Design screen,
// and a backdrop or a background video on the Sections screen.
func TestTheFinderKnowsTheWordsForTheNewDesign(t *testing.T) {
	for query, want := range map[string]string{
		"dark mode": "Design", "neon": "Design", "glow": "Design", "style": "Design",
		"backdrop": "Sections", "background video": "Sections", "hero": "Sections",
	} {
		hits := find.Search(query, find.Sources{Screens: Screens()}, 5)
		if len(hits) == 0 || hits[0].Title != want {
			t.Errorf("%q finds %v, want %s first", query, hits, want)
		}
	}
}

// A hero gets a backdrop on the Sections screen, as a section does: the
// picker offers the library's pictures and its silent recordings, choosing
// one puts it behind the hero's words, and it comes away again. The hero had
// no screen at all, so the backdrop the arena site was made for could be put
// there only from the terminal.
func TestAHeroGetsABackdropOnTheSectionsScreen(t *testing.T) {
	t.Setenv("PATH", "/nonexistent")
	srv, token := setup(t)
	picture := withLibrary(t, srv)
	lib, err := srv.Media.Library()
	if err != nil {
		t.Fatal(err)
	}
	clip := func(name string, sound bool, fill byte) string {
		body := append([]byte{0x1A, 0x45, 0xDF, 0xA3}, []byte("webm")...)
		body = append(body, bytes.Repeat([]byte{fill}, 2048)...)
		f, err := media.Accept(name, body, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		f.Sound = &sound
		if err := lib.Put(f, body); err != nil {
			t.Fatal(err)
		}
		return f.ID
	}
	quiet, loud := clip("loop.webm", false, 1), clip("trailer.webm", true, 2)

	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	index := pages["index"].(map[string]any)
	index["hero"] = map[string]any{"title": "Games for after dark", "lead": "A studio."}
	if _, err := site.SaveDraft(srv.Store, pages, "a hero", "test"); err != nil {
		t.Fatal(err)
	}
	hero := func() map[string]any {
		t.Helper()
		pages, err := site.PagesAt(srv.Store, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		return pages["index"].(map[string]any)["hero"].(map[string]any)
	}

	screen := get(t, srv, "/sections?page=index", token).Body.String()
	link := `/media/pick?page=index&amp;at=hero&amp;path=backdrop_url`
	if !strings.Contains(screen, link) || !strings.Contains(screen, "Put a backdrop behind the hero") {
		t.Fatalf("the Sections screen does not offer a backdrop for the hero:\n%s", screen)
	}

	pick := get(t, srv, "/media/pick?page=index&at=hero&path=backdrop_url", token)
	html := pick.Body.String()
	if pick.Code != http.StatusOK || !strings.Contains(html, `action="/sections/edit"`) ||
		!strings.Contains(html, `name="do" value="herobackdrop"`) {
		t.Fatalf("the picker does not choose for the hero: %d\n%s", pick.Code, html)
	}
	if !strings.Contains(html, `value="/media/`+picture+`"`) || !strings.Contains(html, `value="/media/`+quiet+`"`) {
		t.Error("the picker does not offer the library's pictures and silent recordings for the hero")
	}
	if strings.Contains(html, `value="/media/`+loud+`"`) {
		t.Error("the picker offers a recording with sound for the hero")
	}
	if !strings.Contains(html, "the hero of") {
		t.Error("the picker does not say it is choosing for the hero")
	}
	// Searching keeps it choosing for the hero.
	if !strings.Contains(html, `name="at" value="hero"`) {
		t.Error("the picker's search forgets that it is choosing for the hero")
	}

	base := srv.Store.GetRef(site.RefDraft)
	w := postForm(t, srv, "/sections/edit", token, "page=index&do=herobackdrop&media=/media/"+quiet+"&base="+base)
	if got, _ := hero()["backdrop_url"].(string); got != "/media/"+quiet {
		t.Fatalf("choosing a backdrop for the hero wrote %q (%d %s)", got, w.Code, w.Header().Get("Location"))
	}
	if title, _ := hero()["title"].(string); title != "Games for after dark" {
		t.Error("putting a backdrop behind the hero changed its words")
	}
	screen = get(t, srv, "/sections?page=index", token).Body.String()
	if !strings.Contains(screen, "loop.webm") || !strings.Contains(screen, "Take the backdrop away from the hero") {
		t.Errorf("the Sections screen does not say what is behind the hero:\n%s", screen)
	}

	// Only a file of the library's.
	base = srv.Store.GetRef(site.RefDraft)
	w = postForm(t, srv, "/sections/edit", token, "page=index&do=herobackdrop&media="+
		url.QueryEscape("https://example.com/x.png")+"&base="+base)
	if got, _ := hero()["backdrop_url"].(string); got != "/media/"+quiet || !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Errorf("an outside address went behind the hero: %q", got)
	}

	base = srv.Store.GetRef(site.RefDraft)
	postForm(t, srv, "/sections/edit", token, "page=index&do=noherobackdrop&base="+base)
	if _, has := hero()["backdrop_url"]; has {
		t.Error("the backdrop is still behind the hero")
	}
}
