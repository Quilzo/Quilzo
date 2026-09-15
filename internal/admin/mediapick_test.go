// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/site"
)

// A photograph-shaped PNG: wide enough to have narrower copies, and noisy
// enough that they are smaller than it.
//
// Both halves are needed, and the second is the one that is easy to miss. A
// rendition is discarded when it is not smaller than its source, so a
// thousand-pixel image of a smooth gradient compresses to twenty kilobytes and
// produces no renditions at all — which made the test that walks them pass by
// walking nothing. Deterministic noise, so the bytes are the same every run.
func bigPNG(t *testing.T) []byte {
	t.Helper()
	const w, h = 900, 600
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	seed := uint32(0x9e3779b9)
	next := func() uint8 {
		seed ^= seed << 13
		seed ^= seed >> 17
		seed ^= seed << 5
		return uint8(seed)
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: next(), G: next(), B: next(), A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// withLibrary wires a media library holding one image, and puts a video
// section on the index page so there is somewhere to put it.
func withLibrary(t *testing.T, srv *Server) string {
	t.Helper()
	lib, err := medialib.Open(filepath.Join(t.TempDir(), "media"))
	if err != nil {
		t.Fatal(err)
	}
	shot := bigPNG(t)
	f, err := media.Accept("shot.png", shot, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "a test photograph"
	if err := lib.Put(f, shot); err != nil {
		t.Fatal(err)
	}
	srv.Media = &Media{
		Library: func() (*medialib.Library, error) { return lib, nil },
		Options: func() media.Options { return media.Options{} },
	}

	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	body, err := section.Insert(pages["index"], "video", 0)
	if err != nil {
		t.Fatal(err)
	}
	pages["index"] = body
	if _, err := site.SaveDraft(srv.Store, pages, "a video section", "test"); err != nil {
		t.Fatal(err)
	}
	return f.ID
}

// The picker offers the files a field can actually hold.
//
// The gap it closes: a media id is the SHA-256 of the file's bytes, and
// attaching a photograph through the browser meant copying sixty-four
// hexadecimal characters from one screen to another. Everything else about the
// page builder works without a mouse; this one field asked for a feat of
// transcription.
func TestThePickerOffersTheLibrary(t *testing.T) {
	srv, token := setup(t)
	id := withLibrary(t, srv)

	html := get(t, srv,
		"/media/pick?page=index&at=0&path=poster", token).Body.String()

	if !strings.Contains(html, `value="/media/`+id+`"`) {
		t.Error("the stored image is not offered")
	}
	if !strings.Contains(html, `src="/media/file/`+id+`"`) {
		t.Error("the image is offered without a thumbnail, so it is a hash again")
	}
	if !strings.Contains(html, "Choose an image") {
		t.Errorf("the heading does not name the kind with its article")
	}
	// "Nothing" is a choice, because taking a picture off a section is as
	// ordinary as putting one on.
	if !strings.Contains(html, `name="v.poster" value=""`) {
		t.Error("there is no way to choose nothing")
	}
}

// A field wants one kind of file, and is offered that kind.
//
// A video section's src takes a video. Offering the library's photographs
// there would produce a player pointed at a PNG, which fails silently in the
// browser and is exactly the mistake the picker exists to prevent.
func TestThePickerFiltersToTheFieldsKind(t *testing.T) {
	srv, token := setup(t)
	id := withLibrary(t, srv)

	html := get(t, srv,
		"/media/pick?page=index&at=0&path=src", token).Body.String()

	if strings.Contains(html, id) {
		t.Error("an image was offered for a video field")
	}
	if !strings.Contains(html, "There is no") {
		t.Error("an empty library says nothing about being empty")
	}
}

// Renditions are not offered.
//
// Every image in this library has narrower copies stored beside it under their
// own hashes. Listing them would put the same photograph on the screen four
// times and let somebody attach the 480-wide one to a full-width hero.
func TestThePickerDoesNotOfferRenditions(t *testing.T) {
	srv, token := setup(t)
	withLibrary(t, srv)

	lib, err := srv.Media.Library()
	if err != nil {
		t.Fatal(err)
	}
	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	html := get(t, srv,
		"/media/pick?page=index&at=0&path=poster", token).Body.String()

	narrower := 0
	for _, f := range files {
		if f.RenditionOf == "" {
			continue
		}
		narrower++
		if strings.Contains(html, `value="/media/`+f.ID+`"`) {
			t.Errorf("rendition %s is offered as though it were a file "+
				"somebody chose to upload", f.ID[:12])
		}
	}
	if narrower == 0 {
		t.Fatal("the library stored no renditions, so this test checked " +
			"nothing at all")
	}
}

// What the field holds now is marked, so the screen says where you are.
func TestThePickerMarksTheCurrentChoice(t *testing.T) {
	srv, token := setup(t)
	id := withLibrary(t, srv)

	// Choose it, through the ordinary save path the picker posts to.
	base := srv.Store.GetRef(site.RefDraft)
	if w := postForm(t, srv, "/sections/fields", token,
		"page=index&at=0&base="+base+"&v.poster=/media/"+id); w.Code >= 400 {
		t.Fatalf("choosing answered %d", w.Code)
	}

	html := get(t, srv,
		"/media/pick?page=index&at=0&path=poster", token).Body.String()
	if !strings.Contains(html, "pick-on") {
		t.Error("nothing on the grid is marked as the current choice")
	}
	if strings.Contains(html, `name="v.poster" value="" checked`) {
		t.Error("\"Nothing\" is checked although a picture is attached")
	}
}

// Choosing a picture disturbs nothing else on the section.
//
// The picker posts one value to the endpoint the whole edit form posts to.
// That is only safe because section.Apply touches the paths it is given and no
// others — if it rebuilt the section from the form, picking a poster would
// erase the title, the caption and the video beside it.
func TestChoosingAFileLeavesTheRestOfTheSectionAlone(t *testing.T) {
	srv, token := setup(t)
	id := withLibrary(t, srv)

	base := srv.Store.GetRef(site.RefDraft)
	if w := postForm(t, srv, "/sections/fields", token,
		"page=index&at=0&base="+base+"&v.poster=/media/"+id); w.Code >= 400 {
		t.Fatalf("choosing answered %d", w.Code)
	}

	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := section.Fields(pages["index"], 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range fields {
		got[f.Path] = f.Value
	}
	if got["poster"] != "/media/"+id {
		t.Errorf("poster is %q", got["poster"])
	}
	if got["title"] == "" {
		t.Error("the title was cleared by choosing a poster")
	}
	if got["caption"] == "" {
		t.Error("the caption was cleared by choosing a poster")
	}
}

// A path this section does not have is refused, not drawn.
//
// section.Apply will not create a field that is not already there, so a picker
// for such a path is a screen where choosing a photograph appears to work and
// changes nothing.
func TestThePickerRefusesAFieldTheSectionDoesNotHave(t *testing.T) {
	srv, token := setup(t)
	withLibrary(t, srv)

	html := get(t, srv,
		"/media/pick?page=index&at=0&path=audio", token).Body.String()
	if !strings.Contains(html, "Nothing to fill") {
		t.Error("a picker was drawn for a field the video section has no room for")
	}
	if strings.Contains(html, `name="v.audio"`) {
		t.Error("the refusal still rendered a form that writes")
	}
}

// A field that names no file at all has nothing to pick.
func TestThePickerRefusesAFieldThatIsNotAFile(t *testing.T) {
	srv, token := setup(t)
	withLibrary(t, srv)

	html := get(t, srv,
		"/media/pick?page=index&at=0&path=title", token).Body.String()
	if !strings.Contains(html, "Nothing to pick") {
		t.Error("the title field was offered a file picker")
	}
}

// The picker is a page-scoped screen, like everything else that edits a page.
//
// It reads a page out of the draft and writes to it, so an author confined to
// /blog must not be able to open it on a page outside that — otherwise the
// scope holds on the form and not on the screen that fills it in.
func TestThePickerIsScopedToThePage(t *testing.T) {
	srv, tok := scoped(t, auth.Binding{
		Principal: "bea", Role: auth.RoleAuthor, Resource: "/blog"})

	lib, err := medialib.Open(filepath.Join(t.TempDir(), "media"))
	if err != nil {
		t.Fatal(err)
	}
	srv.Media = &Media{
		Library: func() (*medialib.Library, error) { return lib, nil },
		Options: func() media.Options { return media.Options{} },
	}

	if w := get(t, srv, "/media/pick?page=legal/terms&at=0&path=image",
		tok["bea"]); w.Code != 403 {
		t.Errorf("the picker answered %d for a page outside the author's "+
			"scope; the deny binds on the form and not on the screen", w.Code)
	}
}
