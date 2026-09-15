// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
)

// withPicture wires a library holding one image and returns its id.
func withPicture(t *testing.T, srv *Server) string {
	t.Helper()
	lib, err := medialib.Open(filepath.Join(t.TempDir(), "media"))
	if err != nil {
		t.Fatal(err)
	}
	body := bigPNG(t)
	f, err := media.Accept("shot.png", body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "a test photograph"
	f.Rights = media.Rights{Licence: "cc-by-4.0", Holder: "a photographer"}
	f.Origin = media.Origin{SourceType: "trainedAlgorithmicMedia", Model: "a-model"}
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}
	srv.Media = &Media{
		Library: func() (*medialib.Library, error) { return lib, nil },
		Options: func() media.Options { return media.Options{} },
	}
	return f.ID
}

func countFiles(t *testing.T, srv *Server) int {
	t.Helper()
	lib, err := srv.Media.Library()
	if err != nil {
		t.Fatal(err)
	}
	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	return len(files)
}

// The screen offers shapes rather than a canvas.
//
// The policy on this response permits no script, so there are no drag handles
// and no marching ants. A ratio is the one part of a crop people know the
// answer to before they open the screen.
func TestTheCropScreenOffersShapes(t *testing.T) {
	srv, token := setup(t)
	id := withPicture(t, srv)

	html := get(t, srv, "/media/edit?id="+id, token).Body.String()
	for _, want := range []string{
		"16:9", "1:1", "Leave the shape alone", "Cut an exact rectangle instead",
		"Take the colour out",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the screen does not offer %q", want)
		}
	}
	// Nothing to keep until there is something to look at.
	if strings.Contains(html, "Keep this copy") {
		t.Error("it offers to keep a copy before anything has been shown")
	}
}

// Asking to see a crop puts the recipe in the address and stores nothing.
//
// The preview has to be a GET that can be reloaded, and a request that stores
// a file because somebody reloaded a page is a request that fills a library.
func TestAskingToSeeACropStoresNothing(t *testing.T) {
	srv, token := setup(t)
	id := withPicture(t, srv)
	before := countFiles(t, srv)

	w := postForm(t, srv, "/media/edit", token,
		"id="+id+"&aspect=16%3A9&grey=1")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("asking to see it answered %d, want a redirect", w.Code)
	}
	to := w.Header().Get("Location")
	for _, want := range []string{"aspect=16%3A9", "grey=1", "id=" + id} {
		if !strings.Contains(to, want) {
			t.Errorf("the address does not carry %q: %s", want, to)
		}
	}
	if got := countFiles(t, srv); got != before {
		t.Errorf("%d files became %d without anybody keeping one", before, got)
	}

	// And the page it lands on shows the picture and offers to keep it.
	html := get(t, srv, to, token).Body.String()
	if !strings.Contains(html, "/media/edit/preview?") {
		t.Error("the page shows no preview")
	}
	if !strings.Contains(html, "Keep this copy") {
		t.Error("the page does not offer to keep it")
	}
}

// The preview derives real bytes and is never cached.
//
// Never stored, so never cached: the bytes exist for the length of one
// response, and a copy in a proxy would outlive the question it answered.
func TestThePreviewDerivesAndIsNotCached(t *testing.T) {
	srv, token := setup(t)
	id := withPicture(t, srv)
	before := countFiles(t, srv)

	w := get(t, srv, "/media/edit/preview?id="+id+"&aspect=16%3A9", token)
	if w.Code != http.StatusOK {
		t.Fatalf("the preview answered %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("it is served as %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control is %q; a preview nobody stored must not be "+
			"kept by anybody either", cc)
	}
	if w.Body.Len() < 100 {
		t.Errorf("the preview is %d bytes, which is not a picture", w.Body.Len())
	}
	if got := countFiles(t, srv); got != before {
		t.Errorf("looking at a preview stored %d file(s)", got-before)
	}
	// A recipe that does nothing has nothing to derive, and says so rather
	// than serving the original under a name that says it was edited.
	if w := get(t, srv, "/media/edit/preview?id="+id, token); w.Code != 400 {
		t.Errorf("an empty recipe answered %d", w.Code)
	}
}

// Keeping stores a copy, and the original is exactly where it was.
func TestKeepingStoresACopyAndLeavesTheOriginal(t *testing.T) {
	srv, token := setup(t)
	id := withPicture(t, srv)

	w := postForm(t, srv, "/media/edit", token,
		"id="+id+"&aspect=16%3A9&keep=1")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("keeping answered %d: %s", w.Code, w.Body.String())
	}

	lib, err := srv.Media.Library()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := lib.Get(id); err != nil {
		t.Errorf("the original is gone: %v", err)
	}
	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	var copy *media.File
	for i := range files {
		if files[i].EditOf == id {
			copy = &files[i]
		}
	}
	if copy == nil {
		t.Fatal("nothing was stored as a copy of it")
	}
	// Everything that has to travel with it. See internal/medialib/edit.go.
	if copy.Rights.Licence != "cc-by-4.0" {
		t.Errorf("the copy's licence is %q", copy.Rights.Licence)
	}
	if copy.Origin.SourceType != "trainedAlgorithmicMedia" {
		t.Errorf("the copy declares %q; a crop of a generated picture is "+
			"still generated", copy.Origin.SourceType)
	}
	if copy.Alt != "a test photograph" {
		t.Errorf("the copy's description is %q", copy.Alt)
	}
	if copy.Edit == nil || copy.Edit.Aspect != "16:9" {
		t.Errorf("the copy does not record what was done: %+v", copy.Edit)
	}
}

// A description can be changed on the way, because a crop sometimes shows
// something different from the picture it came out of.
func TestTheCopysDescriptionCanBeChanged(t *testing.T) {
	srv, token := setup(t)
	id := withPicture(t, srv)

	if w := postForm(t, srv, "/media/edit", token,
		"id="+id+"&aspect=1%3A1&keep=1&alt=just+the+label"); w.Code != http.StatusSeeOther {
		t.Fatalf("keeping answered %d", w.Code)
	}
	lib, _ := srv.Media.Library()
	files, _ := lib.List()
	for _, f := range files {
		if f.EditOf == id && f.Alt != "just the label" {
			t.Errorf("the copy's description is %q", f.Alt)
		}
	}
}

// Half a box is refused rather than guessed at.
//
// Treating three numbers as a rectangle would crop somewhere nobody chose, and
// the picture that came back would look like the tool being wrong rather than
// the form being incomplete.
func TestHalfABoxIsRefused(t *testing.T) {
	srv, token := setup(t)
	id := withPicture(t, srv)

	html := get(t, srv, "/media/edit?id="+id+"&x=25&w=50", token).Body.String()
	if !strings.Contains(html, "all four numbers") {
		t.Error("a half-filled box was not explained")
	}
	if strings.Contains(html, "/media/edit/preview?") {
		t.Error("it offered a preview of a recipe it could not read")
	}
}

// A recipe that cannot be carried out is explained, not rendered as a broken
// picture.
func TestAnImpossibleCropIsExplained(t *testing.T) {
	srv, token := setup(t)
	id := withPicture(t, srv)

	html := get(t, srv,
		"/media/edit?id="+id+"&x=60&y=0&w=50&h=100", token).Body.String()
	if !strings.Contains(html, "outside the picture") {
		t.Error("a box running off the edge was not explained")
	}
	if strings.Contains(html, "/media/edit/preview?") {
		t.Error("it pointed an img at a recipe the deriver refuses")
	}
}

// A picture that is not there says so.
func TestEditingSomethingThatIsNotThere(t *testing.T) {
	srv, token := setup(t)
	withPicture(t, srv)

	html := get(t, srv,
		"/media/edit?id="+strings.Repeat("0", 64), token).Body.String()
	if !strings.Contains(html, "No such picture") {
		t.Error("an unknown id did not explain itself")
	}
}
