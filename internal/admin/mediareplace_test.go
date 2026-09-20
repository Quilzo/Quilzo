// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
)

func pic(id, name string, kind media.Kind) media.File {
	return media.File{ID: id, Name: name, Kind: kind, Format: "png"}
}

func TestOnlyTheSameKindMayStandIn(t *testing.T) {
	// A video offered as a replacement for a picture would leave every page
	// rendering an <img> at a file no browser draws — the page looks broken
	// rather than wrong, which is the harder failure to diagnose.
	files := []media.File{
		pic("a", "one.png", media.Image),
		pic("b", "two.png", media.Image),
		pic("c", "film.mp4", media.Video),
	}
	got := replacementsFor(files)
	for _, f := range got["a"] {
		if f.Kind != media.Image {
			t.Errorf("a %s was offered as a replacement for a picture", f.Kind)
		}
		if f.ID == "a" {
			t.Error("a picture was offered as a replacement for itself")
		}
	}
	if len(got["a"]) != 1 || got["a"][0].ID != "b" {
		t.Fatalf("the choices for one.png are %v", got["a"])
	}
	if len(got["c"]) != 0 {
		t.Fatalf("the only video was offered %d replacement(s)", len(got["c"]))
	}
}

func TestANarrowerCopyIsNeverOfferedNorAsked(t *testing.T) {
	// A rendition is not an answer to "which picture goes on this page". It
	// exists only for its parent, and replacing one would leave a srcset
	// candidate the browser may pick pointing somewhere else.
	files := []media.File{
		pic("a", "one.png", media.Image),
		pic("b", "two.png", media.Image),
	}
	small := pic("a480", "one-480.png", media.Image)
	small.RenditionOf = "a"
	files = append(files, small)

	got := replacementsFor(files)
	if _, offered := got["a480"]; offered {
		t.Error("a narrower copy was given a replacement control of its own")
	}
	for _, f := range got["a"] {
		if f.RenditionOf != "" {
			t.Errorf("%s is a narrower copy and was offered as a replacement",
				f.Name)
		}
	}
}

func TestTheChoicesAreInAStableOrder(t *testing.T) {
	// The list is built from a map of kinds, and a control whose options move
	// between page loads is a control somebody mis-clicks.
	files := []media.File{
		pic("a", "zebra.png", media.Image),
		pic("b", "apple.png", media.Image),
		pic("c", "mango.png", media.Image),
	}
	for range 8 {
		got := replacementsFor(files)["a"]
		var names []string
		for _, f := range got {
			names = append(names, f.Name)
		}
		if strings.Join(names, ",") != "apple.png,mango.png" {
			t.Fatalf("the choices came back as %v", names)
		}
	}
}

func TestBothDirectionsOfASuccessionAreAvailable(t *testing.T) {
	// Supersedes points backwards, so a reader looking at the retired picture
	// cannot tell it was retired. That is the whole reason to record it, and
	// the listing needs the other direction worked out for it.
	a := pic("a", "old.png", media.Image)
	b := pic("b", "new.png", media.Image)
	b.Supersedes = "a"
	got := supersededBy([]media.File{a, b})
	if len(got["a"]) != 1 || got["a"][0] != "new.png" {
		t.Fatalf("old.png is recorded as replaced by %v", got["a"])
	}
	if len(got["b"]) != 0 {
		t.Fatalf("the replacement is itself recorded as replaced: %v", got["b"])
	}
}

func TestTwoReplacementsOfOneFileAreBothNamedInOrder(t *testing.T) {
	// Nothing stops it: retire a picture, then retire it again with something
	// else. A listing naming whichever came first out of a map would read
	// differently each time it was loaded.
	a := pic("a", "old.png", media.Image)
	b := pic("b", "zebra.png", media.Image)
	c := pic("c", "apple.png", media.Image)
	b.Supersedes, c.Supersedes = "a", "a"
	for range 8 {
		got := supersededBy([]media.File{a, b, c})
		if strings.Join(got["a"], ",") != "apple.png,zebra.png" {
			t.Fatalf("named as %v", got["a"])
		}
	}
}

func TestTheTwoSurfacesRefuseTheSameThings(t *testing.T) {
	// The command line has its own copy of these refusals, because one
	// returns an error a terminal prints and the other one a redirect
	// carries. What must not differ is the set — a substitution the browser
	// allows and the terminal refuses is a rule that depends on which door
	// somebody used.
	lib := libraryFor(t)
	one := putPicture(t, lib, "one.png", 0x10)
	two := putPicture(t, lib, "two.png", 0x20)

	if err := checkReplacement(lib, one, one); err == nil {
		t.Error("a file was allowed to replace itself")
	}
	film := two
	film.Kind = media.Video
	if err := checkReplacement(lib, one, film); err == nil {
		t.Error("a video was allowed to replace a picture")
	}
	if err := checkReplacement(lib, one, two); err != nil {
		t.Errorf("an ordinary replacement was refused: %v", err)
	}
}

// libraryFor is a real library, because the succession walk reads one.
func libraryFor(t *testing.T) *medialib.Library {
	t.Helper()
	lib, err := medialib.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return lib
}

// putPicture stores a genuinely decodable PNG.
//
// The library re-decodes on the way in rather than trusting a caller, so a
// test storing a few bytes of nonsense would be testing nothing this program
// does.
func putPicture(t *testing.T, lib *medialib.Library, name string, shade uint8) media.File {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for x := range 8 {
		for y := range 8 {
			img.Set(x, y, color.RGBA{shade, uint8(x * 8), uint8(y * 8), 0xff})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	body := b.Bytes()
	f := media.File{
		ID: fmt.Sprintf("%x", sha256.Sum256(body)), Name: name,
		Kind: media.Image, Format: "png", Alt: "a picture",
		Size: int64(len(body)),
	}
	if err := lib.Put(f, body); err != nil {
		t.Fatalf("storing %s: %v", name, err)
	}
	got, err := lib.Stat(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
