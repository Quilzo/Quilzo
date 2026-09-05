package medialib_test

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
)

func wideImage(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1400, 900))
	for x := 0; x < 1400; x++ {
		for y := 0; y < 900; y++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 0x40, 0xff})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// A narrower copy of a picture a model made is still a picture a model made.
//
// The rendition inherits the alt text, the licence and the import source, on
// the reasoning that it is the same picture. Where it came from was the one
// field that argument was not applied to — so the disclosure was intact on the
// original and absent from the 480-wide copy, which is the file a phone
// actually downloads. The version most people receive was the version that
// said nothing.
func TestARenditionKeepsTheDisclosure(t *testing.T) {
	dir := t.TempDir()
	lib, err := medialib.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	body := wideImage(t)
	f, err := media.Accept("meadow.png", body, time.Unix(1787000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "a meadow at dusk"
	f.Origin = media.Origin{
		SourceType: "trainedAlgorithmicMedia",
		Model:      "claude-opus-5",
		Author:     "Rashik",
	}
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}

	stored, err := lib.Stat(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Renditions) == 0 {
		t.Fatal("no narrower copies were made, so this proves nothing")
	}

	for _, r := range stored.Renditions {
		child, serr := lib.Stat(r.ID)
		if serr != nil {
			t.Fatal(serr)
		}
		if child.Origin.SourceType != "trainedAlgorithmicMedia" {
			t.Errorf("the %dw copy declares %q; the disclosure is lost on the "+
				"file a phone downloads", r.Width, child.Origin.SourceType)
		}
		if child.Origin.Model != "claude-opus-5" {
			t.Errorf("the %dw copy names model %q", r.Width, child.Origin.Model)
		}
		if child.RenditionOf != f.ID {
			t.Errorf("the %dw copy does not name its parent", r.Width)
		}
	}
}

// A rendition of an ordinary photograph declares nothing, because nothing was
// declared about the original. Inheriting must not invent.
func TestARenditionOfAnUndeclaredImageStaysUndeclared(t *testing.T) {
	dir := t.TempDir()
	lib, err := medialib.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	body := wideImage(t)
	f, err := media.Accept("photo.png", body, time.Unix(1787000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "a photograph"
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}
	stored, _ := lib.Stat(f.ID)
	for _, r := range stored.Renditions {
		child, _ := lib.Stat(r.ID)
		if child.Origin.Declared() {
			t.Errorf("the %dw copy of an undeclared photograph declares %+v",
				r.Width, child.Origin)
		}
	}
}
