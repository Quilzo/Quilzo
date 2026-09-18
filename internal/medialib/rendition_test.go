// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package medialib_test

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
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

// A stored recording learns what it is, and gets a still.
//
// Both here rather than at each call site, for the reason the renditions are
// here: this is the one place every interface passes through, and three
// surfaces each working out a video's dimensions their own way would be three
// implementations with two of them drifting.
func TestAStoredRecordingIsDescribed(t *testing.T) {
	bin, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("no ffmpeg here, which is a configuration this supports")
	}
	dir := t.TempDir()
	out := dir + "/clip.webm"
	if err := exec.Command(bin, "-v", "error", "-f", "lavfi",
		"-i", "testsrc=size=320x240:rate=10:duration=3",
		"-c:v", "libvpx", "-b:v", "100k", "-y", out).Run(); err != nil {
		t.Skipf("this ffmpeg cannot make the fixture: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	lib, err := medialib.Open(filepath.Join(t.TempDir(), "media"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := media.Accept("clip.webm", body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.Rights = media.Rights{Licence: "own-work", Holder: "somebody"}
	f.Origin = media.Origin{SourceType: "trainedAlgorithmicMedia", Model: "m"}
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}

	stored, err := lib.Stat(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Width != 320 || stored.Height != 240 {
		t.Errorf("the recording is stored as %dx%d; a page carrying it "+
			"emits no intrinsic size and reflows as it arrives",
			stored.Width, stored.Height)
	}
	if stored.Seconds < 2.5 {
		t.Errorf("it is stored as %.2f seconds long", stored.Seconds)
	}
	if stored.Poster == "" {
		t.Fatal("no poster was taken, so a player shows a black rectangle " +
			"until enough has loaded to draw a frame")
	}

	poster, err := lib.Stat(stored.Poster)
	if err != nil {
		t.Fatal(err)
	}
	if poster.PosterOf != f.ID {
		t.Error("the still does not name the recording it came from, so a " +
			"listing cannot tell it from a photograph somebody chose")
	}
	if poster.Alt == "" {
		t.Error("the still has no description, and an image without one " +
			"cannot go on a page at all")
	}
	if poster.Rights.Licence != "own-work" {
		t.Errorf("the still's licence is %q; a frame of a licensed recording "+
			"is covered by the same permission", poster.Rights.Licence)
	}
	// A still from a generated recording is generated. Same rule as a crop:
	// dropping it would be a way to launder generated content into an
	// undeclared file.
	if poster.Origin.SourceType != "trainedAlgorithmicMedia" {
		t.Errorf("the still declares %q", poster.Origin.SourceType)
	}
}

// With nothing on the machine to read a recording, it is stored anyway.
func TestARecordingStoresWithNoTools(t *testing.T) {
	t.Setenv("PATH", "/nonexistent")
	lib, err := medialib.Open(filepath.Join(t.TempDir(), "media"))
	if err != nil {
		t.Fatal(err)
	}
	// A structurally valid WebM header is all Accept requires.
	body := append([]byte{0x1A, 0x45, 0xDF, 0xA3}, []byte("webm")...)
	body = append(body, make([]byte, 2048)...)
	f, err := media.Accept("clip.webm", body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(f, body); err != nil {
		t.Fatalf("a recording could not be stored without ffmpeg: %v", err)
	}
	stored, err := lib.Stat(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Width != 0 || stored.Seconds != 0 || stored.Poster != "" {
		t.Errorf("something was claimed about a recording nothing read: %+v",
			stored)
	}
}
