// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

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

// picture is a small, genuinely decodable PNG.
//
// The library re-decodes on the way in rather than trusting a caller, so a
// test that stored a few bytes of nonsense would be testing nothing this
// program does.
func picture(t *testing.T, shade uint8) []byte {
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
	return b.Bytes()
}

// stored puts a file in a library and returns its record.
func stored(t *testing.T, lib *medialib.Library, name string,
	kind media.Kind, body []byte) media.File {

	t.Helper()
	f := media.File{
		ID: fmt.Sprintf("%x", sha256.Sum256(body)), Name: name, Kind: kind,
		Format: "png", Alt: "a picture", Size: int64(len(body)),
	}
	if err := lib.Put(f, body); err != nil {
		t.Fatalf("storing %s: %v", name, err)
	}
	got, err := lib.Stat(f.ID)
	if err != nil {
		t.Fatalf("reading %s back: %v", name, err)
	}
	return got
}

func library(t *testing.T) *medialib.Library {
	t.Helper()
	lib, err := medialib.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return lib
}

func TestASuccessionIsRecordedOnTheReplacement(t *testing.T) {
	// Not on the file being retired. The old object cannot be rewritten —
	// different bytes are a different address — and a pointer written onto
	// the newer one is the direction that survives that.
	lib := library(t)
	old := stored(t, lib, "last-season.png", media.Image, picture(t, 0x10))
	next := stored(t, lib, "this-season.png", media.Image, picture(t, 0x20))

	if err := noteSuccession(lib, next, old.ID); err != nil {
		t.Fatal(err)
	}
	back, err := lib.Stat(next.ID)
	if err != nil {
		t.Fatal(err)
	}
	if back.Supersedes != old.ID {
		t.Fatalf("the replacement records %q as what it replaced",
			back.Supersedes)
	}
	// And the retired file is untouched, because nothing here is overwritten.
	if was, serr := lib.Stat(old.ID); serr != nil || was.Supersedes != "" {
		t.Fatalf("the retired file changed: %+v, %v", was.Supersedes, serr)
	}
}

func TestRecordingTheSameSuccessionTwiceIsNotAnError(t *testing.T) {
	lib := library(t)
	old := stored(t, lib, "a.png", media.Image, picture(t, 0x10))
	next := stored(t, lib, "b.png", media.Image, picture(t, 0x20))
	if err := noteSuccession(lib, next, old.ID); err != nil {
		t.Fatal(err)
	}
	again, _ := lib.Stat(next.ID)
	if err := noteSuccession(lib, again, old.ID); err != nil {
		t.Fatalf("recording the same fact twice failed: %v", err)
	}
}

func TestASuccessionChainIsAllowedAndALoopIsNot(t *testing.T) {
	// Season one to two to three is an ordinary history. Three back to one is
	// a walk with no end, and being able to walk it is the only reason to
	// record the relationship.
	lib := library(t)
	one := stored(t, lib, "one.png", media.Image, picture(t, 0x30))
	two := stored(t, lib, "two.png", media.Image, picture(t, 0x40))
	three := stored(t, lib, "three.png", media.Image, picture(t, 0x50))

	if err := noSuccessionLoop(lib, one.ID, two.ID); err != nil {
		t.Fatalf("a first replacement was refused: %v", err)
	}
	if err := noteSuccession(lib, two, one.ID); err != nil {
		t.Fatal(err)
	}
	two, _ = lib.Stat(two.ID)

	if err := noSuccessionLoop(lib, two.ID, three.ID); err != nil {
		t.Fatalf("a chain was refused: %v", err)
	}
	if err := noteSuccession(lib, three, two.ID); err != nil {
		t.Fatal(err)
	}

	// three -> two -> one. Retiring three in favour of one closes the loop.
	err := noSuccessionLoop(lib, three.ID, one.ID)
	if err == nil {
		t.Fatal("a succession loop was recorded; following it would not end")
	}
	if !strings.Contains(err.Error(), "loop") {
		t.Errorf("the refusal does not say what is wrong: %v", err)
	}
}

func TestAMissingLinkInAChainStopsTheWalkRatherThanFailing(t *testing.T) {
	// A file removed from the library leaves a Supersedes pointing at nothing.
	// That is a broken chain and not a loop, and refusing the replacement
	// because of it would make one removed file block every later one.
	lib := library(t)
	next := stored(t, lib, "b.png", media.Image, picture(t, 0x20))
	gone := strings.Repeat("a", 64)
	if err := noSuccessionLoop(lib, gone, next.ID); err != nil {
		t.Fatalf("a chain ending at a file that is no longer stored was "+
			"treated as a loop: %v", err)
	}
}
