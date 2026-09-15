// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
)

// Every way an image gets into the library runs it through the pipeline.
//
// internal/media states the property flatly: re-encoding "makes this a
// property of the pipeline rather than a filter somebody has to remember."
// A property of the pipeline has to be in the pipeline. It was not — `quilzo
// media get` called Accept and then Put and no optimiser at all, so the one
// path that ingests a file from somebody else's server stored a photograph
// unresized with its EXIF intact. GPS coordinates and a camera serial number,
// published, on the surface where the uploader is a stranger.
//
// It was written without the optimiser because the settings were read in four
// places and a fifth caller simply did not repeat them. A source walk, because
// this is exactly the kind of thing that is correct when written and forgotten
// when the next entrance is added.
func TestEveryImageEntranceRunsTheOptimiser(t *testing.T) {
	// The function that stores an image, and what surface it is.
	entrances := map[string]string{
		"mediaAdd": "quilzo media add",
		"mediaGet": "quilzo media get",
		"Save":     "the chat surfaces, through chatMedia.Save",
	}
	found := map[string]bool{}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, e.Name(), nil, 0)
		if perr != nil {
			t.Fatalf("%s: %v", e.Name(), perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			if _, wanted := entrances[fn.Name.Name]; !wanted {
				return true
			}
			var calls []string
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				sel, ok := inner.(*ast.SelectorExpr)
				if ok {
					calls = append(calls, sel.Sel.Name)
				}
				return true
			})
			for _, c := range calls {
				if c == "Optimise" {
					found[fn.Name.Name] = true
				}
			}
			return true
		})
	}

	if len(found) == 0 {
		t.Fatal("no entrance was parsed at all; the walk is wrong and this " +
			"test would pass by checking nothing")
	}
	var missing []string
	for name, what := range entrances {
		if !found[name] {
			missing = append(missing, name+" — "+what)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s stores an image without running media.Optimise. That "+
			"path publishes a photograph's GPS coordinates, and it is the "+
			"one nobody notices", m)
	}
}

// The settings are read in one place, so a new entrance cannot read three of
// the five keys.
func TestTheOptimiserSettingsAreReadInOnePlace(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var elsewhere []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			e.Name() == "mediaopts.go" ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body, rerr := os.ReadFile(e.Name())
		if rerr != nil {
			t.Fatal(rerr)
		}
		if strings.Contains(string(body), `"media.max_width"`) {
			elsewhere = append(elsewhere, e.Name())
		}
	}
	sort.Strings(elsewhere)
	for _, f := range elsewhere {
		t.Errorf("%s reads the optimiser settings itself. They live in "+
			"mediaOptions, because four copies of the same five keys is how "+
			"the fifth caller came to be written with none of them", f)
	}
}

// media.strip_metadata reaches the optimiser.
//
// It was declared with a Weaker clause and the NIST controls SI-12 and PM-30,
// and read by nothing at all: setting it to false changed no behaviour. A
// control that appears in the posture report and does nothing is a claim the
// product does not keep, which is the worst-shaped bug available to a project
// whose argument is that the documented behaviour and the real behaviour are
// the same thing.
func TestStripMetadataIsActuallyRead(t *testing.T) {
	c := config.New()
	if opt := mediaOptions(c); opt.KeepMetadata {
		t.Error("the default keeps metadata; it is documented as removing it")
	}
	if err := c.Set("media.strip_metadata", "false",
		"a photography site keeps its capture data", "test"); err != nil {
		t.Fatal(err)
	}
	if opt := mediaOptions(c); !opt.KeepMetadata {
		t.Error("turning media.strip_metadata off changed nothing, which is " +
			"the state this test exists to end")
	}
}

// An unreadable configuration is the defaults, not an empty Options.
//
// media.Options{} means no maximum width, which would store a
// six-thousand-pixel photograph because a file had a syntax error in it.
func TestABadConfigStillOptimises(t *testing.T) {
	opt := mediaOptionsAt(t.TempDir())
	if opt.MaxWidth <= 0 {
		t.Errorf("MaxWidth is %d, so a site with no config stores every "+
			"photograph at full size", opt.MaxWidth)
	}
	if opt.KeepMetadata {
		t.Error("a site with no config keeps EXIF")
	}
}

// A photograph sent to the bot is stored without its metadata, even when the
// stripped copy is not smaller.
//
// The bug this forbids was a size test. Optimise deliberately keeps a
// re-encode that came out a few bytes larger when metadata had to go —
// "because the point there was never the size" — and the chat surface threw
// that away with `len(opt.Body) < len(body)`. So a photograph whose stripped
// copy did not happen to shrink kept its GPS coordinates, on the one surface
// where the file arrives straight out of somebody's phone.
func TestAPhotographSentToTheBotLosesItsMetadata(t *testing.T) {
	dir := t.TempDir()
	lib, err := medialib.Open(filepath.Join(dir, "media"))
	if err != nil {
		t.Fatal(err)
	}
	m := &chatMedia{root: dir, lib: lib, cfg: config.New()}

	body := jpegWithGPS(t)
	if !bytes.Contains(body, []byte("GPSLatitude")) {
		t.Fatal("the fixture carries no coordinates, so this checks nothing")
	}
	id, _, err := m.Save("someone", "photo.jpg", body, "a photograph")
	if err != nil {
		t.Fatal(err)
	}
	_, stored, err := lib.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("GPSLatitude")) {
		t.Error("the stored photograph still carries the coordinates it " +
			"arrived with")
	}
	if bytes.Contains(stored, []byte("Exif")) {
		t.Error("the stored photograph still carries an EXIF segment")
	}
}

// jpegWithGPS is a JPEG carrying an APP1 segment with coordinates in it, built
// so that re-encoding it makes it BIGGER.
//
// That is the whole point of the fixture. Noise at quality 20 re-encoded at
// the pipeline's default of 82 grows by several kilobytes, so removing
// fifty-eight bytes of EXIF still leaves a larger file — which is exactly the
// case the old `len(opt.Body) < len(body)` test rejected, keeping the original
// and publishing the coordinates. A fixture that shrinks would let the bug
// pass.
func jpegWithGPS(t *testing.T) []byte {
	t.Helper()
	const w, h = 160, 120
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	seed := uint32(0x2545f491)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			seed ^= seed << 13
			seed ^= seed >> 17
			seed ^= seed << 5
			img.Set(x, y, color.RGBA{R: uint8(seed), G: uint8(seed >> 8),
				B: uint8(seed >> 16), A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 20}); err != nil {
		t.Fatal(err)
	}
	plain := buf.Bytes()

	payload := append([]byte("Exif\x00\x00"),
		[]byte("GPSLatitude=51.5074 GPSLongitude=-0.1278 Serial=ABC123")...)
	seg := []byte{0xFF, 0xE1,
		byte((len(payload) + 2) >> 8), byte((len(payload) + 2) & 0xFF)}
	seg = append(seg, payload...)

	out := append([]byte{}, plain[:2]...)
	out = append(out, seg...)
	out = append(out, plain[2:]...)

	// The fixture has to be the hard case or the test is decoration.
	opt, err := media.Optimise("jpeg", out, mediaOptions(config.New()))
	if err != nil {
		t.Fatal(err)
	}
	if len(opt.Body) <= len(out) {
		t.Fatalf("the stripped copy is %d bytes against %d: this fixture "+
			"shrinks, so it would pass against the size test that caused the "+
			"bug", len(opt.Body), len(out))
	}
	return out
}
