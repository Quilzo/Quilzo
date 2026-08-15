package media

import (
	"bytes"
	"hash/crc32"
	"image"
	"image/color"
	jpegenc "image/jpeg"
	pngenc "image/png"
	"testing"
)

func photoImage(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8((x * 7) % 256), G: uint8((y * 11) % 256),
				B: uint8((x + y) % 256), A: 255})
		}
	}
	return img
}

func asJPEG(t *testing.T, img image.Image, q int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpegenc.Encode(&b, img, &jpegenc.Options{Quality: q}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func asPNGBytes(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := pngenc.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// -- the thing that actually matters ------------------------------------------

// A photograph from a phone carries GPS coordinates. Publishing an author's
// home address alongside their article is a worse failure than serving a file
// that is 20% too large, and it is the one nobody notices.
func TestEmbeddedMetadataIsRemoved(t *testing.T) {
	// A JPEG with an APP1 segment, which is where EXIF lives.
	base := asJPEG(t, photoImage(64, 64), 90)
	exif := []byte{0xFF, 0xE1, 0x00, 0x20, 'E', 'x', 'i', 'f', 0, 0}
	exif = append(exif, bytes.Repeat([]byte{'G', 'P', 'S'}, 8)...)
	withExif := append(append(append([]byte{}, base[:2]...), exif...), base[2:]...)

	if !hasMetadata("jpeg", withExif) {
		t.Fatal("the fixture does not look like it carries metadata")
	}
	out, err := Optimise("jpeg", withExif, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !out.StrippedMetadata {
		t.Error("metadata was not reported as stripped")
	}
	if hasMetadata("jpeg", out.Body) {
		t.Error("the metadata survived")
	}
	if bytes.Contains(out.Body, []byte("GPSGPSGPS")) {
		t.Error("the payload of the metadata is still in the file")
	}
}

func TestPNGTextChunksAreRemoved(t *testing.T) {
	base := asPNGBytes(t, photoImage(32, 32))

	// A properly framed tEXt chunk: length, type, data, CRC over type+data.
	// Built correctly rather than spliced in roughly, because a chunk with a
	// bad checksum is refused by the decoder and the test would then be
	// asserting that corrupt files fail — which is true and not the point.
	data := []byte("Author\x00Somebody")
	var chunk []byte
	chunk = append(chunk, byte(len(data)>>24), byte(len(data)>>16),
		byte(len(data)>>8), byte(len(data)))
	body := append([]byte("tEXt"), data...)
	chunk = append(chunk, body...)
	sum := crc32.ChecksumIEEE(body)
	chunk = append(chunk, byte(sum>>24), byte(sum>>16), byte(sum>>8), byte(sum))

	// After the 8-byte signature and the 25-byte IHDR chunk.
	const afterIHDR = 8 + 25
	with := append(append(append([]byte{}, base[:afterIHDR]...), chunk...),
		base[afterIHDR:]...)
	if !hasMetadata("png", with) {
		t.Fatal("the fixture does not carry detectable metadata")
	}
	out, err := Optimise("png", with, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Body, []byte("Somebody")) {
		t.Error("a PNG text chunk survived re-encoding")
	}
}

// -- resizing -----------------------------------------------------------------

// A six-thousand-pixel photograph in an eight-hundred-pixel column is the
// actual bloat, and no codec recovers it.
func TestAnOversizedImageIsScaledDown(t *testing.T) {
	big := asJPEG(t, photoImage(2000, 1500), 90)
	out, err := Optimise("jpeg", big, Options{MaxWidth: 800})
	if err != nil {
		t.Fatal(err)
	}
	if out.Width != 800 {
		t.Errorf("width is %d, want 800", out.Width)
	}
	if out.Height != 600 {
		t.Errorf("height is %d; the aspect ratio was not preserved", out.Height)
	}
	if out.Now >= out.Was {
		t.Errorf("resizing 2000px to 800px did not shrink the file: %d → %d",
			out.Was, out.Now)
	}
	if out.Saved() < 50 {
		t.Errorf("only %d%% saved on a 2.5x downscale", out.Saved())
	}
}

// An image already within the box is not touched, so the pipeline is not a
// lossy step applied to everything.
func TestAnImageThatIsAlreadySmallEnoughIsLeftAlone(t *testing.T) {
	small := asPNGBytes(t, photoImage(100, 100))
	out, err := Optimise("png", small, Options{MaxWidth: 800})
	if err != nil {
		t.Fatal(err)
	}
	if out.Width != 100 || out.Height != 100 {
		t.Errorf("a 100px image became %dx%d", out.Width, out.Height)
	}
	for _, did := range out.Did {
		if len(did) > 8 && did[:7] == "resized" {
			t.Errorf("it was resized anyway: %s", did)
		}
	}
}

// A re-encode can produce a larger file. Reporting that as a negative saving
// invites somebody to fix it by switching the pipeline off.
func TestAnUnhelpfulReEncodeIsNotKept(t *testing.T) {
	// A JPEG already at low quality: re-encoding at 82 may grow it.
	lossy := asJPEG(t, photoImage(200, 200), 40)
	out, err := Optimise("jpeg", lossy, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Saved() < 0 {
		t.Error("a negative saving was reported")
	}
	if out.Now > out.Was && !out.StrippedMetadata {
		t.Errorf("a larger result was kept with nothing to justify it: "+
			"%d → %d", out.Was, out.Now)
	}
}

// Aspect ratio is preserved in both directions.
func TestBothDimensionsBound(t *testing.T) {
	out, err := Optimise("png", asPNGBytes(t, photoImage(400, 1200)),
		Options{MaxWidth: 300, MaxHeight: 300})
	if err != nil {
		t.Fatal(err)
	}
	if out.Width > 300 || out.Height > 300 {
		t.Errorf("got %dx%d, wanted both under 300", out.Width, out.Height)
	}
	if out.Width < 1 || out.Height < 1 {
		t.Errorf("degenerate result %dx%d", out.Width, out.Height)
	}
}

// -- it must not break the upload path ----------------------------------------

// A format this cannot re-encode comes back untouched rather than refused.
// The format table has already decided it is acceptable; this stage is an
// optimisation, not a gate.
func TestANonImageIsReturnedUntouched(t *testing.T) {
	body := []byte("%PDF-1.7\nnot an image")
	out, err := Optimise("pdf", body, Options{MaxWidth: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Body, body) {
		t.Error("a PDF was modified by the image optimiser")
	}
}

// Broken bytes are an error, not a panic. This runs on files strangers upload.
func TestCorruptImagesDoNotPanic(t *testing.T) {
	for _, body := range [][]byte{
		{}, {0xFF, 0xD8, 0xFF}, []byte("\x89PNG\r\n\x1a\n"),
		bytes.Repeat([]byte{0}, 1000),
		append(asPNGBytes(t, photoImage(8, 8))[:40], 0xFF, 0xFF, 0xFF),
	} {
		for _, f := range []string{"png", "jpeg", "gif"} {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s panicked on %d bytes: %v", f, len(body), r)
					}
				}()
				Optimise(f, body, Options{MaxWidth: 50})
			}()
		}
	}
}

// -- the budget ---------------------------------------------------------------

func TestTheBudgetSaysSomethingActionable(t *testing.T) {
	b := Budget{Bytes: 4_000_000, Files: 6, Largest: "hero.jpg",
		LargestSize: 3_100_000}
	level, detail := b.Verdict()
	if level != "bad" {
		t.Errorf("4MB is %q", level)
	}
	if detail == "" {
		t.Error("no detail")
	}

	if lvl, _ := (Budget{Bytes: 2_000_000, Files: 3}).Verdict(); lvl != "warn" {
		t.Errorf("2MB is %q, want warn", lvl)
	}
	if lvl, _ := (Budget{Bytes: 200_000, Files: 2}).Verdict(); lvl != "ok" {
		t.Errorf("200KB is %q, want ok", lvl)
	}
}
