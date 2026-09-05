package media_test

import (
	"os"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/media"
)

// The fixtures are real AVIF files, encoded by libavif and committed, not
// hand-assembled here. A container written by the same reasoning that reads it
// proves only that the reasoning is self-consistent — which is exactly how a
// JPEG framing bug in internal/c2pa survived a passing round-trip until a
// third-party reader disagreed.
//
// They are a few kilobytes. Regenerate with Pillow if the format ever needs a
// different shape:
//
//	Image.new("RGB", (320, 200)).save("sample.avif", format="AVIF")
func avifFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("the AVIF fixture is missing: %v", err)
	}
	return b
}

// A real AVIF is accepted, and arrives knowing how big it is.
//
// The dimensions are the point. Go decodes no AVIF, so without reading them
// out of the container the file stores as 0x0 — and the templates emit
// intrinsic sizes from those numbers, so the format that exists to make a page
// fast would be the one that makes it jump as the picture lands.
func TestARealAVIFIsAcceptedWithItsDimensions(t *testing.T) {
	body := avifFixture(t, "sample.avif")

	f, err := media.Accept("photo.avif", body, time.Unix(1787000000, 0))
	if err != nil {
		t.Fatalf("a real AVIF was refused: %v", err)
	}
	if f.Format != "avif" {
		t.Errorf("identified as %q", f.Format)
	}
	if f.Kind != media.Image {
		t.Errorf("kind is %q", f.Kind)
	}
	if f.Width != 320 || f.Height != 200 {
		t.Errorf("dimensions are %dx%d, want 320x200. A stored zero means "+
			"no intrinsic size on the page and a reflow as it loads",
			f.Width, f.Height)
	}
	if f.MIME() != "image/avif" {
		t.Errorf("served as %q", f.MIME())
	}
}

// A small one, so the walk is not relying on a particular box order or on
// there being lots of data after the header.
func TestASmallAVIFAlsoReportsItsSize(t *testing.T) {
	body := avifFixture(t, "tiny.avif")

	f, err := media.Accept("tiny.avif", body, time.Unix(1787000000, 0))
	if err != nil {
		t.Fatalf("a small AVIF was refused: %v", err)
	}
	if f.Width != 64 || f.Height != 48 {
		t.Errorf("dimensions are %dx%d, want 64x48", f.Width, f.Height)
	}
}

// Something that is not an AVIF must not be stored as one.
func TestThingsThatAreNotAVIFAreRefused(t *testing.T) {
	for name, body := range map[string][]byte{
		"empty":           {},
		"a text file":     []byte("this is not a picture at all, not even close"),
		"a truncated one": avifFixture(t, "tiny.avif")[:12],
	} {
		if _, err := media.Accept("x.avif", body, time.Now()); err == nil {
			t.Errorf("%s was accepted as an AVIF", name)
		}
	}
}

// An AVIF whose declared box length runs past the end of the file must be
// refused rather than read past.
func TestAnAVIFThatLiesAboutItsLengthIsRefused(t *testing.T) {
	body := append([]byte(nil), avifFixture(t, "tiny.avif")...)
	// The ftyp box claims the whole file and more.
	body[0], body[1], body[2], body[3] = 0xff, 0xff, 0xff, 0xff

	if _, err := media.Accept("x.avif", body, time.Now()); err == nil {
		t.Error("an AVIF claiming a box larger than the file was accepted")
	}
}

// A box that declares zero length means "to the end" in ISOBMFF, and a walk
// that does not handle it loops forever — a denial of service costing one
// upload. This is the shape, checked for termination rather than for a result.
func TestAZeroLengthBoxDoesNotHang(t *testing.T) {
	body := append([]byte(nil), avifFixture(t, "tiny.avif")...)
	// Zero the length of the box after ftyp, whatever it is.
	size := int(body[0])<<24 | int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if size+4 < len(body) {
		body[size], body[size+1], body[size+2], body[size+3] = 0, 0, 0, 0
	}

	done := make(chan struct{})
	go func() {
		_, _ = media.Accept("x.avif", body, time.Now())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reading an AVIF with a zero-length box did not terminate")
	}
}
