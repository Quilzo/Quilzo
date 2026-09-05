package media_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/big"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/c2pa"
	"github.com/quilzo/quilzo/internal/media"
)

func provenanceSigner(t *testing.T) ([][]byte, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "upstream"},
		NotBefore:    time.Unix(1787000000, 0),
		NotAfter:     time.Unix(1887000000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{der}, priv, pub
}

func bigPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 300, 300))
	for x := 0; x < 300; x++ {
		for y := 0; y < 300; y++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), uint8(x ^ y), 0xff})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func bigJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 300, 300))
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// An image that arrives carrying somebody else's provenance keeps it.
//
// The optimiser re-encodes, and a C2PA manifest is signed over the pixels. So
// re-encoding leaves two bad outcomes and no good one: keep the manifest and
// it no longer verifies, which reads as tampering rather than as a resize; or
// drop it and destroy a record a camera or a generator made, silently, as a
// side effect of saving a few kilobytes.
//
// This was the behaviour before: a signed PNG went in and came out with the
// manifest gone.
func TestAnImageWithAManifestIsNotReEncoded(t *testing.T) {
	chain, priv, pub := provenanceSigner(t)

	for name, original := range map[string][]byte{
		"png":  bigPNG(t),
		"jpeg": bigJPEG(t),
	} {
		format := name
		signed, err := c2pa.Embed(original, c2pa.Claim{
			Title: "upstream." + format, Format: "image/" + format,
			DigitalSourceType: "trainedAlgorithmicMedia",
			SoftwareAgent:     "SomeoneElse",
			When:              time.Unix(1787000000, 0),
		}, chain, priv)
		if err != nil {
			t.Fatal(err)
		}

		out, err := media.Optimise(format, signed, media.Options{
			MaxWidth: 100, MaxHeight: 100,
		})
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if !bytes.Equal(out.Body, signed) {
			t.Errorf("%s: a file carrying a manifest came back changed "+
				"(%d bytes in, %d out)", format, len(signed), len(out.Body))
			continue
		}
		if !out.KeptForProvenance {
			t.Errorf("%s: the file was kept but does not say why", format)
		}
		if _, err := c2pa.Verify(out.Body, pub); err != nil {
			t.Errorf("%s: the manifest no longer verifies after optimisation: %v",
				format, err)
		}
	}
}

// The control, and the thing that must not regress: an ordinary photo is still
// re-encoded and its metadata still stripped. EXIF is where a photographer's
// home address lives, and keeping it would be a worse bug than the one above.
func TestAnOrdinaryImageIsStillOptimised(t *testing.T) {
	out, err := media.Optimise("png", bigPNG(t), media.Options{
		MaxWidth: 100, MaxHeight: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.KeptForProvenance {
		t.Fatal("an image with no manifest was treated as though it had one")
	}
	if out.Width != 100 {
		t.Errorf("an ordinary image was not resized: %dx%d", out.Width, out.Height)
	}
}

// "caBX" appearing inside compressed pixel data must not disable optimisation.
//
// A substring search would do exactly that, on a photograph, for no reason
// anybody could diagnose. The check walks the chunk list instead.
func TestTheMarkerInsidePixelDataIsNotAManifest(t *testing.T) {
	body := bigPNG(t)
	// Somewhere in the middle of the compressed data, well past the header.
	at := len(body) / 2
	copy(body[at:], []byte("caBX"))

	out, err := media.Optimise("png", body, media.Options{MaxWidth: 100})
	// The edit corrupts the stream, so decoding may fail — that is fine and
	// not what this is testing. What must not happen is the file being kept
	// because four bytes appeared somewhere.
	if err == nil && out.KeptForProvenance {
		t.Fatal("four bytes inside the pixel data were taken for a manifest, " +
			"so an ordinary photograph silently stops being optimised")
	}
}
