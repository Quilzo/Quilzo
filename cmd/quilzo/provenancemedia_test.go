package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/c2pa"
	"github.com/quilzo/quilzo/internal/media"
)

func testSigner(t *testing.T) ([][]byte, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Unix(1787000000, 0),
		NotAfter:     time.Unix(1887000000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{der}, priv, pub
}

func fileFor(body []byte, format string, kind media.Kind) media.File {
	sum := sha256.Sum256(body)
	return media.File{
		ID: hex.EncodeToString(sum[:]), Name: "picture." + format,
		Format: format, Kind: kind, Size: int64(len(body)),
		UploadedAt: 1787000000,
		Origin: media.Origin{
			SourceType: "trainedAlgorithmicMedia",
			Model:      "claude-opus-5",
			Author:     "Rashik",
		},
	}
}

// An image comes back carrying what the site says about it, checkable against
// the site's own key.
func TestAServedImageCarriesAVerifiableManifest(t *testing.T) {
	chain, priv, pub := testSigner(t)
	body := testPNG("provenance")
	f := fileFor(body, "png", media.Image)

	s := newSignedMedia(func(string) (media.File, []byte, error) {
		return f, body, nil
	}, chain, priv, "Quilzo")

	_, out, err := s.get(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c2pa.Verify(out, pub)
	if err != nil {
		t.Fatalf("a served image does not verify against the site's key: %v", err)
	}
	if !st.GeneratedByModel() {
		t.Error("a file declared as model-generated did not say so in its " +
			"manifest, which is the marking the disclosure duty is about")
	}
	if st.Author != "Rashik" || st.Model != "claude-opus-5" {
		t.Errorf("author %q model %q", st.Author, st.Model)
	}
}

// A file that already carries a manifest is passed through untouched.
//
// Something upstream -- a camera, a generator -- said this about the picture
// before it arrived. Overwriting that would destroy a record rather than add
// to one, so the original bytes go out unchanged.
func TestAnExistingManifestIsNotOverwritten(t *testing.T) {
	chain, priv, pub := testSigner(t)

	// Signed by somebody else entirely.
	otherChain, otherPriv, otherPub := testSigner(t)
	upstream, err := c2pa.Embed(testPNG("provenance"), c2pa.Claim{
		Title: "from a camera", Format: "image/png",
		SoftwareAgent: "SomeoneElse", When: time.Unix(1787000000, 0),
	}, otherChain, otherPriv)
	if err != nil {
		t.Fatal(err)
	}

	f := fileFor(upstream, "png", media.Image)
	s := newSignedMedia(func(string) (media.File, []byte, error) {
		return f, upstream, nil
	}, chain, priv, "Quilzo")

	_, out, err := s.get(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, upstream) {
		t.Fatal("an image that already carried a manifest was rewritten")
	}
	if _, err := c2pa.Verify(out, otherPub); err != nil {
		t.Errorf("the upstream manifest no longer verifies: %v", err)
	}
	if _, err := c2pa.Verify(out, pub); err == nil {
		t.Error("the upstream manifest now verifies against this site's key, " +
			"so this site overwrote somebody else's record")
	}
}

// Anything that is not a PNG or a JPEG goes out exactly as stored.
func TestFilesWithNoContainerAreUntouched(t *testing.T) {
	chain, priv, _ := testSigner(t)
	body := []byte("%PDF-1.4 not really")
	f := fileFor(body, "pdf", media.Kind("document"))

	s := newSignedMedia(func(string) (media.File, []byte, error) {
		return f, body, nil
	}, chain, priv, "Quilzo")

	_, out, err := s.get(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, body) {
		t.Error("a file this program cannot embed into came back changed")
	}
}

// The same id twice returns the same bytes. Files are immutable and named by
// their own hash, so a second call must not produce a different signature --
// a reader comparing two downloads of one picture would see a tampered file.
func TestTheSameImageTwiceIsTheSameBytes(t *testing.T) {
	chain, priv, _ := testSigner(t)
	body := testPNG("provenance")
	f := fileFor(body, "png", media.Image)

	s := newSignedMedia(func(string) (media.File, []byte, error) {
		return f, body, nil
	}, chain, priv, "Quilzo")

	_, a, err := s.get(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := s.get(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two reads of one image produced different bytes")
	}
}
