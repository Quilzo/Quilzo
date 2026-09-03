package c2pa

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/big"
	"testing"
	"time"
)

func signer(t *testing.T) ([][]byte, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Quilzo test signer"},
		NotBefore:    time.Unix(1787000000, 0),
		NotAfter:     time.Unix(1887000000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{der}, priv, pub
}

func samplePNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for x := 0; x < 16; x++ {
		for y := 0; y < 16; y++ {
			img.Set(x, y, color.RGBA{uint8(x * 16), uint8(y * 16), 0x40, 0xff})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func sampleJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func claim() Claim {
	return Claim{
		Title:             "meadow.png",
		Format:            "image/png",
		DigitalSourceType: "trainedAlgorithmicMedia",
		SoftwareAgent:     "Quilzo",
		Author:            "Rashik",
		Model:             "claude-opus-5",
		Instruction:       "a meadow at dusk",
		When:              time.Unix(1787000000, 0),
	}
}

// The round trip, and the reason the whole package exists: a file goes out
// carrying a claim, and a reader who was not there can check it.
func TestAManifestSurvivesTheRoundTrip(t *testing.T) {
	chain, priv, pub := signer(t)
	original := samplePNG(t)

	out, err := Embed(original, claim(), chain, priv)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Verify(out, pub)
	if err != nil {
		t.Fatalf("a manifest this program wrote does not verify: %v", err)
	}
	if got.Title != "meadow.png" {
		t.Errorf("title is %q", got.Title)
	}
	if got.DigitalSourceType != "trainedAlgorithmicMedia" {
		t.Errorf("source type is %q, want trainedAlgorithmicMedia",
			got.DigitalSourceType)
	}
	if !got.GeneratedByModel() {
		t.Error("a trainedAlgorithmicMedia manifest does not report as " +
			"model-generated, which is the marking Article 50 requires")
	}
	if got.Model != "claude-opus-5" || got.Instruction != "a meadow at dusk" {
		t.Errorf("model is %q and instruction %q", got.Model, got.Instruction)
	}
	if got.Author != "Rashik" {
		t.Errorf("author is %q", got.Author)
	}
}

// The file still has to be the file. A manifest that made the image
// undecodable would be a provenance record nobody could afford to keep.
func TestTheImageStillDecodes(t *testing.T) {
	chain, priv, _ := signer(t)

	out, err := Embed(samplePNG(t), claim(), chain, priv)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("a PNG carrying a manifest no longer decodes: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 16 || b.Dy() != 16 {
		t.Errorf("the image is %v", b)
	}

	j, err := Embed(sampleJPEG(t), claim(), chain, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jpeg.Decode(bytes.NewReader(j)); err != nil {
		t.Fatalf("a JPEG carrying a manifest no longer decodes: %v", err)
	}
}

func TestAJPEGManifestSurvivesTheRoundTrip(t *testing.T) {
	chain, priv, pub := signer(t)
	c := claim()
	c.Format, c.Title = "image/jpeg", "meadow.jpg"

	out, err := Embed(sampleJPEG(t), c, chain, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(out, pub)
	if err != nil {
		t.Fatalf("a JPEG manifest does not verify: %v", err)
	}
	if got.Title != "meadow.jpg" {
		t.Errorf("title is %q", got.Title)
	}
}

// (3) The binding. Change one pixel and the manifest stops applying.
func TestChangingThePixelsBreaksTheManifest(t *testing.T) {
	chain, priv, pub := signer(t)

	out, err := Embed(samplePNG(t), claim(), chain, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Find the image data and flip a byte in it.
	at := len(pngMagic)
	for {
		length := int(binary.BigEndian.Uint32(out[at : at+4]))
		if string(out[at+4:at+8]) == "IDAT" {
			out[at+9] ^= 0xff
			break
		}
		at += 12 + length
	}

	if _, err := Verify(out, pub); err == nil {
		t.Fatal("a manifest verified against an image whose pixels changed " +
			"after it was signed")
	}
}

// (4) The check that is easy to leave out, and without which a manifest
// validates against anything.
//
// The attack: take a signed file, widen the claimed exclusion so the hash
// covers less of it, and the manifest travels onto content it never described.
// Here the exclusion is simply moved to a range that is not where the manifest
// sits, which is the same fault in its simplest form.
func TestAnExclusionThatIsNotWhereTheManifestSitsIsRefused(t *testing.T) {
	chain, priv, pub := signer(t)
	original := samplePNG(t)

	at, err := pngInsertPoint(original)
	if err != nil {
		t.Fatal(err)
	}

	// A manifest built claiming to be somewhere it is not: the hash is honest
	// about that range, so every check except the placement one passes.
	c := claim()
	store, err := c.build(original, []exclusion{{start: at, length: 4}}, chain, priv, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := append(append(append([]byte{}, original[:at]...),
		pngChunkBytes(store)...), original[at:]...)

	_, err = Verify(out, pub)
	if err == nil {
		t.Fatal("a manifest excluding a range it does not occupy verified.\n" +
			"  The hash then covers fewer bytes than the file has, and the " +
			"manifest\n  can be moved onto content it never described.")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("excludes bytes")) {
		t.Errorf("refused, but for the wrong reason: %v", err)
	}
}

// (1) The signature. A manifest signed by somebody else is somebody else's.
func TestAManifestSignedByAnotherKeyIsRefused(t *testing.T) {
	chain, priv, _ := signer(t)
	_, _, otherPub := signer(t)

	out, err := Embed(samplePNG(t), claim(), chain, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(out, otherPub); err == nil {
		t.Fatal("a manifest verified against a key that did not sign it")
	}
}

// (2) An assertion swapped after signing, under the same label.
//
// The claim commits to each assertion by the hash of its bytes, so changing
// one changes what a reader is told without changing what was signed. This
// edits the actions assertion in place: a file that says a person drew it when
// the signer said a model did.
func TestAnAssertionChangedAfterSigningIsRefused(t *testing.T) {
	chain, priv, pub := signer(t)

	out, err := Embed(samplePNG(t), claim(), chain, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Same length, so nothing else about the file shifts.
	from := []byte("trainedAlgorithmicMedia")
	to := []byte("humanEditsAlgorithmXXXX")
	if len(from) != len(to) {
		t.Fatal("the replacement has to be the same length")
	}
	i := bytes.Index(out, from)
	if i < 0 {
		t.Fatal("the source type is not in the file to change")
	}
	copy(out[i:], to)

	if _, err := Verify(out, pub); err == nil {
		t.Fatal("an assertion changed after signing was accepted, so what a " +
			"reader is told is not what the signer said")
	}
}

// A file that already carries a manifest is left alone rather than overwritten.
func TestAFileThatAlreadyHasAManifestIsNotOverwritten(t *testing.T) {
	chain, priv, _ := signer(t)

	out, err := Embed(samplePNG(t), claim(), chain, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Embed(out, claim(), chain, priv); err == nil {
		t.Fatal("embedding over an existing manifest discarded a provenance " +
			"record this program did not write")
	}
}

// Determinism, because the bytes are signed. Two runs over the same input have
// to produce the same file, or a rebuild looks like a tampered one.
func TestTwoRunsProduceTheSameBytes(t *testing.T) {
	chain, priv, _ := signer(t)
	in := samplePNG(t)

	a, err := Embed(in, claim(), chain, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Embed(in, claim(), chain, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two runs over the same input produced different files")
	}
}

// An unsigned file is not a file with a bad manifest. Most images have none,
// and saying so plainly is what lets a caller tell the difference.
func TestAFileWithNoManifestSaysSo(t *testing.T) {
	_, _, pub := signer(t)
	if _, err := Verify(samplePNG(t), pub); err == nil {
		t.Fatal("a file with no manifest verified")
	}
}

// The framing check a round trip cannot make.
//
// A JPEG APP11 segment declares the JUMBF box's length in its first four bytes
// after the packet header, and a reader compares that against how much data
// the segment actually holds. Padding written after the store rather than
// inside it left those disagreeing: every reader but this one rejected the
// segment, and this one accepted it because it repeated the writer's mistake.
//
// exiftool caught it. This keeps it caught.
func TestTheJPEGSegmentDeclaresItsOwnLength(t *testing.T) {
	chain, priv, _ := signer(t)
	c := claim()
	c.Format = "image/jpeg"

	out, err := Embed(sampleJPEG(t), c, chain, priv)
	if err != nil {
		t.Fatal(err)
	}

	at := 2
	for out[at] == 0xff && out[at+1] != jpegAPP11 {
		at += 2 + int(binary.BigEndian.Uint16(out[at+2:at+4]))
	}
	if out[at+1] != jpegAPP11 {
		t.Fatal("no APP11 segment")
	}
	segLen := int(binary.BigEndian.Uint16(out[at+2 : at+4]))
	// Payload after marker(2) + length(2) + CI(2) + instance(2) + sequence(4).
	payload := out[at+12 : at+2+segLen]
	if len(payload) < 8 {
		t.Fatal("the segment holds no box")
	}
	lbox := int(binary.BigEndian.Uint32(payload[:4]))
	if lbox != len(payload) {
		t.Errorf("the JUMBF box declares %d bytes and the segment carries "+
			"%d.\n  Every reader that checks one against the other refuses "+
			"the segment.", lbox, len(payload))
	}
	if kind := string(payload[4:8]); kind != "jumb" {
		t.Errorf("the segment's box is %q, not a superbox", kind)
	}
}

// The same property for PNG: the chunk holds exactly one box.
func TestThePNGChunkHoldsOneBox(t *testing.T) {
	chain, priv, _ := signer(t)

	out, err := Embed(samplePNG(t), claim(), chain, priv)
	if err != nil {
		t.Fatal(err)
	}
	data, _, err := extractPNG(out)
	if err != nil {
		t.Fatal(err)
	}
	lbox := int(binary.BigEndian.Uint32(data[:4]))
	if lbox != len(data) {
		t.Errorf("the JUMBF box declares %d bytes and the chunk carries %d",
			lbox, len(data))
	}
}
