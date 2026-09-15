// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/c2pa"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/provenance"
)

func aPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 16), G: uint8(y * 16), A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// libraryWith stores one file and returns the root and its id.
func libraryWith(t *testing.T, name string, body []byte,
	origin media.Origin) (string, string) {

	t.Helper()
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	f, err := media.Accept(name, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "a picture"
	f.Origin = origin
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}
	return root, f.ID
}

// verdictsFor runs the check the command runs, without the printing.
func verdictsFor(t *testing.T, root string) []verdict {
	t.Helper()
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	chain, key, err := provenanceSigner(root, "A site", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	var out []verdict
	for _, f := range files {
		if f.RenditionOf != "" {
			continue
		}
		out = append(out, verifyOne(lib, f, chain, key, pub))
	}
	return out
}

// What this site signs, verifies.
//
// internal/c2pa verifies four things where most implementations check two, and
// in production it was write-only: Verify was called from tests and from
// nowhere else. The program signed and never looked, which is the whole
// standard's problem in miniature.
func TestThisSitesOwnManifestVerifies(t *testing.T) {
	root, _ := libraryWith(t, "shot.png", aPNG(t), media.Origin{})
	got := verdictsFor(t, root)
	if len(got) != 1 {
		t.Fatalf("%d verdict(s), want 1", len(got))
	}
	if got[0].State != verdictOK {
		t.Errorf("state is %q (%s), want ok", got[0].State, got[0].Detail)
	}
}

// And it carries the origin somebody declared, into the manifest.
func TestADeclaredOriginReachesTheManifest(t *testing.T) {
	root, _ := libraryWith(t, "shot.png", aPNG(t), media.Origin{
		SourceType: string(provenance.TrainedAlgorithmicMedia),
		Model:      "a-model", Author: "somebody",
	})
	got := verdictsFor(t, root)
	if got[0].Claims != string(provenance.TrainedAlgorithmicMedia) {
		t.Errorf("the manifest declares %q", got[0].Claims)
	}
}

// A manifest that arrived with the file is read, and reported as unchecked.
//
// It is signed by a key this site does not hold and there is no trust list to
// look one up in. Reading it anyway is the right answer: three of the four
// checks need no key and they are the ones that say the manifest describes
// these bytes.
func TestAForeignManifestIsReadAndNotClaimedAsVerified(t *testing.T) {
	_, foreignKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := c2pa.Embed(aPNG(t), c2pa.Claim{
		Title: "from elsewhere", Format: "image/png",
		DigitalSourceType: string(provenance.TrainedAlgorithmicMedia),
		SoftwareAgent:     "SomebodyElse", Author: "a stranger",
		When: time.Now(),
	}, [][]byte{{1, 2, 3}}, foreignKey)
	if err != nil {
		t.Fatal(err)
	}

	root, _ := libraryWith(t, "elsewhere.png", signed, media.Origin{})
	got := verdictsFor(t, root)
	if got[0].State != verdictCarried {
		t.Fatalf("state is %q (%s), want carried", got[0].State, got[0].Detail)
	}
	if got[0].Claims != string(provenance.TrainedAlgorithmicMedia) {
		t.Errorf("it read %q out of the foreign manifest", got[0].Claims)
	}
	// The distinction has to be in the words. Rounding this up to "verified"
	// is the easy lie, and rounding it down to "unknown" throws away a real
	// piece of evidence about the file.
	if !strings.Contains(got[0].Detail, "not checked") {
		t.Errorf("the report does not say the signer is unchecked: %s",
			got[0].Detail)
	}
	if got[0].Signer != "SomebodyElse" {
		t.Errorf("the signing agent reads as %q", got[0].Signer)
	}
}

// A manifest moved onto different pixels is caught without any key at all.
//
// This is what the hard binding is for, and it is the check most
// implementations leave out.
func TestATamperedManifestIsBroken(t *testing.T) {
	_, foreignKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := c2pa.Embed(aPNG(t), c2pa.Claim{
		Title: "from elsewhere", Format: "image/png",
		SoftwareAgent: "SomebodyElse", Author: "a stranger", When: time.Now(),
	}, [][]byte{{1, 2, 3}}, foreignKey)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, signed...)
	tampered[len(tampered)-40] ^= 0xFF

	root, _ := libraryWith(t, "tampered.png", tampered, media.Origin{})
	got := verdictsFor(t, root)
	if got[0].State != verdictBroken {
		t.Fatalf("state is %q (%s), want broken", got[0].State, got[0].Detail)
	}
	if !strings.Contains(got[0].Detail, "different content") {
		t.Errorf("the report does not say what is wrong: %s", got[0].Detail)
	}
}

// A file with no manifest and a format this cannot sign is neither verified
// nor broken. Saying nothing about it is the honest answer.
func TestAFormatThisCannotSignIsNotAVerdict(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("name,value\nbrass pen,46\n")
	f, err := media.Accept("prices.csv", body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}
	got := verdictsFor(t, root)
	if len(got) != 1 || got[0].State != verdictNoContainer {
		t.Fatalf("a CSV produced %+v", got)
	}
}

// Renditions are not reported.
//
// Each is a copy of a picture already in the list and carries the same account
// of itself, so listing them buries the answers somebody wants under four
// times as many they do not.
func TestRenditionsAreNotReportedSeparately(t *testing.T) {
	root, parent := libraryWith(t, "big.png", bigNoisyPNG(t), media.Origin{})
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	narrower := 0
	for _, f := range files {
		if f.RenditionOf != "" {
			narrower++
		}
	}
	if narrower == 0 {
		t.Fatal("no renditions were stored, so this test checks nothing")
	}
	got := verdictsFor(t, root)
	if len(got) != 1 || got[0].ID != parent {
		t.Errorf("%d verdict(s) for one picture with %d rendition(s)",
			len(got), narrower)
	}
}

// bigNoisyPNG is wide enough and incompressible enough to get renditions that
// are actually smaller than it.
func bigNoisyPNG(t *testing.T) []byte {
	t.Helper()
	const w, h = 900, 600
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	seed := uint32(0x9e3779b9)
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
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The command reaches the library at all, and a named file narrows it.
func TestVerifyNarrowsToTheFileNamed(t *testing.T) {
	root, id := libraryWith(t, "shot.png", aPNG(t), media.Origin{})
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	second := bigNoisyPNG(t)
	f, err := media.Accept("other.png", second, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "another"
	if err := lib.Put(f, second); err != nil {
		t.Fatal(err)
	}

	w = out.New(true)
	t.Cleanup(func() { w = nil })
	if err := cmdMediaVerify(root, []string{id}); err != nil {
		t.Fatalf("verifying one file: %v", err)
	}
	if err := cmdMediaVerify(root, []string{strings.Repeat("0", 64)}); err == nil {
		t.Error("a file that is not in the library was not refused")
	}
}

// A crop keeps everything that has to travel with it, and says what it is.
//
// The licence, because an edit does not renew permission and does not end it.
// The origin, because a crop of a picture a model made is still a picture a
// model made — dropping it would be a way to launder generated content into an
// undeclared file, which is the exact failure the media provenance gate exists
// to catch. And the alt text, because an image without one cannot go on a page
// at all.
func TestAnEditCarriesTheLicenceAndTheOrigin(t *testing.T) {
	root, id := libraryWith(t, "shot.png", bigNoisyPNG(t), media.Origin{
		SourceType: string(provenance.TrainedAlgorithmicMedia),
		Model:      "a-model", Author: "somebody",
	})
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := lib.Stat(id)
	if err != nil {
		t.Fatal(err)
	}
	parent.Rights = media.Rights{Licence: "cc-by-4.0", Holder: "a photographer"}
	_, raw, err := lib.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(parent, raw); err != nil {
		t.Fatal(err)
	}

	w = out.New(true)
	t.Cleanup(func() { w = nil })
	if err := mediaEdit(root, []string{id, "--crop", "16:9"}); err != nil {
		t.Fatal(err)
	}

	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	var derived *media.File
	for i := range files {
		if files[i].EditOf == id {
			derived = &files[i]
		}
	}
	if derived == nil {
		t.Fatal("no derived file was stored")
	}
	if derived.Origin.SourceType != string(provenance.TrainedAlgorithmicMedia) {
		t.Errorf("the crop declares %q; a crop of a generated picture is "+
			"still generated", derived.Origin.SourceType)
	}
	if derived.Rights.Licence != "cc-by-4.0" {
		t.Errorf("the crop's licence is %q", derived.Rights.Licence)
	}
	if derived.Alt != parent.Alt {
		t.Errorf("the crop's description is %q, want the original's", derived.Alt)
	}
	if derived.Edit == nil || derived.Edit.Aspect != "16:9" {
		t.Errorf("the crop does not record what was done: %+v", derived.Edit)
	}

	// And the original is exactly where it was.
	if _, _, err := lib.Get(id); err != nil {
		t.Errorf("the original is gone: %v", err)
	}
}

// The manifest on an edit binds to the picture it was made from, and says the
// picture was cropped rather than resized.
func TestAnEditsManifestNamesItsParentAndWhatWasDone(t *testing.T) {
	root, id := libraryWith(t, "shot.png", bigNoisyPNG(t), media.Origin{})

	w = out.New(true)
	t.Cleanup(func() { w = nil })
	if err := mediaEdit(root, []string{id, "--crop", "16:9"}); err != nil {
		t.Fatal(err)
	}
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	var derivedID string
	for _, f := range files {
		if f.EditOf == id {
			derivedID = f.ID
		}
	}
	if derivedID == "" {
		t.Fatal("no derived file was stored")
	}

	look, err := mediaLookup(root)
	if err != nil {
		t.Fatal(err)
	}
	_, served, err := look(derivedID)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c2pa.Read(served)
	if err != nil {
		t.Fatalf("the crop's manifest does not read: %v", err)
	}
	if len(st.DerivedFrom) == 0 {
		t.Error("the crop's manifest names no parent, so \"derived from " +
			"something\" is a claim no verifier can test")
	}
	// The parent as a reader receives it, which is the copy anybody could
	// fetch and hash.
	_, parentServed, err := look(id)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(parentServed)
	if !bytes.Equal(st.DerivedFrom, want[:]) {
		t.Error("the crop binds to bytes nobody can download")
	}
}
