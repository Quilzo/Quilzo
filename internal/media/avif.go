package media

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// AVIF, and the reason accepting it needs more than a magic number.
//
// # Why it is worth having
//
// It is the format that makes a photograph small. A picture that is 150 kB as
// a JPEG is routinely 60 kB as AVIF at the same quality, and this program's
// whole argument about pages is that a reader on a phone should not download
// pixels their screen cannot use.
//
// # Why the dimensions are parsed here
//
// Go has no AVIF decoder, so image.DecodeConfig returns nothing and the file
// is stored with a width and height of zero. That is not a cosmetic gap. The
// templates emit intrinsic dimensions from those numbers, and it is what stops
// a page reflowing as its images arrive -- so an AVIF accepted without them
// would be a picture that loads fast and makes the page jump, which is a worse
// reading experience than the JPEG it replaced. `media renditions` also skips
// anything with a zero width, so such a file would silently never get narrower
// copies either.
//
// The numbers are in the file. AVIF is ISOBMFF, and an image's size lives in
// an ispe box -- twelve bytes of fixed layout. Walking to it is a great deal
// less work than decoding AV1, and this program does not need the pixels.
//
// # What this deliberately does not do
//
// It does not decode. There is no AV1 decoder here and there will not be one:
// that is a large amount of attacker-facing parsing to run on an upload, for
// a picture this program only ever stores and serves. So the check is
// structural, like the WebP one -- the file is what it claims to be, its boxes
// are internally consistent, and the dimensions are the ones it declares.

// avifBrands are the ftyp brands that mean "a still image", as opposed to the
// AVIF sequence brands, which are video in an image's clothing.
var avifBrands = []string{"avif", "avis", "mif1", "miaf"}

// verifyAVIF checks the container structurally.
func verifyAVIF(b []byte) error {
	if len(b) < 16 {
		return fmt.Errorf("too short to be a container")
	}
	if !bytes.Equal(b[4:8], []byte("ftyp")) {
		return fmt.Errorf("no ftyp box at offset 4")
	}

	size := int(binary.BigEndian.Uint32(b[:4]))
	if size < 16 || size > len(b) {
		return fmt.Errorf("the ftyp box claims %d bytes of %d", size, len(b))
	}
	// The major brand, then the compatible brands that follow the version.
	// A file whose major brand is something else but which lists avif as
	// compatible is still an AVIF, and that is the common shape.
	brands := []string{string(b[8:12])}
	for at := 16; at+4 <= size; at += 4 {
		brands = append(brands, string(b[at:at+4]))
	}
	for _, got := range brands {
		for _, want := range avifBrands {
			if got == want {
				return nil
			}
		}
	}
	return fmt.Errorf("brands %v include none that mean AVIF", brands)
}

// avifSize returns the declared dimensions.
//
// The ispe box is inside meta/iprp/ipco, and the walk below descends through
// those rather than scanning for the four bytes anywhere in the file: "ispe"
// occurring inside compressed image data is a coincidence that would produce
// confident nonsense, and a wrong intrinsic size is worse than none because
// the page reserves the wrong space.
func avifSize(b []byte) (w, h int, ok bool) {
	meta, found := findBox(b, "meta", 0)
	if !found {
		return 0, 0, false
	}
	// A meta box is a FullBox: four bytes of version and flags before its
	// children. Skipping them is what makes the next box header land where it
	// is expected rather than four bytes into the previous one.
	if len(meta) < 4 {
		return 0, 0, false
	}
	iprp, found := findBox(meta[4:], "iprp", 0)
	if !found {
		return 0, 0, false
	}
	ipco, found := findBox(iprp, "ipco", 0)
	if !found {
		return 0, 0, false
	}
	ispe, found := findBox(ipco, "ispe", 0)
	if !found || len(ispe) < 12 {
		return 0, 0, false
	}
	// FullBox again: version and flags, then width and height.
	w = int(binary.BigEndian.Uint32(ispe[4:8]))
	h = int(binary.BigEndian.Uint32(ispe[8:12]))
	if w <= 0 || h <= 0 || w > 1<<20 || h > 1<<20 {
		return 0, 0, false
	}
	return w, h, true
}

// findBox returns the payload of the first box of this type at this level.
//
// Bounded, and every bound matters: a size of zero means "to the end of the
// file" in ISOBMFF and a naive walk on one loops forever, which is a denial of
// service that costs an attacker one upload.
func findBox(data []byte, kind string, depth int) ([]byte, bool) {
	if depth > 8 {
		return nil, false
	}
	at := 0
	for at+8 <= len(data) {
		size := int(binary.BigEndian.Uint32(data[at : at+4]))
		name := string(data[at+4 : at+8])
		header := 8
		switch {
		case size == 1:
			// A 64-bit size follows the name. Not expected in a still image,
			// and refused rather than guessed at.
			return nil, false
		case size == 0:
			// To the end of the data.
			size = len(data) - at
		}
		if size < header || at+size > len(data) {
			return nil, false
		}
		if name == kind {
			return data[at+header : at+size], true
		}
		at += size
	}
	return nil, false
}
