package c2pa

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
)

// Putting a manifest into a file, and getting it back out.
//
// # The circle, and how it is closed
//
// The manifest holds a hash of the file. The file holds the manifest. So the
// hash excludes the bytes the manifest occupies -- and the exclusion range,
// being part of the claim, is itself hashed and signed. Build the manifest,
// measure it, and rebuild with the real size, and the size changes again,
// because a larger offset encodes to more bytes in CBOR.
//
// The way out is to fix the size before signing: reserve a slot, build the
// manifest to fit, and pad the remainder with a JUMBF box that means nothing.
// The padding sits inside the excluded range, where its contents cannot affect
// the hash and its length is already accounted for.
//
// # Reading, and the check that matters
//
// A verifier must not take the exclusion range from the manifest at face
// value. A range wider than the manifest hides real bytes from the hash, and a
// manifest that excludes half the image validates against a picture it never
// described. So Verify locates the manifest itself, and requires the claimed
// exclusions to be exactly the range the manifest actually occupies. Anything
// else is refused, including a range that is merely larger.

// slack is the room left for the manifest to grow between measuring and
// signing. The variation is a few bytes -- an offset crossing a CBOR length
// boundary -- and this is cheap.
const slack = 64

// paddingLabel is the box that fills the reserved slot. "free" is the
// conventional four-character type for bytes with no meaning.
const paddingKind = "free"

// Embed writes a signed manifest into a PNG or JPEG.
//
// Formats without an implementation here are refused rather than returned
// unchanged: a file that silently came back without a manifest, from a
// function whose name says it embeds one, is a provenance claim that quietly
// is not there.
func Embed(file []byte, c Claim, chain [][]byte, key ed25519.PrivateKey) ([]byte, error) {
	switch {
	case bytes.HasPrefix(file, pngMagic):
		return embedPNG(file, c, chain, key)
	case bytes.HasPrefix(file, []byte{0xff, 0xd8}):
		return embedJPEG(file, c, chain, key)
	}
	return nil, fmt.Errorf("this is not a PNG or a JPEG, and a manifest has " +
		"to be embedded the way each format says or it is invisible to every " +
		"reader")
}

var pngMagic = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// -- PNG ----------------------------------------------------------------------

// caBX is the PNG chunk type C2PA defines for a manifest store. Lowercase
// first letter: ancillary, so a decoder that does not know it ignores it
// rather than refusing the image.
const pngChunk = "caBX"

// embedPNG inserts a caBX chunk before the image data.
//
// Before IDAT because C2PA requires it, and because a reader should be able to
// know what it is looking at before it has decoded the pixels.
func embedPNG(file []byte, c Claim, chain [][]byte, key ed25519.PrivateKey) ([]byte, error) {
	at, err := pngInsertPoint(file)
	if err != nil {
		return nil, err
	}
	store, err := buildToFit(file, c, chain, key, at, 12)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(file)+len(store)+12)
	out = append(out, file[:at]...)
	out = append(out, pngChunkBytes(store)...)
	out = append(out, file[at:]...)
	return out, nil
}

// pngChunkBytes frames a chunk: length, type, data, CRC over type and data.
func pngChunkBytes(data []byte) []byte {
	out := make([]byte, 0, 12+len(data))
	out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
	out = append(out, pngChunk...)
	out = append(out, data...)
	return binary.BigEndian.AppendUint32(out, chunkCRC(data))
}

// pngInsertPoint finds the offset of the first IDAT chunk.
func pngInsertPoint(file []byte) (int, error) {
	at := len(pngMagic)
	for at+8 <= len(file) {
		length := binary.BigEndian.Uint32(file[at : at+4])
		kind := string(file[at+4 : at+8])
		if kind == "IDAT" {
			return at, nil
		}
		if kind == pngChunk {
			return 0, fmt.Errorf("this PNG already carries a manifest; " +
				"replacing one would discard a provenance record this " +
				"program did not write")
		}
		next := at + 12 + int(length)
		if next <= at || next > len(file) {
			return 0, fmt.Errorf("a PNG chunk at byte %d claims %d bytes",
				at, length)
		}
		at = next
	}
	return 0, fmt.Errorf("this PNG has no image data")
}

// -- JPEG ---------------------------------------------------------------------

// JPEG carries a manifest in APP11 segments. The payload is a JUMBF box
// wrapped in a small header: the two bytes "JP", a box instance number, and a
// packet sequence number, per JPEG XT part 3.
//
// One segment only. A segment's length field is 16 bits, so a manifest over
// about 64KB has to be split across several, and this one is a claim and a
// signature -- around a kilobyte. A manifest too large for one segment is
// refused rather than truncated.
const (
	jpegAPP11    = 0xeb
	jpegCI       = 0x4a50 // "JP"
	jpegInstance = 0x0211 // what c2pa-rs writes for a manifest store
)

func embedJPEG(file []byte, c Claim, chain [][]byte, key ed25519.PrivateKey) ([]byte, error) {
	at, err := jpegInsertPoint(file)
	if err != nil {
		return nil, err
	}
	// Segment overhead: marker, length, CI, instance, sequence.
	store, err := buildToFit(file, c, chain, key, at, 2+2+2+2+4)
	if err != nil {
		return nil, err
	}
	seg := jpegSegment(store)
	if len(seg) > 0xffff+2 {
		return nil, fmt.Errorf(
			"the manifest needs %d bytes and an APP11 segment holds %d; "+
				"splitting across segments is not implemented, and a "+
				"truncated manifest is worse than none",
			len(seg), 0xffff)
	}

	out := make([]byte, 0, len(file)+len(seg))
	out = append(out, file[:at]...)
	out = append(out, seg...)
	out = append(out, file[at:]...)
	return out, nil
}

func jpegSegment(store []byte) []byte {
	body := make([]byte, 0, 8+len(store))
	body = binary.BigEndian.AppendUint16(body, jpegCI)
	body = binary.BigEndian.AppendUint16(body, jpegInstance)
	body = binary.BigEndian.AppendUint32(body, 1) // packet sequence
	body = append(body, store...)

	out := []byte{0xff, jpegAPP11}
	// The length field counts itself and the payload, not the marker.
	out = binary.BigEndian.AppendUint16(out, uint16(2+len(body)))
	return append(out, body...)
}

// jpegInsertPoint finds where to put the segment: after any leading APPn
// segments, before the first non-APPn marker.
func jpegInsertPoint(file []byte) (int, error) {
	if !bytes.HasPrefix(file, []byte{0xff, 0xd8}) {
		return 0, fmt.Errorf("this is not a JPEG")
	}
	at := 2
	for at+4 <= len(file) {
		if file[at] != 0xff {
			return 0, fmt.Errorf("byte %d is not a marker, so this JPEG's "+
				"structure is not one this program can read", at)
		}
		marker := file[at+1]
		if marker == jpegAPP11 {
			return 0, fmt.Errorf("this JPEG already carries an APP11 " +
				"segment, which may be a manifest; replacing one would " +
				"discard a record this program did not write")
		}
		// APPn is 0xe0-0xef. Anything else -- a quantisation table, a frame
		// header, the scan -- is where the metadata ends.
		if marker < 0xe0 || marker > 0xef {
			return at, nil
		}
		length := int(binary.BigEndian.Uint16(file[at+2 : at+4]))
		next := at + 2 + length
		if length < 2 || next > len(file) {
			return 0, fmt.Errorf("a JPEG segment at byte %d claims %d bytes",
				at, length)
		}
		at = next
	}
	return 0, fmt.Errorf("this JPEG ends before its image data")
}

// -- fitting ------------------------------------------------------------------

// buildToFit builds a manifest store of a size decided before it is signed.
//
// overhead is what the container adds around the store -- a PNG chunk header
// and CRC, a JPEG segment header -- because the excluded range has to cover
// the whole of what was inserted, not just the JUMBF bytes. Excluding only the
// payload would leave the chunk framing in the hash, which is correct until
// somebody rewrites a length field.
func buildToFit(file []byte, c Claim, chain [][]byte, key ed25519.PrivateKey,
	at, overhead int) ([]byte, error) {

	// First pass: a build with a provisional range, only to learn the size.
	probe, err := c.build(file, []exclusion{{start: at, length: overhead}},
		chain, key, 0)
	if err != nil {
		return nil, err
	}

	reserve := len(probe) + slack
	for attempt := 0; attempt < 4; attempt++ {
		declared := []exclusion{{start: at, length: overhead + reserve}}
		bare, berr := c.build(file, declared, chain, key, 0)
		if berr != nil {
			return nil, berr
		}
		switch {
		case len(bare) == reserve:
			return bare, nil
		case len(bare)+8 <= reserve:
			// Rebuild with the remainder filled. A padding box costs 8 bytes
			// of header, which is why an exact fit and a fit with room to
			// spare are the only two cases -- there is no way to add fewer.
			// The length prefix is always four bytes, so the padded store is
			// exactly 8 + pad longer and lands on the reserved size.
			padded, perr := c.build(file, declared, chain, key,
				reserve-len(bare)-8)
			if perr != nil {
				return nil, perr
			}
			if len(padded) != reserve {
				return nil, fmt.Errorf(
					"padding produced %d bytes for a %d-byte slot",
					len(padded), reserve)
			}
			return padded, nil
		default:
			reserve = len(bare) + slack
		}
	}
	return nil, fmt.Errorf("the manifest's size did not settle in four " +
		"attempts, which means the reserved size and the encoded size are " +
		"chasing each other")
}
