// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package media

import "image"

// Which way up a photograph is.
//
// # Why this has to exist, given that nothing else here parses EXIF
//
// optimise.go says, correctly, that parsing EXIF properly "would mean parsing
// attacker-controlled TIFF in order to decide whether to discard it, which is
// work done for no benefit — it is being discarded either way." That was true
// while the tag was only ever thrown away. It is not true of one tag.
//
// A phone writes its photographs in the sensor's orientation and records how
// to turn them in EXIF Orientation. Browsers honour it: since image-orientation
// defaulted to from-image, an untouched JPEG out of a phone displays the right
// way up. This pipeline re-encodes, and a re-encode drops every ancillary
// segment — so the tag went and the pixels did not move, and the stored
// photograph was rotated ninety degrees with nothing left to say it should not
// be. The upload looked right in the operating system's preview and wrong on
// the published page, which is the hardest kind of bug to be told about.
//
// So the rule is narrow, and it is the rule rather than "support EXIF": if the
// orientation tag is going to be discarded, the rotation it describes has to be
// in the pixels first.
//
// # The parse, and how small it is kept
//
// One tag out of one directory. The walk finds the APP1 segment, checks it
// begins "Exif\0\0", reads the TIFF header for a byte order and the offset of
// the first directory, and reads that directory's entries looking for 0x0112.
// It follows no sub-directory, resolves no offset-valued tag, recurses
// nowhere, and gives up on anything it does not understand. Every read is
// bounds-checked against the slice it came from, and the entry count is
// capped.
//
// That is a much smaller surface than a TIFF parser, and it is all the
// question needs: a value of 1 to 8, or nothing.

// Orientation is what EXIF says about which way up an image is.
//
// Values are the eight the specification defines. 0 means no answer, which is
// the common case — most images carry no tag at all — and is treated exactly
// like 1.
type Orientation uint16

// Transforms reports whether this orientation moves any pixels.
func (o Orientation) Transforms() bool { return o >= 2 && o <= 8 }

// SwapsAxes reports whether applying it exchanges width and height.
func (o Orientation) SwapsAxes() bool { return o >= 5 && o <= 8 }

// maxIFDEntries bounds the directory walk.
//
// A real IFD0 holds a few dozen tags. The cap is what keeps a file claiming
// sixty-five thousand of them from being sixty-five thousand bounds checks,
// and it is far above anything a camera writes.
const maxIFDEntries = 512

// orientationOf reads the tag, or returns 0.
//
// JPEG only. PNG and GIF have no orientation tag, so there is nothing to read
// and nothing to correct.
func orientationOf(format string, body []byte) Orientation {
	if format != "jpeg" {
		return 0
	}
	exif, ok := exifSegment(body)
	if !ok {
		return 0
	}
	return orientationInTIFF(exif)
}

// exifSegment finds the APP1 payload after its "Exif\0\0" header.
func exifSegment(body []byte) ([]byte, bool) {
	// The same marker walk hasMetadata does, stopping at the scan for the same
	// reason: metadata comes before the image data, and walking into
	// compressed pixels is how a byte pattern becomes a parse.
	for i := 2; i+4 <= len(body) && i < 1<<16; {
		if body[i] != 0xFF {
			return nil, false
		}
		marker := body[i+1]
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			i += 2
			continue
		}
		if marker == 0xDA || marker == 0xD9 {
			return nil, false
		}
		size := int(body[i+2])<<8 | int(body[i+3])
		if size < 2 || i+2+size > len(body) {
			return nil, false
		}
		if marker == 0xE1 {
			payload := body[i+4 : i+2+size]
			const header = "Exif\x00\x00"
			if len(payload) > len(header) && string(payload[:len(header)]) == header {
				return payload[len(header):], true
			}
		}
		i += 2 + size
	}
	return nil, false
}

// orientationInTIFF reads tag 0x0112 out of the first directory.
func orientationInTIFF(t []byte) Orientation {
	if len(t) < 8 {
		return 0
	}
	var big bool
	switch {
	case t[0] == 'I' && t[1] == 'I':
		big = false
	case t[0] == 'M' && t[1] == 'M':
		big = true
	default:
		return 0
	}
	u16 := func(b []byte) uint16 {
		if big {
			return uint16(b[0])<<8 | uint16(b[1])
		}
		return uint16(b[1])<<8 | uint16(b[0])
	}
	u32 := func(b []byte) uint32 {
		if big {
			return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		}
		return uint32(b[3])<<24 | uint32(b[2])<<16 | uint32(b[1])<<8 | uint32(b[0])
	}
	if u16(t[2:4]) != 42 {
		return 0
	}
	off := u32(t[4:8])
	// An offset past the end, or one that leaves no room for the count, is a
	// file this does not understand. Nothing is guessed: no answer is a
	// correct answer here, and the image is stored as it was decoded.
	if off < 8 || uint64(off)+2 > uint64(len(t)) {
		return 0
	}
	count := int(u16(t[off : off+2]))
	if count <= 0 || count > maxIFDEntries {
		return 0
	}
	entries := t[off+2:]
	if len(entries) < count*12 {
		return 0
	}
	for i := 0; i < count; i++ {
		e := entries[i*12 : i*12+12]
		if u16(e[0:2]) != 0x0112 {
			continue
		}
		// SHORT, one value, which is what the specification says this tag is.
		// Anything else is a file disagreeing with the specification, and a
		// reader that accommodates that is a reader doing more work than the
		// question needs.
		if u16(e[2:4]) != 3 || u32(e[4:8]) != 1 {
			return 0
		}
		// A value this small lives in the entry rather than at an offset, so
		// there is no pointer to follow.
		v := u16(e[8:10])
		if v < 1 || v > 8 {
			return 0
		}
		return Orientation(v)
	}
	return 0
}

// applyOrientation turns an image the way its EXIF tag says it should be.
//
// A new image rather than a view, because the caller is about to encode it and
// image/jpeg writes rows in order. Written out as eight explicit mappings
// rather than as a composition of flips and rotations: the eight are what the
// specification defines, and a clever derivation of them is a thing to get
// subtly wrong in the two cases nobody has a test photograph for.
func applyOrientation(src image.Image, o Orientation) image.Image {
	if !o.Transforms() {
		return src
	}
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	dw, dh := w, h
	if o.SwapsAxes() {
		dw, dh = h, w
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := src.At(b.Min.X+x, b.Min.Y+y)
			var nx, ny int
			switch o {
			case 2: // mirrored
				nx, ny = w-1-x, y
			case 3: // rotated 180
				nx, ny = w-1-x, h-1-y
			case 4: // mirrored, then 180
				nx, ny = x, h-1-y
			case 5: // mirrored, then rotated 270 clockwise
				nx, ny = y, x
			case 6: // rotated 90 clockwise
				nx, ny = h-1-y, x
			case 7: // mirrored, then rotated 90 clockwise
				nx, ny = h-1-y, w-1-x
			case 8: // rotated 270 clockwise
				nx, ny = y, w-1-x
			}
			dst.Set(nx, ny, c)
		}
	}
	return dst
}

// describeOrientation says what was done, for the report a person reads.
func describeOrientation(o Orientation) string {
	switch o {
	case 2:
		return "flipped it left to right, as its EXIF orientation asked"
	case 3:
		return "turned it 180°, as its EXIF orientation asked"
	case 4:
		return "flipped it top to bottom, as its EXIF orientation asked"
	case 5, 7:
		return "flipped and turned it, as its EXIF orientation asked"
	case 6:
		return "turned it 90° clockwise, as its EXIF orientation asked"
	case 8:
		return "turned it 90° anticlockwise, as its EXIF orientation asked"
	}
	return ""
}
