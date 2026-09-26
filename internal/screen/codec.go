// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package screen

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
)

// Encoding a frame, and the three decisions that make it small.
//
// First: which tiles differ from the last frame. Typing changes one, and
// everything downstream then works on one tile rather than five hundred.
//
// Second: within a changed tile, how many distinct colours there are. One is
// a header; two is a bit a pixel and is what text looks like; sixteen is four
// bits; more than that is a photograph and goes out as pixels.
//
// Third: deflate over the whole payload, from the standard library. The tile
// encodings above remove the structure deflate is bad at — long runs of
// four-byte colours — and deflate then removes the repetition they leave.
// Either alone is much worse than both.

// MaxFrame bounds an encoded frame a decoder will accept.
//
// Thirty-two megabytes. A 4K frame is 33 million bytes raw and this codec is
// only ever larger than raw by a header, so anything past this is a frame
// claiming to be a size it cannot be — and a decoder that allocated whatever
// it was told to would be a way to exhaust memory from the network.
const MaxFrame = 32 << 20

// Encoder holds the previous frame, which is what makes a delta possible.
//
// Not safe for concurrent use: a screen has one encoder and the previous
// frame is state.
type Encoder struct {
	previous Frame
	// force makes the next frame a key frame.
	force bool
}

// NewEncoder starts one. The first frame it sees is a key frame.
func NewEncoder() *Encoder { return &Encoder{force: true} }

// Keyframe asks for the next frame to carry every tile.
//
// Needed whenever a receiver joins, and after any loss: this codec has no
// error concealment and a decoder that missed a tile is wrong until it is
// sent again. Saying so is better than pretending a lost packet is
// survivable.
func (e *Encoder) Keyframe() { e.force = true }

// Encode produces a frame, against whatever the encoder last saw.
func (e *Encoder) Encode(f Frame) ([]byte, Stats, error) {
	var s Stats
	if err := f.Valid(); err != nil {
		return nil, s, err
	}
	key := e.force || e.previous.Width != f.Width ||
		e.previous.Height != f.Height
	across, down := f.tiles()
	s.Tiles, s.Key = across*down, key
	s.Source = len(f.Pix)

	// The changed-tile bitmap, one bit a tile, and then the tiles.
	bitmap := make([]byte, (s.Tiles+7)/8)
	var body bytes.Buffer
	for ty := range down {
		for tx := range across {
			pix, w, h := f.tile(tx, ty)
			if !key {
				was, _, _ := e.previous.tile(tx, ty)
				if bytes.Equal(was, pix) {
					continue
				}
			}
			index := ty*across + tx
			bitmap[index/8] |= 1 << (index % 8)
			s.Changed++
			writeTile(&body, pix, w, h, &s)
		}
	}

	var out bytes.Buffer
	out.WriteString(Magic)
	out.WriteByte(Version)
	var flags byte
	if key {
		flags |= 1
	}
	out.WriteByte(flags)
	var dims [8]byte
	binary.BigEndian.PutUint32(dims[0:4], uint32(f.Width))
	binary.BigEndian.PutUint32(dims[4:8], uint32(f.Height))
	out.Write(dims[:])

	// Deflate over the bitmap and the tiles together. The tile encodings
	// removed the structure deflate handles badly; what is left is
	// repetition, which is what it is for.
	payload := append(bitmap, body.Bytes()...)
	packed, err := deflate(payload)
	if err != nil {
		return nil, s, err
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(payload)))
	out.Write(size[:])
	out.Write(packed)

	e.previous = Frame{Width: f.Width, Height: f.Height,
		Pix: append([]byte(nil), f.Pix...)}
	e.force = false
	s.Bytes = out.Len()
	return out.Bytes(), s, nil
}

// writeTile encodes one tile by whatever fits it.
func writeTile(out *bytes.Buffer, pix []byte, w, h int, s *Stats) {
	palette, ok := paletteOf(pix)
	switch {
	case ok && len(palette) == 1:
		s.Solid++
		out.WriteByte(encSolid)
		out.Write(palette[0][:])

	case ok && len(palette) == 2:
		s.Mono++
		out.WriteByte(encMono)
		out.Write(palette[0][:])
		out.Write(palette[1][:])
		out.Write(pack(pix, palette, 1, w, h))

	case ok:
		s.Palette++
		out.WriteByte(encPalette)
		out.WriteByte(byte(len(palette)))
		for _, c := range palette {
			out.Write(c[:])
		}
		out.Write(pack(pix, palette, 4, w, h))

	default:
		s.Raw++
		out.WriteByte(encRaw)
		out.Write(pix)
	}
}

// colour is one pixel.
type colour [4]byte

// paletteOf returns the distinct colours in a tile, in first-seen order, and
// whether there are few enough to be worth a palette.
//
// First-seen order rather than sorted, because the order only has to match
// between the two halves of pack and unpack and sorting would be work for
// nothing.
func paletteOf(pix []byte) ([]colour, bool) {
	var out []colour
	seen := map[colour]bool{}
	for i := 0; i+4 <= len(pix); i += 4 {
		c := colour{pix[i], pix[i+1], pix[i+2], pix[i+3]}
		if seen[c] {
			continue
		}
		if len(out) == MaxPalette {
			return nil, false
		}
		seen[c] = true
		out = append(out, c)
	}
	return out, true
}

// pack writes palette indices at the given bit width, row by row.
//
// Rows are byte-aligned. That wastes up to seven bits a row and makes the
// decoder's arithmetic obvious, which on a routine that runs five hundred
// times a frame at thirty frames a second is the trade worth taking: the
// wasted bits are under one per cent and an off-by-one here corrupts a
// picture in a way nobody can read back from the symptom.
func pack(pix []byte, palette []colour, bits, w, h int) []byte {
	index := map[colour]byte{}
	for i, c := range palette {
		index[c] = byte(i)
	}
	perRow := (w*bits + 7) / 8
	out := make([]byte, perRow*h)
	for y := range h {
		row := out[y*perRow : (y+1)*perRow]
		for x := range w {
			at := (y*w + x) * 4
			v := index[colour{pix[at], pix[at+1], pix[at+2], pix[at+3]}]
			bit := x * bits
			row[bit/8] |= v << (8 - bits - bit%8)
		}
	}
	return out
}

// unpack reverses it.
func unpack(in []byte, palette []colour, bits, w, h int) ([]byte, error) {
	perRow := (w*bits + 7) / 8
	if len(in) < perRow*h {
		return nil, fmt.Errorf(
			"a %dx%d tile at %d bit(s) a pixel needs %d bytes and has %d",
			w, h, bits, perRow*h, len(in))
	}
	mask := byte(1<<bits - 1)
	out := make([]byte, w*h*4)
	for y := range h {
		row := in[y*perRow : (y+1)*perRow]
		for x := range w {
			bit := x * bits
			v := (row[bit/8] >> (8 - bits - bit%8)) & mask
			if int(v) >= len(palette) {
				return nil, fmt.Errorf(
					"a pixel names palette entry %d of %d", v, len(palette))
			}
			copy(out[(y*w+x)*4:], palette[v][:])
		}
	}
	return out, nil
}

// Decoder holds the previous frame, which is what a delta is against.
type Decoder struct{ previous Frame }

// NewDecoder starts one.
func NewDecoder() *Decoder { return &Decoder{} }

// Decode applies a frame to whatever the decoder last held.
func (d *Decoder) Decode(in []byte) (Frame, error) {
	if len(in) < 14 {
		return Frame{}, fmt.Errorf("this is too short to be a frame")
	}
	if string(in[:4]) != Magic {
		return Frame{}, fmt.Errorf("this is not a screen frame")
	}
	if in[4] != Version {
		return Frame{}, fmt.Errorf(
			"this frame is version %d and this build speaks %d", in[4],
			Version)
	}
	key := in[5]&1 != 0
	width := int(binary.BigEndian.Uint32(in[6:10]))
	height := int(binary.BigEndian.Uint32(in[10:14]))
	size := int(binary.BigEndian.Uint32(in[14:18]))

	out := Frame{Width: width, Height: height}
	if err := checkDimensions(width, height); err != nil {
		return Frame{}, err
	}
	if size < 0 || size > MaxFrame {
		return Frame{}, fmt.Errorf(
			"this frame says its payload is %d bytes, which is past the "+
				"%d-byte ceiling. A decoder that allocated whatever it was "+
				"told to would be a way to exhaust memory from the network",
			size, MaxFrame)
	}
	payload, err := inflate(in[18:], size)
	if err != nil {
		return Frame{}, err
	}

	switch {
	case key:
		out.Pix = make([]byte, width*height*4)
	case d.previous.Width != width || d.previous.Height != height:
		return Frame{}, fmt.Errorf(
			"this is a delta against a %dx%d frame and the last one was "+
				"%dx%d. A receiver that has missed a key frame is wrong "+
				"until it is sent another", width, height,
			d.previous.Width, d.previous.Height)
	default:
		out.Pix = append([]byte(nil), d.previous.Pix...)
	}

	across, down := out.tiles()
	count := across * down
	bits := (count + 7) / 8
	if len(payload) < bits {
		return Frame{}, fmt.Errorf("the frame has no tile map")
	}
	bitmap, body := payload[:bits], payload[bits:]

	at := 0
	for ty := range down {
		for tx := range across {
			index := ty*across + tx
			if bitmap[index/8]&(1<<(index%8)) == 0 {
				continue
			}
			w, h := TileSize, TileSize
			if tx*TileSize+w > width {
				w = width - tx*TileSize
			}
			if ty*TileSize+h > height {
				h = height - ty*TileSize
			}
			pix, used, rerr := readTile(body[at:], w, h)
			if rerr != nil {
				return Frame{}, fmt.Errorf("tile %d,%d: %w", tx, ty, rerr)
			}
			at += used
			out.putTile(tx, ty, pix, w, h)
		}
	}
	d.previous = Frame{Width: width, Height: height,
		Pix: append([]byte(nil), out.Pix...)}
	return out, nil
}

// checkDimensions refuses a frame that claims a size nothing can hold.
//
// Before any allocation. The numbers came off the wire, and width times
// height times four is the size of the buffer a decoder is about to make.
func checkDimensions(width, height int) error {
	if width <= 0 || height <= 0 {
		return fmt.Errorf("this frame claims to be %dx%d", width, height)
	}
	if width > MaxDimension || height > MaxDimension {
		return fmt.Errorf(
			"this frame claims to be %dx%d, which is larger than any "+
				"display and is the shape of a number chosen to make a "+
				"decoder allocate", width, height)
	}
	return nil
}

// readTile decodes one tile and says how many bytes it took.
func readTile(in []byte, w, h int) ([]byte, int, error) {
	if len(in) == 0 {
		return nil, 0, fmt.Errorf("the frame ends where a tile should start")
	}
	switch in[0] {
	case encSolid:
		if len(in) < 5 {
			return nil, 0, fmt.Errorf("a solid tile with no colour")
		}
		pix := make([]byte, w*h*4)
		for i := 0; i < len(pix); i += 4 {
			copy(pix[i:], in[1:5])
		}
		return pix, 5, nil

	case encMono:
		if len(in) < 9 {
			return nil, 0, fmt.Errorf("a two-colour tile with one colour")
		}
		palette := []colour{
			{in[1], in[2], in[3], in[4]},
			{in[5], in[6], in[7], in[8]},
		}
		n := ((w*1+7)/8)*h + 9
		if len(in) < n {
			return nil, 0, fmt.Errorf("a two-colour tile is short")
		}
		pix, err := unpack(in[9:n], palette, 1, w, h)
		return pix, n, err

	case encPalette:
		if len(in) < 2 {
			return nil, 0, fmt.Errorf("a palette tile with no palette")
		}
		size := int(in[1])
		if size < 1 || size > MaxPalette {
			return nil, 0, fmt.Errorf(
				"a tile claims a palette of %d, and the ceiling is %d",
				size, MaxPalette)
		}
		head := 2 + size*4
		if len(in) < head {
			return nil, 0, fmt.Errorf("a palette tile is short")
		}
		palette := make([]colour, size)
		for i := range palette {
			copy(palette[i][:], in[2+i*4:6+i*4])
		}
		n := head + ((w*4+7)/8)*h
		if len(in) < n {
			return nil, 0, fmt.Errorf("a palette tile is short")
		}
		pix, err := unpack(in[head:n], palette, 4, w, h)
		return pix, n, err

	case encRaw:
		n := 1 + w*h*4
		if len(in) < n {
			return nil, 0, fmt.Errorf("a raw tile is short")
		}
		return append([]byte(nil), in[1:n]...), n, nil
	}
	return nil, 0, fmt.Errorf("%d is not a tile encoding", in[0])
}

func deflate(in []byte) ([]byte, error) {
	var out bytes.Buffer
	w, err := flate.NewWriter(&out, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(in); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// inflate expands a payload, refusing one that does not stop where it said.
//
// The declared size is the ceiling as well as the expectation: a compressed
// stream that expands to a hundred times what it claims is the oldest attack
// on a decompressor, and reading into a bounded buffer is the whole defence.
func inflate(in []byte, size int) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(in))
	defer r.Close()
	out := make([]byte, size)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf(
			"this frame said it holds %d bytes and does not: %w", size, err)
	}
	// One more byte would mean it holds more than it declared.
	var extra [1]byte
	if n, _ := r.Read(extra[:]); n > 0 {
		return nil, fmt.Errorf(
			"this frame expands past the %d bytes it declared", size)
	}
	return out, nil
}
