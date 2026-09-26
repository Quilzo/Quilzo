// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package screen is a codec for screen content, and deliberately not one for
// video.
//
// # Why writing a video codec would be a mistake
//
// AV1 took a consortium several years and hundreds of engineers. VP9 took
// Google years before that. A codec written here would be somewhere between
// five and ten times worse per bit than any of them, would have no hardware
// decoder on any device, and would therefore cost battery on every phone it
// ran on. There is no version of that trade worth making, and a project that
// made it would be spending its distinctiveness on the one problem the
// industry has most thoroughly solved.
//
// # Why screen content is a different problem
//
// Video codecs are built on assumptions about natural images: smooth
// gradients, motion between frames, and an eye that does not notice small
// errors. Screen content breaks all three. A terminal is flat colour with
// hard edges; a code editor changes one character between frames and nothing
// else; and the eye notices small errors immediately, because a small error
// in a letterform is a different letter.
//
// That last point is the whole argument. Every screen share on every video
// platform runs the picture through a transform designed to discard what the
// eye will not miss, and applied to eight-pixel-tall text it discards the
// serifs, the dot on an i and the difference between a colon and a
// semicolon. Anybody who has tried to read code over a call has seen it. The
// usual answer is to raise the bitrate until it stops, which works and costs
// several megabits.
//
// So this is lossless. Not high quality, not visually lossless — lossless.
// Text is either right or it is not, and a codec that is right by
// construction needs no bitrate to defend it.
//
// # The compression is the damage model
//
// Typing a character changes one 64-pixel tile out of five hundred. Moving a
// cursor changes one. Scrolling changes everything, and there is no clever
// way round that. So the first thing the encoder does is work out which tiles
// differ from the last frame, and the rest of the work happens only on those.
//
// Within a changed tile the encoding is chosen by what is in it: one colour,
// two colours, sixteen colours, or give up and send the pixels. Two colours
// at one bit per pixel is the text case and it is where most of the win is.
//
// # What this is bad at, and says so
//
// Natural images. A photograph or a video playing in a window has no small
// palette and no unchanged tiles, so every tile falls through to raw and the
// output is larger than the input before the final deflate saves it. The
// encoder counts that and reports it, because a codec that silently emits
// fifty megabytes a second when pointed at the wrong content is worse than
// one that says it is the wrong tool.
//
// A codec nobody else implements is also a codec only this client can decode.
// That is a real cost, it is the price of being right about text, and it is
// why this sits behind the same frame encryption as everything else rather
// than pretending to be an interchange format.
package screen

import "fmt"

// TileSize is the edge of a tile, in pixels.
//
// Sixty-four. Small enough that typing a character dirties one tile rather
// than a quarter of the screen, large enough that the per-tile header is not
// the message. At 1920 by 1080 it is 510 tiles.
const TileSize = 64

// Magic identifies a frame, and Version what it was encoded by.
const (
	Magic   = "QSCR"
	Version = 1
)

// MaxDimension bounds a frame.
//
// Sixteen thousand pixels a side: larger than any display and small enough
// that width times height times four cannot overflow an int on a 32-bit
// build, which is the arithmetic a decoder does on numbers it was handed.
const MaxDimension = 16384

// Frame is a screen, as four bytes a pixel.
type Frame struct {
	Width, Height int
	// Pix is row-major, four bytes a pixel, in whatever order the capture
	// produced. Nothing here interprets the channels: the codec is lossless
	// and a lossless codec does not need to know what the bytes mean.
	Pix []byte
}

// Valid reports whether the frame's dimensions and buffer agree.
func (f Frame) Valid() error {
	if f.Width <= 0 || f.Height <= 0 {
		return fmt.Errorf("a frame of %dx%d has no pixels", f.Width,
			f.Height)
	}
	if f.Width > MaxDimension || f.Height > MaxDimension {
		return fmt.Errorf("a frame of %dx%d is larger than any display",
			f.Width, f.Height)
	}
	if want := f.Width * f.Height * 4; len(f.Pix) != want {
		return fmt.Errorf("a %dx%d frame needs %d bytes and has %d",
			f.Width, f.Height, want, len(f.Pix))
	}
	return nil
}

// tiles is how many tiles across and down a frame is.
func (f Frame) tiles() (across, down int) {
	return (f.Width + TileSize - 1) / TileSize,
		(f.Height + TileSize - 1) / TileSize
}

// tile copies one tile out of the frame, row by row.
//
// The last column and row are partial, so a tile carries its own width and
// height rather than being assumed square.
func (f Frame) tile(tx, ty int) (pix []byte, w, h int) {
	x0, y0 := tx*TileSize, ty*TileSize
	w, h = TileSize, TileSize
	if x0+w > f.Width {
		w = f.Width - x0
	}
	if y0+h > f.Height {
		h = f.Height - y0
	}
	pix = make([]byte, 0, w*h*4)
	for y := y0; y < y0+h; y++ {
		start := (y*f.Width + x0) * 4
		pix = append(pix, f.Pix[start:start+w*4]...)
	}
	return pix, w, h
}

// putTile writes a tile back into the frame.
func (f Frame) putTile(tx, ty int, pix []byte, w, h int) {
	x0, y0 := tx*TileSize, ty*TileSize
	for y := range h {
		start := ((y0+y)*f.Width + x0) * 4
		copy(f.Pix[start:start+w*4], pix[y*w*4:(y+1)*w*4])
	}
}

// How a tile was encoded.
const (
	// encSolid is one colour for the whole tile.
	encSolid byte = 1
	// encMono is two colours, one bit a pixel. The text case.
	encMono byte = 2
	// encPalette is up to sixteen colours, four bits a pixel.
	encPalette byte = 3
	// encRaw is the pixels. What a photograph gets.
	encRaw byte = 4
)

// MaxPalette is how many distinct colours a tile may have before it is sent
// raw.
//
// Sixteen, because four bits a pixel is a clean eighth of the raw size and
// because a tile of text or interface has two to eight. Above sixteen the
// content is a gradient or a photograph, and a larger palette would spend
// header on something that was never going to compress.
const MaxPalette = 16

// Stats say what an encoder did, which is how a caller finds out this is the
// wrong codec for what it was pointed at.
type Stats struct {
	// Tiles is how many the frame has, and Changed how many differed.
	Tiles   int `json:"tiles"`
	Changed int `json:"changed"`
	// Solid, Mono, Palette and Raw are how the changed ones were encoded.
	Solid   int `json:"solid"`
	Mono    int `json:"mono"`
	Palette int `json:"palette"`
	Raw     int `json:"raw"`
	// Bytes is the encoded length and Source the frame's raw length.
	Bytes  int `json:"bytes"`
	Source int `json:"source"`
	// Key says every tile was sent.
	Key bool `json:"key"`
}

// Ratio is how much smaller the frame became.
func (s Stats) Ratio() float64 {
	if s.Bytes == 0 {
		return 0
	}
	return float64(s.Source) / float64(s.Bytes)
}

// Photographic reports whether the content is the kind this codec is bad at.
//
// More than half the changed tiles falling through to raw means no small
// palettes and no flat colour, which is a photograph, a video playing in a
// window, or a desktop wallpaper somebody is very proud of. Reported rather
// than hidden: a codec that silently emits fifty megabytes a second when
// pointed at the wrong content is worse than one that says so.
func (s Stats) Photographic() bool {
	return s.Changed >= 8 && s.Raw*2 > s.Changed
}

// Why explains what happened to a frame, in one line.
func (s Stats) Why() string {
	switch {
	case s.Changed == 0:
		return "nothing changed; the frame is a header"
	case s.Photographic():
		return fmt.Sprintf(
			"%d of %d changed tile(s) had no palette to speak of. This is "+
				"a photograph or a video playing in a window, which is the "+
				"content this codec is worst at — %.1fx against raw, where "+
				"a video codec would be a hundred", s.Raw, s.Changed,
			s.Ratio())
	case s.Mono*2 > s.Changed:
		return fmt.Sprintf(
			"%d of %d changed tile(s) were two colours at one bit a pixel, "+
				"which is text. %.0fx against raw, losslessly", s.Mono,
			s.Changed, s.Ratio())
	default:
		return fmt.Sprintf(
			"%d of %d tile(s) changed; %.0fx against raw, losslessly",
			s.Changed, s.Tiles, s.Ratio())
	}
}
