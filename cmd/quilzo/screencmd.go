// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"math/rand/v2"

	"github.com/quilzo/quilzo/internal/screen"
	"github.com/quilzo/quilzo/internal/sframe"
)

// What sharing a screen costs, measured rather than claimed.
//
// A video codec applied to a code editor spends its bitrate defending text
// against a transform designed to throw away what the eye will not miss —
// and at eight pixels tall what the eye misses is the difference between a
// colon and a semicolon. This codec is lossless instead, and the arithmetic
// that makes that affordable is the damage model: typing changes one tile out
// of five hundred.
//
// `screen cost` runs the encoder over a synthetic editor at a given size and
// prints what a session would actually use, including the frame encryption
// from internal/sframe, because the overhead of the second is only
// interesting next to the first.

func cmdScreen(args []string) error {
	if len(args) == 0 {
		args = []string{"cost"}
	}
	switch args[0] {
	case "cost":
		return screenCost(args[1:])
	default:
		return fmt.Errorf("unknown screen command %q; try cost", args[0])
	}
}

func screenCost(args []string) error {
	fs := flag.NewFlagSet("cost", flag.ContinueOnError)
	width := fs.Int("width", 1920, "the shared screen's width")
	height := fs.Int("height", 1080, "its height")
	fps := fs.Int("fps", 30, "frames a second")
	suite := fs.Int("suite", int(sframe.AES128GCMSHA256128),
		"which SFrame cipher suite the frames go out under")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cipher := sframe.Suite(*suite)
	if !cipher.Known() {
		return fmt.Errorf("%d is not a registered cipher suite", *suite)
	}

	f := synthetic(*width, *height)
	e := screen.NewEncoder()
	_, key, err := e.Encode(f)
	if err != nil {
		return err
	}
	// One character changes.
	typed := screen.Frame{Width: f.Width, Height: f.Height,
		Pix: append([]byte(nil), f.Pix...)}
	paint(typed, f.Width/3, f.Height/3, 5, 7,
		[]byte{0xa6, 0xe3, 0xa1, 0xff})
	_, edit, err := e.Encode(typed)
	if err != nil {
		return err
	}
	_, still, err := e.Encode(typed)
	if err != nil {
		return err
	}

	// The encryption on top. Two bytes of header plus the tag, per frame.
	perFrame := cipher.Overhead(2)
	typing := (edit.Bytes + perFrame) * *fps
	idle := (still.Bytes + perFrame) * *fps

	if w.JSON(map[string]any{
		"raw_frame": key.Source, "key_frame": key.Bytes,
		"keystroke": edit.Bytes, "still": still.Bytes,
		"cipher": cipher.String(), "cipher_overhead": perFrame,
		"typing_bytes_per_second": typing,
		"idle_bytes_per_second":   idle,
	}) {
		return nil
	}
	w.Human("%s%dx%d at %d frame(s) a second%s\n", bold, *width, *height,
		*fps, reset)
	w.Human("  %s%d bytes a frame uncompressed%s\n\n", dim, key.Source,
		reset)
	w.Human("  key frame    %8d bytes  %s(%.0fx, losslessly)%s\n",
		key.Bytes, dim, key.Ratio(), reset)
	w.Human("  a keystroke  %8d bytes  %s(%d of %d tile(s))%s\n",
		edit.Bytes, dim, edit.Changed, edit.Tiles, reset)
	w.Human("  still        %8d bytes\n\n", still.Bytes)
	w.Human("  %s+%d bytes a frame for %s%s\n", dim, perFrame, cipher,
		reset)
	w.Human("  %styping: about %d KB/s.  idle: about %d KB/s%s\n",
		bold, typing/1024, idle/1024, reset)
	w.Human("\n  %sthis is a codec for screens and not for cameras: a "+
		"photograph or a video playing in a window has no palette and no "+
		"unchanged tiles, and the encoder reports that rather than "+
		"quietly sending the lot%s\n", dim, reset)
	return nil
}

// synthetic builds something with the structure of a code editor.
//
// Flat colour, hard edges, a small palette per region. Not a photograph of
// one: what the arithmetic turns on is the structure, and a screenshot
// checked into a repository is a licence question and a megabyte.
func synthetic(w, h int) screen.Frame {
	f := screen.Frame{Width: w, Height: h, Pix: make([]byte, w*h*4)}
	bg := []byte{0x1e, 0x1e, 0x2e, 0xff}
	gutter := []byte{0x18, 0x18, 0x25, 0xff}
	for y := range h {
		for x := range w {
			c := bg
			if x < 48 {
				c = gutter
			}
			copy(f.Pix[(y*w+x)*4:], c)
		}
	}
	r := rand.New(rand.NewPCG(7, 11))
	text := []byte{0xcd, 0xd6, 0xf4, 0xff}
	keyword := []byte{0xcb, 0xa6, 0xf7, 0xff}
	for line := 0; line*16+12 < h; line++ {
		y, x := line*16+4, 56
		for x < w-8 {
			run := 3 + r.IntN(6)
			c := text
			if r.IntN(5) == 0 {
				c = keyword
			}
			paint(f, x, y, run, 7, c)
			x += run + 1 + r.IntN(4)
		}
	}
	return f
}

func paint(f screen.Frame, x0, y0, w, h int, c []byte) {
	for dy := range h {
		for dx := range w {
			x, y := x0+dx, y0+dy
			if x < 0 || y < 0 || x >= f.Width || y >= f.Height {
				continue
			}
			if (dx+dy)%3 == 0 && len(c) == 4 && c[0] != 0xa6 {
				continue
			}
			copy(f.Pix[(y*f.Width+x)*4:], c)
		}
	}
}
