// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package media

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"strconv"
	"strings"
)

// Editing a picture, in a system where nothing can be edited.
//
// # Why this is not Photoshop, and why that is the better model here
//
// Photoshop's default is destructive: the file you opened is the file you
// saved over. That is wrong for content generally and impossible here
// specifically — an asset is addressed by the SHA-256 of its bytes, so
// "change the file" is not an operation this library has.
//
// So an edit derives. The original stays exactly where it was, under its own
// hash, and the result is a new asset that records what was done to it and
// what it was done to. Which is Lightroom's model rather than Photoshop's, and
// for a content system it is strictly the better one:
//
//   - The original cannot be lost, because nothing overwrote it.
//   - A page changing which asset it shows is a draft commit with an author,
//     so a crop rolls back the way every other change does.
//   - The derivative goes through the same gates: the same licence, the same
//     provenance, the same accessibility requirement on its description.
//
// # What it can do, and what it deliberately cannot
//
// Geometry and one colour operation: crop, an aspect-ratio crop taken around
// the focal point somebody already set, quarter turns, mirrors, and grey.
// Those are the operations that change *what is in the picture*, which is the
// part a content system is for.
//
// Not retouching, not layers, not masks, not curves. Those want a canvas and
// a pointer, and the interface this program serves has neither — see
// internal/admin/design.go for why that is a decision rather than a gap. A
// crop that can be typed, checked, stored and rolled back is a different
// product from a brush, not a worse version of one.
//
// # Why percentages
//
// A box in pixels is a box that means something different on the rendition
// than on the original, and nothing at all if the parent is ever replaced by a
// larger scan of the same photograph. A percentage survives both. It is also
// the only spelling somebody can reasonably type into a form, which is the
// interface this has to work in.

// A Box is a rectangle as percentages of the picture it is taken from.
type Box struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
	W float64 `json:"w"`
	H float64 `json:"h"`
}

// An Edit is what was done to a picture to make another one.
//
// Applied in a fixed order — crop, then turn, then flip, then grey — because
// the operations do not commute and a recipe whose meaning depends on the
// order somebody typed it is a recipe nobody can reproduce.
type Edit struct {
	// Crop is an explicit rectangle. Exclusive with Aspect.
	Crop *Box `json:"crop,omitempty"`
	// Aspect crops to a ratio — "16:9", "1:1" — taking the largest rectangle
	// of that shape that fits, positioned around the focal point. It is what
	// object-fit: cover does in a browser, done once into a file that is
	// actually smaller rather than on every reader's device.
	Aspect string `json:"aspect,omitempty"`
	// Turn is a clockwise rotation in degrees: 90, 180 or 270.
	Turn int `json:"turn,omitempty"`
	// Flip is "across" for left-to-right or "down" for top-to-bottom.
	Flip string `json:"flip,omitempty"`
	// Grey removes the colour.
	Grey bool `json:"grey,omitempty"`
}

// Empty reports whether this edit would do nothing.
func (e Edit) Empty() bool {
	return e.Crop == nil && strings.TrimSpace(e.Aspect) == "" &&
		e.Turn == 0 && strings.TrimSpace(e.Flip) == "" && !e.Grey
}

// SwapsAxes reports whether the turn exchanges width and height.
func (e Edit) SwapsAxes() bool { return e.Turn == 90 || e.Turn == 270 }

// Validate refuses a recipe that cannot be carried out.
//
// Before anything is decoded, because a refusal that arrives after two seconds
// of resampling is a refusal somebody waited for.
func (e Edit) Validate() error {
	if e.Empty() {
		return fmt.Errorf("this would do nothing to the picture")
	}
	if e.Crop != nil && strings.TrimSpace(e.Aspect) != "" {
		return fmt.Errorf(
			"a box and an aspect ratio are two ways to say where to cut, and " +
				"they disagree; pass one")
	}
	if b := e.Crop; b != nil {
		if b.W <= 0 || b.H <= 0 {
			return fmt.Errorf("a crop with no width or no height keeps nothing")
		}
		if b.X < 0 || b.Y < 0 || b.X+b.W > 100.0001 || b.Y+b.H > 100.0001 {
			return fmt.Errorf(
				"the box runs outside the picture: %g,%g %g×%g is measured in "+
					"percentages and has to fit inside 100 by 100",
				b.X, b.Y, b.W, b.H)
		}
	}
	if a := strings.TrimSpace(e.Aspect); a != "" {
		if _, _, err := ratio(a); err != nil {
			return err
		}
	}
	switch e.Turn {
	case 0, 90, 180, 270:
	default:
		return fmt.Errorf(
			"%d° is not a quarter turn. This resamples rather than rotating "+
				"freely, and an angle between them would blur every edge in "+
				"the picture to no purpose", e.Turn)
	}
	switch strings.TrimSpace(e.Flip) {
	case "", "across", "down":
	default:
		return fmt.Errorf(
			"%q is not a way to flip; try across (left to right) or down "+
				"(top to bottom)", e.Flip)
	}
	return nil
}

// Describe writes the recipe out for a person, in the order it is applied.
func (e Edit) Describe() string {
	var did []string
	switch {
	case e.Crop != nil:
		did = append(did, fmt.Sprintf("cropped to %g%%×%g%% from %g%%,%g%%",
			e.Crop.W, e.Crop.H, e.Crop.X, e.Crop.Y))
	case strings.TrimSpace(e.Aspect) != "":
		did = append(did, "cropped to "+strings.TrimSpace(e.Aspect)+
			" around the focal point")
	}
	if e.Turn != 0 {
		did = append(did, fmt.Sprintf("turned %d° clockwise", e.Turn))
	}
	switch strings.TrimSpace(e.Flip) {
	case "across":
		did = append(did, "flipped left to right")
	case "down":
		did = append(did, "flipped top to bottom")
	}
	if e.Grey {
		did = append(did, "made grey")
	}
	if len(did) == 0 {
		return "nothing"
	}
	return strings.Join(did, ", ")
}

// Action is the C2PA action term for what this recipe did.
//
// The most significant operation wins, in the order a reader cares about:
// somebody asking what happened to a photograph wants to hear that it was
// cropped before they hear that it was turned.
func (e Edit) Action() string {
	switch {
	case e.Crop != nil || strings.TrimSpace(e.Aspect) != "":
		return "c2pa.cropped"
	case e.Turn != 0 || strings.TrimSpace(e.Flip) != "":
		return "c2pa.orientation"
	case e.Grey:
		return "c2pa.color_adjustments"
	}
	return "c2pa.edited"
}

// ratio reads "16:9" into two numbers.
func ratio(s string) (w, h int, err error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf(
			"%q is not an aspect ratio; they are written like 16:9", s)
	}
	w, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || w <= 0 {
		return 0, 0, fmt.Errorf("%q has no usable width", s)
	}
	h, err = strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || h <= 0 {
		return 0, 0, fmt.Errorf("%q has no usable height", s)
	}
	// A bound, because the ratio becomes a rectangle and a picture 4000 times
	// wider than it is tall is one pixel of content and a lot of arithmetic.
	if w > 100 || h > 100 {
		return 0, 0, fmt.Errorf(
			"%q is a more extreme shape than a picture can usefully be; the "+
				"sides are limited to 100", s)
	}
	return w, h, nil
}

// boxFor works out the rectangle in pixels that an edit asks for.
//
// focus may be nil, which means the centre — the same default Focus.Position
// uses, so a picture with no focal point crops the way a browser would.
func boxFor(e Edit, w, h int, focus *Focus) (image.Rectangle, error) {
	full := image.Rect(0, 0, w, h)
	switch {
	case e.Crop != nil:
		b := e.Crop
		r := image.Rect(
			int(float64(w)*b.X/100+0.5),
			int(float64(h)*b.Y/100+0.5),
			int(float64(w)*(b.X+b.W)/100+0.5),
			int(float64(h)*(b.Y+b.H)/100+0.5),
		)
		r = r.Intersect(full)
		if r.Dx() < 1 || r.Dy() < 1 {
			return full, fmt.Errorf(
				"that box is smaller than one pixel of this %d×%d picture", w, h)
		}
		return r, nil

	case strings.TrimSpace(e.Aspect) != "":
		rw, rh, err := ratio(e.Aspect)
		if err != nil {
			return full, err
		}
		// The largest rectangle of the asked-for shape that fits: take the
		// full width and see whether the height it implies fits, and if not
		// take the full height instead. One of the two always works, because
		// one of them is limited by the side the picture has least of.
		cw, ch := w, w*rh/rw
		if ch > h {
			ch = h
			cw = h * rw / rh
		}
		if cw < 1 || ch < 1 {
			return full, fmt.Errorf(
				"a %s crop of a %d×%d picture has no area", e.Aspect, w, h)
		}
		// Positioned around the focal point, clamped to stay inside. This is
		// object-position doing its job: the point somebody marked as the
		// subject stays in frame.
		fx, fy := 50, 50
		if focus != nil {
			// Clamped the same way Position clamps before it reaches a
			// stylesheet: a record that arrived some other way — a hand edit,
			// an import — must not be able to put the crop outside the
			// picture.
			fx, fy = clampPercent(focus.X), clampPercent(focus.Y)
		}
		x := w*fx/100 - cw/2
		y := h*fy/100 - ch/2
		if x < 0 {
			x = 0
		}
		if y < 0 {
			y = 0
		}
		if x+cw > w {
			x = w - cw
		}
		if y+ch > h {
			y = h - ch
		}
		return image.Rect(x, y, x+cw, y+ch), nil
	}
	return full, nil
}

// ApplyEdit carries out a recipe.
//
// Written as separate passes rather than one fused loop: each is a few lines
// and obviously right on its own, and the fused version is where an off-by-one
// in the mirror hides behind a correct-looking crop.
func ApplyEdit(src image.Image, e Edit, focus *Focus) (image.Image, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	b := src.Bounds()
	r, err := boxFor(e, b.Dx(), b.Dy(), focus)
	if err != nil {
		return nil, err
	}

	out := cropTo(src, r)
	if e.Turn != 0 {
		out = turn(out, e.Turn)
	}
	switch strings.TrimSpace(e.Flip) {
	case "across":
		out = mirror(out, true)
	case "down":
		out = mirror(out, false)
	}
	if e.Grey {
		out = greyscale(out)
	}
	return out, nil
}

// cropTo copies the rectangle out, in the source's own coordinates.
//
// A copy rather than a SubImage view: the result is encoded immediately, and
// image/jpeg writes from Bounds().Min, so a view whose origin is not zero
// encodes correctly and then confuses every later reader of its size.
func cropTo(src image.Image, r image.Rectangle) image.Image {
	b := src.Bounds()
	r = r.Add(b.Min).Intersect(b)
	dst := image.NewRGBA(image.Rect(0, 0, r.Dx(), r.Dy()))
	for y := 0; y < r.Dy(); y++ {
		for x := 0; x < r.Dx(); x++ {
			dst.Set(x, y, src.At(r.Min.X+x, r.Min.Y+y))
		}
	}
	return dst
}

// turn rotates clockwise by a quarter, a half or three quarters.
func turn(src image.Image, degrees int) image.Image {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	dw, dh := w, h
	if degrees == 90 || degrees == 270 {
		dw, dh = h, w
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := src.At(b.Min.X+x, b.Min.Y+y)
			switch degrees {
			case 90:
				dst.Set(h-1-y, x, c)
			case 180:
				dst.Set(w-1-x, h-1-y, c)
			case 270:
				dst.Set(y, w-1-x, c)
			default:
				dst.Set(x, y, c)
			}
		}
	}
	return dst
}

// mirror flips across the vertical axis, or down across the horizontal one.
func mirror(src image.Image, across bool) image.Image {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := src.At(b.Min.X+x, b.Min.Y+y)
			if across {
				dst.Set(w-1-x, y, c)
			} else {
				dst.Set(x, h-1-y, c)
			}
		}
	}
	return dst
}

// greyscale removes the colour, keeping the alpha.
//
// Rec. 601 luma rather than an average of the channels. An average turns a
// saturated red and a saturated blue into the same grey, which is how a chart
// with a key becomes unreadable — and unreadable is the failure this is most
// often used to avoid.
func greyscale(src image.Image) image.Image {
	b := src.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			r, g, bl, a := src.At(b.Min.X+x, b.Min.Y+y).RGBA()
			lum := (299*uint32(r) + 587*uint32(g) + 114*uint32(bl)) / 1000
			dst.Set(x, y, color.RGBA64{
				R: uint16(lum), G: uint16(lum), B: uint16(lum), A: uint16(a)})
		}
	}
	return dst
}

// Derive makes the bytes of an edited copy.
//
// Everything the upload pipeline does, in the same order and for the same
// reasons: the orientation tag is honoured before anything else (idempotent —
// a parent this library stored carries none), the recipe is applied, and the
// result is bounded by the same maximum size an upload is. What it does not do
// is change the format. Cropping a PNG and being handed a JPEG is a surprise,
// and the two have different extensions, different MIME types and different
// answers about transparency.
func Derive(format string, body []byte, e Edit, focus *Focus, opt Options) (
	Optimised, error) {

	if err := e.Validate(); err != nil {
		return Optimised{}, err
	}
	opt = opt.withDefaults()
	switch format {
	case "png", "jpeg", "gif":
	default:
		return Optimised{}, fmt.Errorf(
			"this edits PNG, JPEG and GIF, and %s is not one of them: there "+
				"is no decoder here for it", format)
	}

	img, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		return Optimised{}, fmt.Errorf("cannot decode the picture to edit it: %w", err)
	}
	if t := orientationOf(format, body); t.Transforms() {
		img = applyOrientation(img, t)
	}

	edited, err := ApplyEdit(img, e, focus)
	if err != nil {
		return Optimised{}, err
	}

	out := Optimised{Format: format, Was: len(body)}
	b := edited.Bounds()
	out.Width, out.Height = b.Dx(), b.Dy()
	out.Did = append(out.Did, e.Describe())

	if opt.MaxWidth > 0 || opt.MaxHeight > 0 {
		if resized, w, h, did := fit(edited, opt.MaxWidth, opt.MaxHeight); did {
			edited = resized
			out.Did = append(out.Did, fmt.Sprintf("resized %dx%d to %dx%d",
				out.Width, out.Height, w, h))
			out.Width, out.Height = w, h
		}
	}

	encoded, encFormat, err := encode(edited, format, opt)
	if err != nil {
		return Optimised{}, err
	}
	out.Body, out.Format, out.Now = encoded, encFormat, len(encoded)
	return out, nil
}
