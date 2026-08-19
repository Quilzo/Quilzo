// Command gendemoassets draws the demonstration's images.
//
// # Why these are generated rather than photographed
//
// A demonstration that ships stock photography ships a licence question with
// it, and the answer changes depending on who redistributes the binary. These
// are drawn by this program, so the answer is the same for everybody: they are
// part of the source, under the same licence as the rest of it.
//
// The package documentation has claimed the images were generated since the
// first demonstration shipped. It was true, and the program that did it was not
// committed — so the claim was unverifiable and the images were unreproducible.
// This is that program, kept.
//
// # What they are
//
// Product plates: a soft studio gradient with one geometric form standing in
// for the object. Not an attempt to look like a photograph. A shop
// demonstration full of convincing fake product photography is a demonstration
// that lies about what it is, and the alt text would have to lie with it.
//
//	go run ./scripts/gendemoassets internal/demo/assets
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/rand"
	"os"
	"path/filepath"
)

const size = 480

// plate is one image: a hue, and which form stands in for the object.
type plate struct {
	name string
	hue  float64 // degrees
	form string  // book, pen, card, box, roll, jar
}

func main() {
	dir := "internal/demo/assets"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	for _, p := range []plate{
		{"notebook-linen", 28, "book"},
		{"notebook-pocket", 196, "book"},
		{"pen-brass", 44, "pen"},
		{"pen-copper", 14, "pen"},
		{"cards-correspondence", 158, "card"},
		{"cards-plain", 214, "card"},
		{"box-archive", 112, "box"},
		{"box-desk", 264, "box"},
		{"tape-gummed", 340, "roll"},
		{"ink-walnut", 20, "jar"},
		{"ink-indigo", 232, "jar"},
		{"blotter-desk", 88, "card"},
	} {
		img := draw(p)
		path := filepath.Join(dir, p.name+".png")
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := png.Encode(f, img); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		f.Close()
		st, _ := os.Stat(path)
		fmt.Printf("%-24s %6d bytes\n", p.name, st.Size())
	}
}

func draw(p plate) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	// The ground: a vertical gradient from a light tint of the hue to a
	// slightly deeper one, with a soft radial lift where a light would be.
	top := hsl(p.hue, 0.30, 0.93)
	bottom := hsl(p.hue, 0.34, 0.82)
	lightX, lightY := 0.36*size, 0.28*size

	// Seeded from the name, so the same plate is byte-identical on every run.
	// A generator whose output changes each time makes every regeneration a
	// diff nobody can review.
	rng := rand.New(rand.NewSource(seedOf(p.name)))

	for y := 0; y < size; y++ {
		t := float64(y) / float64(size-1)
		base := lerp(top, bottom, t)
		for x := 0; x < size; x++ {
			d := math.Hypot(float64(x)-lightX, float64(y)-lightY) / (0.9 * size)
			lift := math.Max(0, 1-d*d) * 0.10
			c := lighten(base, lift)
			// A little grain, so a large flat area does not band.
			c = jitter(c, rng, 3)
			img.Set(x, y, c)
		}
	}

	ink := hsl(p.hue, 0.42, 0.30)
	shade := hsl(p.hue, 0.38, 0.42)
	switch p.form {
	case "book":
		rect(img, 130, 96, 220, 288, ink)
		rect(img, 130, 96, 26, 288, shade) // the spine
		rect(img, 176, 140, 128, 8, lighten(hsl(p.hue, 0.2, 0.9), 0))
		rect(img, 176, 168, 96, 8, lighten(hsl(p.hue, 0.2, 0.9), 0))
	case "pen":
		// A barrel on the diagonal, tapering to a nib.
		for i := 0; i < 300; i++ {
			t := float64(i) / 299
			x := 120 + t*240
			y := 360 - t*240
			w := 13 - 9*math.Pow(t, 3)
			disc(img, x, y, w, ink)
		}
		disc(img, 356, 124, 9, shade)
	case "card":
		rect(img, 108, 150, 264, 180, ink)
		rect(img, 132, 174, 216, 132, hsl(p.hue, 0.18, 0.95))
		rect(img, 156, 210, 168, 7, shade)
		rect(img, 156, 236, 120, 7, shade)
	case "box":
		rect(img, 112, 168, 256, 180, ink)
		rect(img, 112, 168, 256, 44, shade) // the lid
		rect(img, 210, 244, 60, 12, hsl(p.hue, 0.2, 0.92))
	case "roll":
		disc(img, 240, 240, 118, ink)
		disc(img, 240, 240, 44, hsl(p.hue, 0.22, 0.93))
		disc(img, 240, 240, 30, shade)
	case "jar":
		rect(img, 168, 196, 144, 148, ink)
		rect(img, 186, 160, 108, 40, shade)
		rect(img, 192, 236, 96, 76, hsl(p.hue, 0.5, 0.22))
	}
	return img
}

// seedOf turns a name into a stable seed.
func seedOf(s string) int64 {
	var h int64 = 1469598103934665603
	for _, b := range []byte(s) {
		h ^= int64(b)
		h *= 1099511628211
	}
	return h
}

func rect(img *image.RGBA, x, y, w, h int, c color.RGBA) {
	for yy := y; yy < y+h && yy < size; yy++ {
		for xx := x; xx < x+w && xx < size; xx++ {
			if xx >= 0 && yy >= 0 {
				img.Set(xx, yy, c)
			}
		}
	}
}

// disc draws an antialiased filled circle.
func disc(img *image.RGBA, cx, cy, r float64, c color.RGBA) {
	for y := int(cy - r - 2); y <= int(cy+r+2); y++ {
		for x := int(cx - r - 2); x <= int(cx+r+2); x++ {
			if x < 0 || y < 0 || x >= size || y >= size {
				continue
			}
			d := math.Hypot(float64(x)-cx, float64(y)-cy)
			a := clamp((r-d)+0.5, 0, 1)
			if a <= 0 {
				continue
			}
			old := img.RGBAAt(x, y)
			img.Set(x, y, color.RGBA{
				R: mix(old.R, c.R, a), G: mix(old.G, c.G, a),
				B: mix(old.B, c.B, a), A: 255})
		}
	}
}

func mix(a, b uint8, t float64) uint8 {
	return uint8(float64(a)*(1-t) + float64(b)*t)
}

func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }

func lerp(a, b color.RGBA, t float64) color.RGBA {
	return color.RGBA{mix(a.R, b.R, t), mix(a.G, b.G, t), mix(a.B, b.B, t), 255}
}

func lighten(c color.RGBA, by float64) color.RGBA {
	return color.RGBA{
		uint8(clamp(float64(c.R)+by*255, 0, 255)),
		uint8(clamp(float64(c.G)+by*255, 0, 255)),
		uint8(clamp(float64(c.B)+by*255, 0, 255)), 255}
}

func jitter(c color.RGBA, rng *rand.Rand, amount float64) color.RGBA {
	n := (rng.Float64() - 0.5) * 2 * amount
	return lighten(c, n/255)
}

// hsl converts to RGB. Written out rather than imported, for the same reason
// everything else here is.
func hsl(h, s, l float64) color.RGBA {
	c := (1 - math.Abs(2*l-1)) * s
	hp := math.Mod(h, 360) / 60
	x := c * (1 - math.Abs(math.Mod(hp, 2)-1))
	var r, g, b float64
	switch {
	case hp < 1:
		r, g, b = c, x, 0
	case hp < 2:
		r, g, b = x, c, 0
	case hp < 3:
		r, g, b = 0, c, x
	case hp < 4:
		r, g, b = 0, x, c
	case hp < 5:
		r, g, b = x, 0, c
	default:
		r, g, b = c, 0, x
	}
	m := l - c/2
	return color.RGBA{
		uint8(clamp((r+m)*255, 0, 255)),
		uint8(clamp((g+m)*255, 0, 255)),
		uint8(clamp((b+m)*255, 0, 255)), 255}
}
