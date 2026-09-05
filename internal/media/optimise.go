package media

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	// Aliased because this package's tests already declare helpers called png
	// and jpeg, and a collision here would mean editing working tests to
	// accommodate a new file — the wrong direction.
	gifenc "image/gif"
	jpegenc "image/jpeg"
	pngenc "image/png"
	"os/exec"
	"strconv"
	"strings"
)

// Optimising an upload, and an honest account of what that can and cannot mean
// here.
//
// The obvious ask is "compress to WebP or AVIF". Neither is in Go's standard
// library — not the encoder, not the decoder, not the format. Three ways to get
// one, and the constraint decides:
//
//	A third-party encoder. Several good pure-Go ones exist. This program has no
//	dependencies and refuses them in CI, so this is closed.
//
//	Write a VP8L encoder. Genuinely feasible — it is LZ77, Huffman and colour
//	transforms, roughly a PNG encoder with more steps. It is also fifteen
//	hundred lines of new parsing in the one code path that touches files
//	strangers upload, to gain 13–23% over PNG. That trade is bad today and the
//	reasoning is written down so it can be revisited when the value changes.
//
//	Use cwebp if the operator has it. Taken. It is not a build dependency, it
//	is detected rather than required, and the pipeline works without it.
//
// What is done natively is the part that actually matters, and it is not the
// codec:
//
//   - **Metadata is stripped.** A photograph from a phone carries GPS
//     coordinates, a serial number, and often a full-size embedded thumbnail.
//     Publishing an author's home address alongside their article is a worse
//     failure than serving a file that is 20% too large, and it is the one
//     nobody notices. Re-encoding through the standard library drops every
//     ancillary chunk, which makes this a property of the pipeline rather than
//     a filter somebody has to remember.
//   - **Oversized images are resized.** A six-thousand-pixel photograph
//     displayed in an eight-hundred-pixel column is the actual bloat. No codec
//     recovers that; the resize does, and it is usually a bigger saving than
//     the format change everyone asks for.
//   - **The cost is reported before it ships.** A page whose media adds up to
//     four megabytes is a page that fails its Core Web Vitals, and the moment
//     to say so is while somebody can still choose otherwise.

// Budget is what a page's media costs a visitor.
type Budget struct {
	// Bytes is the total transferred for one page's media.
	Bytes int
	// Files is how many requests that is.
	Files int
	// Largest names the worst single offender, because "your page is heavy"
	// is not actionable and "this one photograph is 3MB" is.
	Largest     string
	LargestSize int
}

// Thresholds for the warning. Derived from what a page can transfer and still
// meet Largest Contentful Paint on a median mobile connection, rounded to
// numbers a person can hold in their head.
const (
	// BudgetWarn is where a page starts costing a visitor real time.
	BudgetWarn = 1_500_000
	// BudgetBad is where it stops being a slow page and becomes one people
	// leave before it renders.
	BudgetBad = 3_000_000
	// SingleFileWarn is one file large enough to be the whole problem.
	SingleFileWarn = 500_000
)

// Verdict describes a budget.
func (b Budget) Verdict() (level, detail string) {
	switch {
	case b.Bytes >= BudgetBad:
		return "bad", fmt.Sprintf(
			"%s across %d file(s). On a median mobile connection this is "+
				"several seconds before anything renders, and most visitors "+
				"do not wait", human(int64(b.Bytes)), b.Files)
	case b.Bytes >= BudgetWarn:
		return "warn", fmt.Sprintf(
			"%s across %d file(s), which is where a page starts costing a "+
				"visitor noticeable time", human(int64(b.Bytes)), b.Files)
	}
	return "ok", fmt.Sprintf("%s across %d file(s)", human(int64(b.Bytes)), b.Files)
}

// Optimised is the result of processing an upload.
type Optimised struct {
	Body []byte
	// Format is what it ended up as, which may differ from what arrived.
	Format string
	// Width and Height after any resize.
	Width, Height int
	// Was and Now are the sizes, so the saving can be stated rather than
	// claimed.
	Was, Now int
	// Did lists what was done, in order, for the audit record and for the
	// person who wants to know why their file changed.
	Did []string
	// StrippedMetadata is true when the original carried EXIF or similar.
	// Reported separately because it is a privacy outcome rather than a size
	// one, and the two get conflated.
	StrippedMetadata bool

	// KeptForProvenance says the file was left exactly as uploaded because it
	// carries a signed provenance manifest. Reported so that "this was not
	// optimised" is a decision somebody can see rather than a silent
	// exception that looks like the optimiser failing.
	KeptForProvenance bool
}

// Saved reports the reduction as a percentage, floored at zero.
//
// Re-encoding can produce a larger file — a photographic PNG round-tripped
// through PNG sometimes does — and reporting that as a negative saving invites
// somebody to "fix" it by turning the pipeline off. When it grows, the
// original is kept and this is zero.
func (o Optimised) Saved() int {
	if o.Was <= 0 || o.Now >= o.Was {
		return 0
	}
	return (o.Was - o.Now) * 100 / o.Was
}

// Options control the pipeline.
type Options struct {
	// MaxWidth and MaxHeight bound the stored image. Zero means no resize.
	MaxWidth, MaxHeight int
	// JPEGQuality is 1..100. Zero means 82, which is where most viewers stop
	// being able to tell and the file is roughly half the size of 95.
	JPEGQuality int
	// WebP asks for a WebP conversion using an external encoder, when one is
	// present. Ignored when it is not: the pipeline degrades to native
	// optimisation rather than failing an upload because a tool is missing.
	WebP bool
}

func (o Options) withDefaults() Options {
	if o.JPEGQuality <= 0 || o.JPEGQuality > 100 {
		o.JPEGQuality = 82
	}
	return o
}

// Optimise processes an image.
//
// Returns the original untouched when it cannot do better, which is the case
// that keeps this from being a lossy step somebody has to opt out of: a file
// that is already small, already correctly sized and carries no metadata comes
// back byte-identical.
func Optimise(format string, body []byte, opt Options) (Optimised, error) {
	opt = opt.withDefaults()
	out := Optimised{Body: body, Format: format, Was: len(body), Now: len(body)}

	switch format {
	case "png", "jpeg", "gif":
	default:
		// Not an image this can re-encode. Returned untouched rather than
		// refused: the format table has already decided it is acceptable, and
		// this stage is an optimisation rather than a gate.
		return out, nil
	}

	img, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		return out, fmt.Errorf("cannot decode the image to optimise it: %w", err)
	}
	b := img.Bounds()
	out.Width, out.Height = b.Dx(), b.Dy()

	// A file carrying a provenance manifest is returned exactly as it arrived.
	//
	// Not because the manifest is metadata worth keeping -- everything else
	// here is stripped deliberately, and rightly, since EXIF is where the
	// photographer's home address lives. It is because a C2PA manifest is
	// bound to the bytes it was signed over. Re-encoding changes the pixels,
	// and then there are only bad options: keep the manifest and it fails to
	// verify, which reads as tampering rather than as a resize; drop it and a
	// record somebody else made -- a camera, a generator -- is destroyed by an
	// optimisation nobody asked about.
	//
	// So the picture is stored as it came. The cost is bytes on a file that
	// already carries a signed claim, which is a small price for not being the
	// program that quietly broke everybody's provenance.
	if hasProvenance(format, body) {
		out.KeptForProvenance = true
		out.Did = append(out.Did,
			"kept exactly as uploaded: it carries a provenance manifest, and "+
				"re-encoding would break the signature over its pixels")
		return out, nil
	}

	// Metadata is detected before it is dropped, so the fact can be reported.
	// A re-encode drops it either way; saying so is what makes it a feature
	// rather than a side effect nobody knows about.
	if hasMetadata(format, body) {
		out.StrippedMetadata = true
		out.Did = append(out.Did, "removed embedded metadata")
	}

	if opt.MaxWidth > 0 || opt.MaxHeight > 0 {
		if resized, w, h, did := fit(img, opt.MaxWidth, opt.MaxHeight); did {
			img = resized
			out.Did = append(out.Did, fmt.Sprintf("resized %dx%d to %dx%d",
				out.Width, out.Height, w, h))
			out.Width, out.Height = w, h
		}
	}

	encoded, encFormat, err := encode(img, format, opt)
	if err != nil {
		return out, err
	}

	// An external WebP encoder, if the operator has one and asked for it.
	if opt.WebP {
		if webp, ok := toWebP(encoded, encFormat, opt.JPEGQuality); ok &&
			len(webp) < len(encoded) {
			encoded, encFormat = webp, "webp"
			out.Did = append(out.Did, "converted to webp")
		}
	}

	// Kept only if it is actually smaller, or if metadata had to go. The
	// second case matters: an image whose only problem is a GPS tag must be
	// re-encoded even when the result is a few bytes larger, because the point
	// there was never the size.
	if len(encoded) < len(body) || out.StrippedMetadata ||
		len(out.Did) > 0 {
		out.Body, out.Format, out.Now = encoded, encFormat, len(encoded)
		if len(encoded) < len(body) {
			out.Did = append(out.Did, fmt.Sprintf("%s to %s",
				human(int64(len(body))), human(int64(len(encoded)))))
		}
	}
	return out, nil
}

// encode writes an image back out, dropping everything that is not pixels.
func encode(img image.Image, format string, opt Options) ([]byte, string, error) {
	var buf bytes.Buffer
	switch format {
	case "jpeg":
		if err := jpegenc.Encode(&buf, img, &jpegenc.Options{Quality: opt.JPEGQuality}); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "jpeg", nil
	case "gif":
		if err := gifenc.Encode(&buf, img, nil); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "gif", nil
	default:
		enc := pngenc.Encoder{CompressionLevel: pngenc.BestCompression}
		if err := enc.Encode(&buf, img); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "png", nil
	}
}

// fit scales an image down to fit a box, preserving its aspect ratio.
//
// A box-filtered average rather than nearest-neighbour. Nearest is four lines
// shorter and produces visible aliasing on exactly the content people upload —
// text in screenshots, thin lines in diagrams — which makes the optimisation
// look like damage and gets it switched off.
func fit(src image.Image, maxW, maxH int) (image.Image, int, int, bool) {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w == 0 || h == 0 {
		return src, w, h, false
	}
	tw, th := w, h
	if maxW > 0 && tw > maxW {
		th = th * maxW / tw
		tw = maxW
	}
	if maxH > 0 && th > maxH {
		tw = tw * maxH / th
		th = maxH
	}
	if tw >= w && th >= h {
		return src, w, h, false
	}
	if tw < 1 {
		tw = 1
	}
	if th < 1 {
		th = 1
	}

	dst := image.NewRGBA(image.Rect(0, 0, tw, th))
	xr, yr := float64(w)/float64(tw), float64(h)/float64(th)
	for y := 0; y < th; y++ {
		y0 := b.Min.Y + int(float64(y)*yr)
		y1 := b.Min.Y + int(float64(y+1)*yr)
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < tw; x++ {
			x0 := b.Min.X + int(float64(x)*xr)
			x1 := b.Min.X + int(float64(x+1)*xr)
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, bl, a, n uint64
			for sy := y0; sy < y1 && sy < b.Max.Y; sy++ {
				for sx := x0; sx < x1 && sx < b.Max.X; sx++ {
					cr, cg, cb, ca := src.At(sx, sy).RGBA()
					r += uint64(cr)
					g += uint64(cg)
					bl += uint64(cb)
					a += uint64(ca)
					n++
				}
			}
			if n == 0 {
				continue
			}
			dst.Set(x, y, color.RGBA64{
				R: uint16(r / n), G: uint16(g / n),
				B: uint16(bl / n), A: uint16(a / n),
			})
		}
	}
	return dst, tw, th, true
}

// hasProvenance reports whether a file carries a C2PA manifest.
//
// Structural, like hasMetadata: the question is only whether one is present,
// and the containers put it somewhere specific. A walk rather than a substring
// search, because "caBX" appearing inside compressed image data is a
// coincidence that would silently disable optimisation for an ordinary photo.
func hasProvenance(format string, body []byte) bool {
	switch format {
	case "png":
		// A caBX chunk, found by walking the chunk list.
		at := 8
		for at+8 <= len(body) {
			length := int(binary.BigEndian.Uint32(body[at : at+4]))
			if string(body[at+4:at+8]) == "caBX" {
				return true
			}
			next := at + 12 + length
			if next <= at || next > len(body) {
				return false
			}
			at = next
		}
	case "jpeg":
		// An APP11 segment whose payload begins with the JUMBF marker "JP".
		for i := 2; i+4 <= len(body); {
			if body[i] != 0xFF {
				return false
			}
			marker := body[i+1]
			if marker == 0xDA { // the scan; nothing after this is metadata
				return false
			}
			size := int(body[i+2])<<8 | int(body[i+3])
			if size < 2 || i+2+size > len(body) {
				return false
			}
			if marker == 0xEB && i+6 <= len(body) &&
				body[i+4] == 0x4A && body[i+5] == 0x50 {
				return true
			}
			i += 2 + size
		}
	}
	return false
}

// hasMetadata reports whether a file carries anything that is not pixels.
//
// Structural rather than a full parse: the question is only whether
// re-encoding removes something, and a marker's presence answers it. Parsing
// EXIF properly would mean parsing attacker-controlled TIFF in order to decide
// whether to discard it, which is work done for no benefit — it is being
// discarded either way.
func hasMetadata(format string, body []byte) bool {
	switch format {
	case "jpeg":
		// APP1 (EXIF/XMP), APP13 (IPTC), or a COM comment.
		for i := 2; i+4 < len(body) && i < 1<<16; {
			if body[i] != 0xFF {
				break
			}
			marker := body[i+1]
			if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
				i += 2
				continue
			}
			if marker == 0xDA { // start of scan; metadata comes before this
				break
			}
			if marker == 0xE1 || marker == 0xED || marker == 0xFE || marker == 0xE2 {
				return true
			}
			size := int(body[i+2])<<8 | int(body[i+3])
			if size < 2 {
				break
			}
			i += 2 + size
		}
	case "png":
		for _, chunk := range [][]byte{
			[]byte("eXIf"), []byte("tEXt"), []byte("iTXt"), []byte("zTXt"),
		} {
			if bytes.Contains(body, chunk) {
				return true
			}
		}
	case "gif":
		return bytes.Contains(body, []byte("XMP DataXMP"))
	}
	return false
}

// toWebP shells out to cwebp when the operator has it.
//
// Detected, never required. An upload must not fail because a tool is missing,
// so every failure here returns false and the caller keeps the native result —
// the pipeline degrades to "still stripped, still resized, just not WebP".
//
// The input is an image this process has already decoded and re-encoded
// itself, not the bytes a stranger uploaded, so cwebp is handed something of
// known shape. That ordering is deliberate: it means a bug in cwebp's parser
// is not reachable from an upload.
func toWebP(body []byte, format string, quality int) ([]byte, bool) {
	bin, err := exec.LookPath("cwebp")
	if err != nil {
		return nil, false
	}
	cmd := exec.Command(bin, "-quiet", "-q", strconv.Itoa(quality),
		"-o", "-", "--", "-")
	cmd.Stdin = bytes.NewReader(body)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil || out.Len() == 0 {
		return nil, false
	}
	// Verified as WebP rather than trusted. An external tool that returned
	// something else — an error page, a truncated file — must not become the
	// bytes this site serves.
	if !bytes.HasPrefix(out.Bytes(), []byte("RIFF")) ||
		!bytes.Contains(out.Bytes()[:min(16, out.Len())], []byte("WEBP")) {
		return nil, false
	}
	return out.Bytes(), true
}

// HaveWebP reports whether an external WebP encoder is available, so the CLI
// can say so rather than silently doing less than asked.
func HaveWebP() (string, bool) {
	bin, err := exec.LookPath("cwebp")
	return bin, err == nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = strings.TrimSpace

// RenditionWidths are the narrower copies made for a picture.
//
// Three, not seven. Each one is bytes on a disk and in every static copy, and
// the difference between a 480 and a 560 wide file is not a difference a reader
// can see — while the difference between 480 and 1200 is four fifths of the
// transfer on a phone. The list is ascending, and a width at or above the
// original's is skipped rather than upscaled.
var RenditionWidths = []int{480, 960, 1440}

// Renditions makes the narrower copies of an image.
//
// Returns nothing for a format this cannot re-encode and for an image already
// narrower than the smallest width — both of which are ordinary, and neither of
// which is an error: a site whose pictures are all small simply has no
// renditions and serves the originals, which is the behaviour it had before
// this existed.
//
// A photograph resized to 480 wide is usually smaller as a JPEG than as a PNG,
// so a PNG source may come back as JPEG renditions. The parent keeps its own
// format: replacing it would change its address, and its address is in
// published pages.
func Renditions(format string, body []byte, opt Options) ([]Optimised, error) {
	opt = opt.withDefaults()
	switch format {
	case "png", "jpeg", "gif":
	default:
		return nil, nil
	}
	img, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cannot decode the image to resize it: %w", err)
	}
	full := img.Bounds().Dx()

	var out []Optimised
	for _, width := range RenditionWidths {
		if width >= full {
			continue
		}
		resized, w, h, did := fit(img, width, 0)
		if !did {
			continue
		}
		target := format
		if format == "png" && !hasAlpha(resized) {
			// A photograph, not a diagram. JPEG is dramatically smaller and
			// the difference is invisible at this size; an image with
			// transparency stays PNG, because JPEG has none and the
			// alternative is a black rectangle where the transparency was.
			target = "jpeg"
		}
		encoded, encFormat, eerr := encode(resized, target, opt)
		if eerr != nil {
			return nil, eerr
		}
		if len(encoded) >= len(body) {
			// Narrower and no smaller. Nothing to gain and a file to keep, so
			// it is not made — which happens with small PNGs of flat colour.
			continue
		}
		out = append(out, Optimised{
			Body: encoded, Format: encFormat, Width: w, Height: h,
			Was: len(body), Now: len(encoded),
		})
	}
	return out, nil
}

// hasAlpha reports whether any pixel is not fully opaque.
//
// Sampled rather than exhaustive for large images: a grid of points across the
// picture, because transparency in a real image is a region rather than one
// stray pixel, and reading twelve million alpha values to decide an encoding is
// a cost every upload would pay.
func hasAlpha(img image.Image) bool {
	b := img.Bounds()
	stepX := b.Dx()/64 + 1
	stepY := b.Dy()/64 + 1
	for y := b.Min.Y; y < b.Max.Y; y += stepY {
		for x := b.Min.X; x < b.Max.X; x += stepX {
			if _, _, _, a := img.At(x, y).RGBA(); a < 0xffff {
				return true
			}
		}
	}
	return false
}
