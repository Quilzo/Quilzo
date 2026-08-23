package media

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

// png builds a real PNG so the tests exercise the actual decoder rather than a
// hand-written byte slice that only satisfies the signature check.
//
// withPixels false writes a header and a stub data chunk: DecodeConfig reads
// dimensions without allocating pixels, which is both why the bomb check can
// run before anything large is allocated and how a 66-byte file can claim to be
// 30000x30000.
func png(w, h int, withPixels bool) []byte {
	chunk := func(typ string, data []byte) []byte {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
		body := append([]byte(typ), data...)
		b.Write(body)
		_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(body))
		return b.Bytes()
	}
	var ihdr bytes.Buffer
	_ = binary.Write(&ihdr, binary.BigEndian, uint32(w))
	_ = binary.Write(&ihdr, binary.BigEndian, uint32(h))
	ihdr.Write([]byte{8, 2, 0, 0, 0}) // 8-bit truecolour

	var raw bytes.Buffer
	if withPixels {
		for range h {
			raw.WriteByte(0)
			raw.Write(bytes.Repeat([]byte{0, 0, 0}, w))
		}
	} else {
		raw.WriteByte(0)
	}
	var comp bytes.Buffer
	zw := zlib.NewWriter(&comp)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()

	var out bytes.Buffer
	out.Write([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	out.Write(chunk("IHDR", ihdr.Bytes()))
	out.Write(chunk("IDAT", comp.Bytes()))
	out.Write(chunk("IEND", nil))
	return out.Bytes()
}

func pdf(extra string) []byte {
	return []byte("%PDF-1.7\n1 0 obj\n<< /Type /Catalog " + extra +
		" >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")
}

// -- the happy path ----------------------------------------------------------

func TestARealImageIsAcceptedWithItsDimensions(t *testing.T) {
	f, err := Accept("photo.png", png(64, 48, true), now)
	if err != nil {
		t.Fatalf("a valid PNG was refused: %v", err)
	}
	if f.Width != 64 || f.Height != 48 {
		t.Errorf("dimensions read as %dx%d; templates need these to reserve "+
			"space and stop the page reflowing", f.Width, f.Height)
	}
	if f.Kind != Image || f.Format != "png" {
		t.Errorf("classified as %s/%s", f.Kind, f.Format)
	}
	if len(f.ID) != 64 {
		t.Errorf("the id is %d chars; it should be a SHA-256", len(f.ID))
	}
}

// The stored name is the content hash, so the same file uploaded twice is the
// same object. That is deduplication for free and, more importantly, it means
// no caller-supplied string is ever a path.
func TestTheSameBytesAlwaysGetTheSameID(t *testing.T) {
	body := png(8, 8, true)
	a, _ := Accept("one.png", body, now)
	b, _ := Accept("../../etc/passwd", body, now)
	if a.ID != b.ID {
		t.Error("identical bytes produced different ids")
	}
	if strings.Contains(b.ID, "/") || strings.Contains(b.ID, ".") {
		t.Errorf("the id %q is not opaque", b.ID)
	}
}

// -- the bomb ----------------------------------------------------------------

// A file-size limit does not see this: it is 66 bytes on disk and 900 million
// pixels decoded, which is several gigabytes of memory. The pixel count is the
// thing that has to be bounded.
func TestADecompressionBombIsRefusedDespiteBeingTiny(t *testing.T) {
	body := png(30000, 30000, false)
	if len(body) > 1000 {
		t.Fatalf("the fixture is %d bytes; it is meant to be tiny", len(body))
	}
	_, err := Accept("innocent.png", body, now)
	if err == nil {
		t.Fatal("a 900-megapixel image in 66 bytes was accepted")
	}
	if !strings.Contains(err.Error(), "megapixel") {
		t.Errorf("refused, but not for the right reason: %v", err)
	}
	// And an ordinary large photograph must still be accepted.
	if _, err := Accept("big.png", png(4000, 3000, false), now); err != nil {
		t.Errorf("a 12-megapixel image was refused: %v", err)
	}
}

// -- lying about what a file is ----------------------------------------------

// Magic bytes are a hint. The bytes decide, and a file whose extension and
// contents disagree is refused rather than trusted in either direction.
func TestTheExtensionDoesNotDecideWhatAFileIs(t *testing.T) {
	// A PDF wearing a PNG extension must not be accepted as an image.
	f, err := Accept("photo.png", pdf(""), now)
	if err != nil {
		t.Logf("refused outright, which is also fine: %v", err)
		return
	}
	if f.Kind == Image {
		t.Errorf("a PDF named .png was accepted as an image")
	}
	if f.Format != "pdf" {
		t.Errorf("classified as %q rather than by its contents", f.Format)
	}
}

// A file called photo.png that is not a PNG at all is refused, not stored as
// something unknown.
func TestBytesThatMatchNothingAreRefused(t *testing.T) {
	if _, err := Accept("photo.png", []byte("not a png at all"), now); err == nil {
		t.Error("arbitrary bytes with a .png extension were accepted")
	}
}

// RIFF starts both WebP and WAV. Without checking the four bytes at offset 8, a
// WAV would be served as an image and a WebP as audio, decided only by which
// extension was claimed.
func TestRIFFContainersAreDistinguishedByTheirSubtype(t *testing.T) {
	wav := append([]byte("RIFF\x00\x00\x00\x00WAVE"), bytes.Repeat([]byte{0}, 32)...)
	webp := append([]byte("RIFF\x00\x00\x00\x00WEBP"), bytes.Repeat([]byte{0}, 32)...)

	if err := verifyWebP(wav); err == nil {
		t.Error("a WAV passed the WebP check")
	}
	if err := verifyWAV(webp); err == nil {
		t.Error("a WebP passed the WAV check")
	}
	if err := verifyWebP(webp); err != nil {
		t.Errorf("a real WebP header was refused: %v", err)
	}
}

// An MP4 has no fixed prefix: it starts with a size, then "ftyp" at offset 4.
// Checking at offset 0 would validate nothing.
func TestMP4IsCheckedAtTheRightOffset(t *testing.T) {
	good := append([]byte{0, 0, 0, 0x18}, []byte("ftypisom")...)
	good = append(good, bytes.Repeat([]byte{0}, 16)...)
	if err := verifyISOBMFF(good); err != nil {
		t.Errorf("a valid MP4 header was refused: %v", err)
	}
	if err := verifyISOBMFF([]byte("ftypisom0000000000000000")); err == nil {
		t.Error("ftyp at offset 0 was accepted; it belongs at offset 4")
	}
	if err := verifyISOBMFF(append([]byte{0, 0, 0, 0x18},
		[]byte("ftypEVIL00000000")...)); err == nil {
		t.Error("an unrecognised brand was accepted")
	}
}

// -- formats that are refused on principle -----------------------------------

// SVG is the one people argue about, so the refusal has to explain itself well
// enough that the argument does not happen twice.
func TestSVGIsRefusedWithAReason(t *testing.T) {
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	_, err := Accept("logo.svg", svg, now)
	if err == nil {
		t.Fatal("an SVG containing a script element was accepted")
	}
	for _, want := range []string{"script", "PNG"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

func TestExecutableAndArchiveFormatsAreRefused(t *testing.T) {
	for _, name := range []string{
		"shell.php", "page.html", "app.js", "lib.wasm", "backup.zip",
		"theme.tar.gz", "report.docx", "sheet.xlsx", "run.exe", "x.jar",
	} {
		if _, err := Accept(name, []byte("MZ\x90\x00 whatever"), now); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A double extension is dangerous on a server configured to dispatch on any
// segment, so every segment is checked rather than only the last.
func TestEveryExtensionSegmentIsChecked(t *testing.T) {
	for _, name := range []string{
		"shell.php.png", "x.phtml.jpg", "a.jsp.gif", "evil.exe.pdf",
	} {
		if _, err := Accept(name, png(4, 4, true), now); err == nil {
			t.Errorf("%s was accepted despite a dangerous inner extension", name)
		}
	}
}

// -- PDF ---------------------------------------------------------------------

// A document being published on a website should not do anything when opened.
func TestAPDFThatActsIsRefused(t *testing.T) {
	for _, construct := range []string{
		"/JavaScript (app.alert\\(1\\))",
		"/JS (x)",
		"/OpenAction << /S /JavaScript >>",
		"/Launch << /F (calc.exe) >>",
		"/EmbeddedFile 2 0 R",
		"/AA << /O << /S /JavaScript >> >>",
		"/XFA 3 0 R",
	} {
		if _, err := Accept("report.pdf", pdf(construct), now); err == nil {
			t.Errorf("a PDF containing %s was accepted", construct)
		}
	}
	if _, err := Accept("report.pdf", pdf("/Pages 2 0 R"), now); err != nil {
		t.Errorf("an ordinary PDF was refused: %v", err)
	}
}

func TestATruncatedPDFIsRefused(t *testing.T) {
	if _, err := Accept("x.pdf", []byte("%PDF-1.7\nsome content but no marker"),
		now); err == nil {
		t.Error("a PDF with no end-of-file marker was accepted")
	}
}

// -- the WordPress bug -------------------------------------------------------

// CVE-2021-29447 was XXE reached through WordPress parsing ID3 tags on an
// uploaded audio file. Nothing here parses the tag — but a tag carrying a
// DOCTYPE is a file built to be parsed by something that does, and passing it
// on is how the next tool inherits the bug.
func TestAnAudioFileCarryingXMLInItsTagIsRefused(t *testing.T) {
	payload := append([]byte("ID3\x04\x00\x00\x00\x00\x00\x00"),
		[]byte(`<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>`)...)
	_, err := Accept("song.mp3", payload, now)
	if err == nil {
		t.Fatal("an MP3 with an XXE payload in its ID3 tag was accepted")
	}
	if !strings.Contains(err.Error(), "CVE-2021-29447") {
		t.Errorf("the refusal does not say what this is: %v", err)
	}
	// A normal tagged MP3 must still pass.
	ok := append([]byte("ID3\x04\x00\x00\x00\x00\x00\x00TIT2"),
		bytes.Repeat([]byte{0x20}, 64)...)
	if err := verifyMP3(ok); err != nil {
		t.Errorf("an ordinary tagged MP3 was refused: %v", err)
	}
}

// -- CSV ---------------------------------------------------------------------

// The file is harmless where it sits and dangerous where it lands, which is the
// case people forget.
func TestCSVFormulaInjectionIsRefused(t *testing.T) {
	for _, body := range []string{
		"name,note\nalice,=cmd|'/c calc'!A1\n",
		"a,b\n1,+1+1\n",
		"a,b\n1,@SUM(1:2)\n",
		"a,b\n1,\"=HYPERLINK(\"\"http://evil\"\")\"\n",
	} {
		if _, err := Accept("data.csv", []byte(body), now); err == nil {
			t.Errorf("a CSV containing a formula was accepted: %q", body)
		}
	}
	if _, err := Accept("data.csv", []byte("name,note\nalice,hello\n"), now); err != nil {
		t.Errorf("an ordinary CSV was refused: %v", err)
	}
}

// -- filenames ---------------------------------------------------------------

// The display name is kept for humans and is never a path, but it still gets
// into a Content-Disposition header and onto a screen, so the characters that
// lie or split have to go.
func TestDisplayNamesLoseWhatCanLieOrSplit(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd":        "passwd",
		"..\\..\\windows\\sys":    "sys",
		"photo.png\x00.php":       "photo.png.php",
		"head\r\nX-Evil: yes.png": "headX-Evil: yes.png",
		"invoice‮gnp.exe.png":     "invoicegnp.exe.png",
		"  spaced.png  ":          "spaced.png",
	}
	for in, want := range cases {
		if got := displayName(in); got != want {
			t.Errorf("displayName(%q) = %q, wanted %q", in, got, want)
		}
	}
	if displayName("\x00\x00") != "unnamed" {
		t.Error("a name made only of control characters should become 'unnamed'")
	}
}

// The download name is rebuilt from the id and the format's own extension
// rather than sanitised from the caller's string, because sanitising is a
// blocklist and blocklists lose.
func TestDownloadNamesAreBuiltNotCleaned(t *testing.T) {
	f, err := Accept("../../evil\"; filename=\"x.png", png(4, 4, true), now)
	if err != nil {
		t.Fatal(err)
	}
	name := f.DownloadName()
	for _, bad := range []string{"..", "/", "\\", "\"", ";", " "} {
		if strings.Contains(name, bad) {
			t.Errorf("the download name %q contains %q", name, bad)
		}
	}
	if !strings.HasSuffix(name, ".png") {
		t.Errorf("the download name %q does not carry the real format", name)
	}
}

// -- serving decisions -------------------------------------------------------

// What may render in the site's origin, and what has to be a download.
//
// This used to say images and nothing else, on the grounds that a format with
// an unaudited parser must not become a page. Two things were wrong with using
// Content-Disposition to enforce that.
//
// It does not enforce it. A browser ignores Content-Disposition on a media
// subresource: <video src> and <audio src> load and decode the file whatever
// this header says. So the parser was reached either way and the header bought
// nothing.
//
// And this program ships a video section kind whose entire job is to put a file
// from this origin into a page. Marking those files as attachments meant the
// documented feature worked by accident, and a reader following a direct link
// to one got a download named after its hash.
//
// So the rule is by what handles the bytes. An image, an audio file or a video
// goes to a media decoder, and every one of them is decoded here before it is
// stored. A PDF goes to a viewer with a scripting engine attached, and text in
// the site's own origin is a page nobody wrote; both stay downloads.
func TestOnlyMediaRendersInline(t *testing.T) {
	inline := map[string]bool{}
	for name, fm := range formats {
		if !fm.Inline {
			continue
		}
		inline[name] = true
		switch fm.Kind {
		case Image, Audio, Video:
			// Handed to a decoder, and decoded here before storage.
		default:
			t.Errorf("%s is served inline and is a %s; only media may render "+
				"in this origin", name, fm.Kind)
		}
	}
	for _, want := range []string{"png", "jpeg", "mp4", "webm", "mp3"} {
		if !inline[want] {
			t.Errorf("%s should render in a page: a section kind puts one "+
				"there, and a download instead is a feature that does not work",
				want)
		}
	}
	for _, no := range []string{"pdf", "txt", "md", "csv"} {
		if inline[no] {
			t.Errorf("%s must be a download: it is not handed to a media "+
				"decoder, and in this origin it is a page nobody wrote", no)
		}
	}
}

// The MIME type comes from the table, never from the upload. A caller-supplied
// Content-Type is a request, not a fact.
func TestTheServedTypeComesFromTheFormatTable(t *testing.T) {
	f, err := Accept("photo.png", png(4, 4, true), now)
	if err != nil {
		t.Fatal(err)
	}
	if f.MIME() != "image/png" {
		t.Errorf("served as %q", f.MIME())
	}
	// An unknown format must fall back to something inert, not to a guess.
	unknown := File{Format: "not-a-format"}
	if unknown.MIME() != "application/octet-stream" {
		t.Errorf("an unknown format is served as %q", unknown.MIME())
	}
}

// -- the refusal list itself -------------------------------------------------

// "Unsupported file type" sends people looking for a converter that produces
// the same risk under a different extension.
func TestEveryRefusalExplainsItself(t *testing.T) {
	if len(refused) < 20 {
		t.Errorf("only %d refused extensions", len(refused))
	}
	// Resolved, not raw: the table says "See php." to stay readable, but a
	// person shown that has been told nothing, so WhyRefused follows the
	// reference. This asserts the resolution actually happens.
	for ext := range refused {
		why := WhyRefused(ext)
		if len(why) < 30 {
			t.Errorf("%s is refused with %q, which explains nothing to whoever "+
				"pasted the file", ext, why)
		}
		if strings.HasPrefix(why, "See ") {
			t.Errorf("%s returns an unresolved cross-reference: %q", ext, why)
		}
	}
	// The ones that matter most, named so removing them fails here.
	for _, ext := range []string{"svg", "html", "js", "php", "zip", "docx"} {
		if refused[ext] == "" {
			t.Errorf("%s is not on the refusal list", ext)
		}
	}
	// And nothing may be both accepted and refused.
	for ext := range refused {
		if _, ok := formats[ext]; ok {
			t.Errorf("%s is both accepted and refused", ext)
		}
	}
}

func TestEveryAcceptedFormatHasBoundsAndAVerifier(t *testing.T) {
	for name, fm := range formats {
		if fm.MaxBytes <= 0 {
			t.Errorf("%s has no size limit", name)
		}
		if fm.Verify == nil {
			t.Errorf("%s has no verifier, so only its signature is checked", name)
		}
		if fm.MIME == "" || fm.Kind == "" {
			t.Errorf("%s is missing its MIME type or kind", name)
		}
	}
}
