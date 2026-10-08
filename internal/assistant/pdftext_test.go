// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assistant

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// pdfWith builds a minimal PDF whose page content is the given stream.
func pdfWith(content []byte, flate bool) []byte {
	var body []byte
	dict := fmt.Sprintf("<< /Length %d >>", len(content))
	body = content
	if flate {
		var b bytes.Buffer
		zw := zlib.NewWriter(&b)
		zw.Write(content)
		zw.Close()
		body = b.Bytes()
		dict = fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>", len(body))
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	fmt.Fprintf(&out, "4 0 obj\n%s\nstream\n", dict)
	out.Write(body)
	out.WriteString("\nendstream\nendobj\n%%EOF\n")
	return out.Bytes()
}

const policy = `BT /F1 12 Tf 72 712 Td (Returns Policy) Tj ET
BT /F1 10 Tf 72 690 Td (Unopened items can be returned within 30 days.) Tj
/F2 10 Tf
0 -14 Td [(Opened ink) -250 (cannot be returned \(sorry\).)] TJ
T* (Refunds take 5 working days.) Tj ET`

func TestTextComesOutOfAPDF(t *testing.T) {
	for _, flate := range []bool{false, true} {
		got, err := PDFText(pdfWith([]byte(policy), flate))
		if err != nil {
			t.Fatalf("flate=%v: %v", flate, err)
		}
		for _, want := range []string{"Returns Policy",
			"Unopened items can be returned within 30 days.",
			"Opened ink cannot be returned (sorry).",
			"Refunds take 5 working days."} {
			if !strings.Contains(got, want) {
				t.Errorf("flate=%v: %q not in\n%s", flate, want, got)
			}
		}
	}
}

// TestAFontChangeDoesNotLoseTheLine — the first version's bug.
func TestAFontChangeDoesNotLoseTheLine(t *testing.T) {
	got, err := PDFText(pdfWith([]byte(
		`BT /F1 10 Tf 72 700 Td (The shop is open daily from nine.) Tj /F2 9 Tf ( Closed Sundays and holidays.) Tj ET`), true))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "open daily from nine") || !strings.Contains(got, "Closed Sundays") {
		t.Fatalf("got %q", got)
	}
}

func TestAScannedPDFSaysSo(t *testing.T) {
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n5 0 obj\n<< /Type /XObject /Subtype /Image /Filter /DCTDecode /Length 4 >>\nstream\n\xff\xd8\xff\xe0\nendstream\nendobj\n")
	_, err := PDFText(out.Bytes())
	if !errors.Is(err, ErrNoText) || !strings.Contains(err.Error(), "scanned") {
		t.Fatalf("err = %v", err)
	}
}

func TestGlyphNumbersAreNotIndexedAsText(t *testing.T) {
	// Identity-encoded fonts show two-byte glyph ids, which decode as noise.
	_, err := PDFText(pdfWith([]byte(`BT /F1 12 Tf 72 700 Td <0024005100470003002C0051004E> Tj ET`), true))
	if !errors.Is(err, ErrNoText) {
		t.Fatalf("noise was accepted as text: %v", err)
	}
}

func TestAFlateBombStopsAtTheLimit(t *testing.T) {
	var b bytes.Buffer
	zw := zlib.NewWriter(&b)
	chunk := bytes.Repeat([]byte("(a) Tj "), 1<<16)
	for i := 0; i < 400; i++ { // ~180 MB inflated
		zw.Write(chunk)
	}
	zw.Close()
	pdf := []byte(fmt.Sprintf("%%PDF-1.7\n1 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", b.Len()))
	pdf = append(pdf, b.Bytes()...)
	pdf = append(pdf, []byte("\nendstream\nendobj\n")...)

	start := time.Now()
	text, _ := PDFText(pdf)
	if len(text) > maxPDFText+maxInflate {
		t.Fatalf("%d bytes of text from a bomb", len(text))
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("a bomb took too long")
	}
}

func TestNotAPDF(t *testing.T) {
	if _, err := PDFText([]byte("hello")); err == nil {
		t.Fatal("accepted")
	}
}
