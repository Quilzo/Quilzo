// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assistant

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Reading the text out of a PDF, and saying when it cannot.
//
// The alternatives are a dependency (this program has none), a subprocess
// (a PDF is attacker-supplied input handed to a large C program), or this: the
// part of the format that holds text in the PDFs people actually upload —
// price lists, handbooks, policies exported from a word processor. Content
// streams, compressed with Flate or not, and the text-showing operators Tj,
// TJ, ' and ".
//
// What it does not do is also said out loud. A scanned PDF has no text, only
// pictures of it; a PDF whose fonts map glyphs through a custom table encodes
// its text as numbers only that table can decode. Both come back as an error
// naming the reason, never as garbage indexed as knowledge — a chatbot citing
// a passage of mojibake is worse than one that says the document could not
// be read.
//
// Bounded throughout, because the input is whoever uploaded it: a stream
// inflates to at most maxInflate, the whole document to maxPDFText, and the
// number of streams considered is capped. A Flate bomb stops at the limit.

const (
	maxInflate = 8 << 20
	maxPDFText = 2 << 20
	maxStreams = 2000
)

// ErrNoText is a PDF this cannot read text from, with the reason.
var ErrNoText = errors.New("no readable text")

var (
	reFlate = regexp.MustCompile(`/Filter\s*(\[\s*)?/FlateDecode`)
	reOther = regexp.MustCompile(`/Filter\s*(\[\s*)?/(DCTDecode|JPXDecode|CCITTFaxDecode|JBIG2Decode|LZWDecode|RunLengthDecode|ASCII85Decode|ASCIIHexDecode)`)
)

// PDFText extracts the text of a PDF.
func PDFText(pdf []byte) (string, error) {
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		return "", errors.New("not a PDF")
	}
	var out strings.Builder
	streams := 0
	rest := pdf
	for {
		dict, data, next, ok := nextStream(rest)
		if !ok {
			break
		}
		rest = next
		streams++
		if streams > maxStreams {
			break
		}

		// Images, fonts and anything encoded another way hold no text.
		if reOther.Match(dict) || bytes.Contains(dict, []byte("/Subtype/Image")) ||
			bytes.Contains(dict, []byte("/Subtype /Image")) ||
			bytes.Contains(dict, []byte("/Length1")) {
			continue
		}
		if reFlate.Match(dict) {
			zr, err := zlib.NewReader(bytes.NewReader(data))
			if err != nil {
				continue
			}
			inflated, err := io.ReadAll(io.LimitReader(zr, maxInflate))
			zr.Close()
			if err != nil && len(inflated) == 0 {
				continue
			}
			data = inflated
		}
		showText(data, &out)
		if out.Len() > maxPDFText {
			break
		}
	}
	text := strings.TrimSpace(out.String())
	if text == "" {
		return "", errors.Join(ErrNoText, errors.New("this PDF holds no text "+
			"a program can read — it is probably scanned, and needs text "+
			"recognition before a chatbot can use it"))
	}
	if !readable(text) {
		return "", errors.Join(ErrNoText, errors.New("this PDF's text is "+
			"encoded through its fonts in a way this cannot decode; export it "+
			"again as text, or upload the text itself"))
	}
	return text, nil
}

// nextStream finds the next stream: its dictionary, its raw bytes, and what
// follows it.
//
// A scan for the keyword rather than a pattern over the dictionary, because
// dictionaries nest and a pattern that stops at the first ">>" stops inside
// the inner one. The dictionary is everything between the object header and
// the keyword, bounded, which holds the /Filter and /Subtype this needs.
func nextStream(b []byte) (dict, data, rest []byte, ok bool) {
	for {
		i := bytes.Index(b, []byte("stream"))
		if i < 0 {
			return nil, nil, nil, false
		}
		after := i + len("stream")
		isStart := after < len(b) && (b[after] == '\n' || b[after] == '\r') &&
			(i < 3 || !bytes.Equal(b[i-3:i], []byte("end")))
		if !isStart {
			b = b[after:]
			continue
		}
		start := i - 1024
		if start < 0 {
			start = 0
		}
		dict = b[start:i]
		if o := bytes.LastIndex(dict, []byte(" obj")); o >= 0 {
			dict = dict[o:]
		}
		body := b[after:]
		if len(body) > 0 && body[0] == '\r' {
			body = body[1:]
		}
		if len(body) > 0 && body[0] == '\n' {
			body = body[1:]
		}
		end := bytes.Index(body, []byte("endstream"))
		if end < 0 {
			return nil, nil, nil, false
		}
		return dict, body[:end], body[end+len("endstream"):], true
	}
}

// showText walks a content stream and writes what its text operators show.
//
// A small tokeniser rather than a regular expression over the whole stream,
// because strings may contain the characters that delimit them when escaped,
// and a regex that got that wrong would split a sentence at "(1)".
//
// Two buffers: operands waiting for their operator, and the line of text
// already shown. The first version had one, and cleared it on any operator
// that was not a text operator — so a font change after Tj discarded the
// text Tj had just shown.
func showText(cs []byte, out *strings.Builder) {
	var operands, line []string
	flush := func() {
		if len(line) > 0 {
			out.WriteString(strings.Join(line, ""))
			out.WriteByte('\n')
			line = line[:0]
		}
	}
	i := 0
	for i < len(cs) {
		c := cs[i]
		switch {
		case c == '(':
			s, n := pdfString(cs[i:])
			operands = append(operands, s)
			i += n
		case c == '<' && i+1 < len(cs) && cs[i+1] != '<':
			s, n := pdfHex(cs[i:])
			operands = append(operands, s)
			i += n
		case c == '[' || c == ']':
			i++
		case c == '%':
			for i < len(cs) && cs[i] != '\n' && cs[i] != '\r' {
				i++
			}
		case isDelim(c):
			i++
		default:
			j := i
			for j < len(cs) && !isDelim(cs[j]) && cs[j] != '(' && cs[j] != '<' &&
				cs[j] != '[' && cs[j] != ']' {
				j++
			}
			if j == i {
				j++
			}
			tok := string(cs[i:j])
			i = j
			switch tok {
			case "Tj", "TJ":
				line = append(line, operands...)
				operands = operands[:0]
			case "'", "\"":
				// Move to the next line, then show.
				flush()
				line = append(line, operands...)
				operands = operands[:0]
			case "Td", "TD", "T*", "ET", "Tm", "BT":
				flush()
				operands = operands[:0]
			default:
				if n, err := strconv.ParseFloat(tok, 64); err == nil {
					// Inside a TJ array, a large negative adjustment is the
					// gap between words.
					if n < -180 && len(operands) > 0 {
						operands = append(operands, " ")
					}
				} else if !isOperand(tok) {
					// Any other operator consumes its operands. Strings it
					// took were not shown as text.
					operands = operands[:0]
				}
			}
		}
	}
	flush()
}

// isOperand reports whether a token is data rather than an operator: a
// name, a number or a boolean.
func isOperand(tok string) bool {
	if strings.HasPrefix(tok, "/") || tok == "true" || tok == "false" || tok == "null" {
		return true
	}
	_, err := strconv.ParseFloat(tok, 64)
	return err == nil
}

func isDelim(c byte) bool {
	return c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\f' || c == 0 ||
		c == '{' || c == '}' || c == '>'
}

// pdfString reads a literal string starting at "(", returning its text and
// how many bytes it took.
func pdfString(b []byte) (string, int) {
	var s []byte
	depth := 0
	i := 0
	for i < len(b) {
		c := b[i]
		switch {
		case c == '(':
			if depth > 0 {
				s = append(s, c)
			}
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return latin(s), i + 1
			}
			s = append(s, c)
		case c == '\\' && i+1 < len(b):
			i++
			e := b[i]
			switch e {
			case 'n':
				s = append(s, '\n')
			case 'r':
				s = append(s, '\r')
			case 't':
				s = append(s, '\t')
			case 'b', 'f':
			case '(', ')', '\\':
				s = append(s, e)
			case '\r', '\n':
				// A line continuation.
			default:
				if e >= '0' && e <= '7' {
					n := 0
					k := 0
					for k < 3 && i < len(b) && b[i] >= '0' && b[i] <= '7' {
						n = n*8 + int(b[i]-'0')
						i++
						k++
					}
					i--
					s = append(s, byte(n))
				} else {
					s = append(s, e)
				}
			}
		default:
			s = append(s, c)
		}
		i++
	}
	return latin(s), len(b)
}

// pdfHex reads a hex string starting at "<".
func pdfHex(b []byte) (string, int) {
	end := bytes.IndexByte(b, '>')
	if end < 0 {
		return "", len(b)
	}
	hex := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, string(b[1:end]))
	if len(hex)%2 == 1 {
		hex += "0"
	}
	var s []byte
	for k := 0; k+1 < len(hex); k += 2 {
		v, err := strconv.ParseUint(hex[k:k+2], 16, 8)
		if err != nil {
			return "", end + 1
		}
		s = append(s, byte(v))
	}
	return latin(s), end + 1
}

// latin decodes single-byte text, which is what the standard encodings are.
// Bytes outside the printable range become nothing, so an encoding this does
// not understand shows up as too little text rather than as control
// characters in a chatbot's answer.
func latin(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\n' || c == '\t':
			sb.WriteByte(' ')
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		case c >= 0xa0:
			sb.WriteRune(rune(c))
		}
	}
	return sb.String()
}

// readable reports whether extracted text is language rather than glyph
// numbers: most of its characters are letters, digits, spaces or ordinary
// punctuation, and it contains words.
func readable(s string) bool {
	var good, total, words int
	inWord := false
	for _, r := range s {
		total++
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) ||
			strings.ContainsRune(".,;:!?'\"()-£$€%/&", r) {
			good++
		}
		if unicode.IsLetter(r) {
			if !inWord {
				words++
			}
			inWord = true
		} else {
			inWord = false
		}
	}
	return total > 0 && float64(good)/float64(total) > 0.85 && words >= 3
}
