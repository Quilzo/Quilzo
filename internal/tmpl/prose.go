// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package tmpl

import (
	"html"
	"regexp"
	"strings"
)

// Markup is text that is already HTML, produced by something in this package
// that can only produce safe HTML.
//
// It is not a way to mark a string as trusted. Nothing accepts one from
// content, from a template, or from any caller outside this file — Prose is
// the only function that returns one, and Prose builds its output from a fixed
// set of tags after escaping everything it was given. So the type does not
// assert that a value is safe; it records that the only thing that could have
// made it is a function which cannot make anything else.
//
// That distinction is the whole reason this exists rather than {% raw %}. Raw
// takes whatever it is handed and prints it, which is why `quilzo scan` reports
// it and the assistant refuses to write it. This cannot print what it was
// handed: it prints what it built.
type Markup string

// Prose renders a small, fixed subset of Markdown.
//
// # Why a subset, and why this one
//
// Long text fields were escaped with no exceptions, so an editor could not
// bold a word, make a list, or link a phrase. The project's own importer says
// what that costs: WordPress bodies arrive as HTML and are stripped to plain
// text, because "the choice is to strip it to text or to route it through raw
// — lossy and visible beats faithful and dangerous".
//
// This is the third option. A fixed transform is not a template language and
// not a parser for somebody else's document format: it is a function from text
// to a closed set of tags. It cannot be extended by content, it has no
// evaluation step, and there is no syntax that reaches anything outside the
// list below.
//
// # What it does
//
//	paragraphs      blank line between them
//	## ### ####     headings, h2 to h4
//	- or *          an unordered list
//	1.              an ordered list
//	>               a quotation
//	**bold**        strong
//	*italic*        em
//	`code`          code
//	[text](url)     a link, http/https/mailto/tel only
//	![what it shows](/media/ID)
//	                a picture from this site's library, on a line of its
//	                own, with what it shows; no other address, and none
//	                without a description
//
// # What it deliberately does not do
//
// Raw HTML in the source is escaped, never passed through. Every Markdown
// implementation in wide use allows inline HTML and that is exactly the
// property this cannot have — the input is content, and content is written by
// whoever can write content.
//
// No images from anywhere else. Media in this program goes through a library
// that will not store a picture without a description and tracks the licence
// it was used under, so an image syntax that took any address would be a
// second way in that skips both. A picture already in the library is another
// matter: it was described and checked on the way in, and a post with its
// pictures among its words is what a blog brought from elsewhere is. So a
// picture is the library's, by the hash it is stored under, with the words
// saying what it shows, or it is not a picture.
//
// No tables, no footnotes, no reference links, no HTML entities. Each of those
// is a parser with states, and the states are where the holes are.
//
// # Why it escapes first
//
// The text is escaped before any marker is looked at, so a `<` in the source is
// `&lt;` before this function has decided anything. Nothing that arrives can
// become a tag; the only tags in the output are the ones written below, as
// literals. That ordering is the safety property, and it is why the marker
// scanning can be as simple as it is without that simplicity mattering.
func Prose(src string) Markup {
	var b strings.Builder
	for _, blk := range blocks(src) {
		writeBlock(&b, blk)
	}
	return Markup(b.String())
}

// blocks splits on blank lines, keeping each run of lines together.
func blocks(src string) [][]string {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	var out [][]string
	var cur []string
	for _, line := range strings.Split(src, "\n") {
		if strings.TrimSpace(line) == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, line)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// rePicture is a picture from the library on a line of its own.
var rePicture = regexp.MustCompile(`^!\[([^\]\n]{0,250}[^\s\]][^\]\n]{0,250})\]\(/media/([0-9a-f]{64})\)$`)

func writeBlock(b *strings.Builder, lines []string) {
	first := strings.TrimSpace(lines[0])

	switch {
	case rePicture.MatchString(first):
		m := rePicture.FindStringSubmatch(first)
		if alt := strings.TrimSpace(unescape(m[1])); alt != "" {
			b.WriteString(`<figure class="prose-picture"><img src="/media/` + m[2] + `" alt="` + html.EscapeString(alt) +
				`" loading="lazy" decoding="async"></figure>`)
		}
		writeBlock2(b, lines[1:])
	case strings.HasPrefix(first, "#### "):
		b.WriteString("<h4>" + inline(first[5:]) + "</h4>")
		writeBlock2(b, lines[1:])
	case strings.HasPrefix(first, "### "):
		b.WriteString("<h3>" + inline(first[4:]) + "</h3>")
		writeBlock2(b, lines[1:])
	case strings.HasPrefix(first, "## "):
		b.WriteString("<h2>" + inline(first[3:]) + "</h2>")
		writeBlock2(b, lines[1:])
	case isBullet(first):
		writeList(b, lines, "ul", isBullet, bulletText)
	case isNumber(first):
		writeList(b, lines, "ol", isNumber, numberText)
	case strings.HasPrefix(first, "> "):
		var qs []string
		for _, l := range lines {
			t := strings.TrimSpace(l)
			qs = append(qs, strings.TrimPrefix(strings.TrimPrefix(t, ">"), " "))
		}
		b.WriteString("<blockquote><p>" + inline(strings.Join(qs, " ")) + "</p></blockquote>")
	default:
		// Lines inside one paragraph are joined with a space rather than kept.
		// A hard line break needs a decision about what a stray newline means
		// in a field somebody pasted into, and joining is the answer that
		// never produces a surprise.
		var ps []string
		for _, l := range lines {
			ps = append(ps, strings.TrimSpace(l))
		}
		b.WriteString("<p>" + inline(strings.Join(ps, " ")) + "</p>")
	}
}

// writeBlock2 renders whatever followed a heading on the same block.
func writeBlock2(b *strings.Builder, rest []string) {
	if len(rest) > 0 {
		writeBlock(b, rest)
	}
}

func isBullet(s string) bool {
	return strings.HasPrefix(s, "- ") || strings.HasPrefix(s, "* ")
}

func bulletText(s string) string { return s[2:] }

// isNumber matches "1. ", with at most three digits so a line beginning with a
// long number is prose rather than a list nobody asked for.
func isNumber(s string) bool {
	i := 0
	for i < len(s) && i < 3 && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i > 0 && strings.HasPrefix(s[i:], ". ")
}

func numberText(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[i+2:]
	}
	return s
}

func writeList(b *strings.Builder, lines []string, tag string,
	is func(string) bool, text func(string) string) {

	b.WriteString("<" + tag + ">")
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if !is(t) {
			// A line that does not start a new item continues the last one,
			// which is what somebody wrapping a long bullet meant.
			b.WriteString(" " + inline(t))
			continue
		}
		b.WriteString("<li>" + inline(text(t)))
		b.WriteString("</li>")
	}
	b.WriteString("</" + tag + ">")
}

// inline escapes the text and then applies the inline markers.
//
// Escaping first is what makes the rest of this safe: after it, there is no <
// in the string, so nothing the scanner does can produce a tag that was not
// written here as a literal.
//
// Scanned rather than matched with expressions. A regular expression over
// attacker-supplied prose is a second question — how it backtracks — and this
// needs no answer to it: one pass, left to right, no lookahead beyond finding
// a closing marker.
func inline(s string) string {
	s = html.EscapeString(s)

	var b strings.Builder
	i := 0
	for i < len(s) {
		switch {
		case escaped(s, i):
			b.WriteByte(s[i+1])
			i += 2
			continue
		case strings.HasPrefix(s[i:], `\&gt;`):
			// A quotation's marker, escaped: it was a > before escaping.
			b.WriteString("&gt;")
			i += len(`\&gt;`)
			continue
		case strings.HasPrefix(s[i:], "**"):
			if j := find(s[i+2:], "**"); j >= 0 {
				b.WriteString("<strong>" + inlineRest(s[i+2:i+2+j]) + "</strong>")
				i += 2 + j + 2
				continue
			}
		case s[i] == '*':
			if j := find(s[i+1:], "*"); j >= 0 {
				b.WriteString("<em>" + inlineRest(s[i+1:i+1+j]) + "</em>")
				i += 1 + j + 1
				continue
			}
		case s[i] == '`':
			if j := strings.IndexByte(s[i+1:min(len(s), i+1+maxSpan)], '`'); j >= 0 {
				// No markers inside code. The point of it is that what is in
				// there is what it says.
				b.WriteString("<code>" + s[i+1:i+1+j] + "</code>")
				i += 1 + j + 1
				continue
			}
		case s[i] == '[':
			if text, href, n, ok := link(s[i:]); ok {
				b.WriteString(`<a href="` + href + `">` + inlineRest(text) + "</a>")
				i += n
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// inlineRest applies markers to text that is already escaped.
func inlineRest(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		switch {
		case escaped(s, i):
			b.WriteByte(s[i+1])
			i += 2
			continue
		case strings.HasPrefix(s[i:], "**"):
			if j := find(s[i+2:], "**"); j >= 0 {
				b.WriteString("<strong>" + unescape(s[i+2:i+2+j]) + "</strong>")
				i += 2 + j + 2
				continue
			}
		case s[i] == '`':
			if j := strings.IndexByte(s[i+1:min(len(s), i+1+maxSpan)], '`'); j >= 0 {
				b.WriteString("<code>" + s[i+1:i+1+j] + "</code>")
				i += 1 + j + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// Backslash escapes, so text can say what a marker says without being one.
//
// Text brought from another site is full of them: "5 * 3", a footnote in
// square brackets, a price with an asterisk. Without a way to write them,
// whatever wrote this subset for somebody else's words had to choose between
// losing the characters and having them read as markup. A backslash before
// one of the markers, or before a backslash, is that character and nothing
// more, as in every other Markdown.
const escapable = "\\*`[]()#->_!+."

// escaped says whether s[i] is a backslash escaping the character after it.
func escaped(s string, i int) bool {
	return s[i] == '\\' && i+1 < len(s) && strings.IndexByte(escapable, s[i+1]) >= 0
}

// Lookahead bounds. Each marker looks this far for its partner and no
// further, so a page of nothing but [ or * is read in one pass rather than
// one pass per character: without them, twenty thousand unclosed brackets
// took a second and a half to render, on every request for the page.
const (
	maxSpan     = 4096 // bold, italic or code
	maxLinkText = 1024
	maxLinkURL  = 2048
)

// find is the first marker in s that is not escaped, within maxSpan, or -1.
func find(s, marker string) int { return findWithin(s, marker, maxSpan) }

// findWithin is the first marker in s that is not escaped, starting within
// limit bytes, or -1.
func findWithin(s, marker string, limit int) int {
	if len(s) > limit+len(marker) {
		s = s[:limit+len(marker)]
	}
	for from := 0; ; {
		j := strings.Index(s[from:], marker)
		if j < 0 {
			return -1
		}
		j += from
		// Escaped when an odd run of backslashes stands before it: each
		// pair is one backslash, and one left over escapes the marker.
		n := 0
		for k := j - 1; k >= 0 && s[k] == '\\'; k-- {
			n++
		}
		if n%2 == 0 {
			return j
		}
		from = j + 1
	}
}

// unescape is text with its escapes taken out, and no markers applied.
func unescape(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if escaped(s, i) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// link reads [text](url) from the front of s.
//
// The scheme is checked the same way a URL in a template attribute is, by the
// same table — so `javascript:` is refused here for the reason it is refused
// there, and the two cannot drift apart into a link that is safe in one place
// and not in the other.
func link(s string) (text, href string, n int, ok bool) {
	close := findWithin(s, "]", maxLinkText)
	if close < 0 || !strings.HasPrefix(s[close+1:], "(") {
		return "", "", 0, false
	}
	// Balanced, not the first one. Wikipedia puts parentheses in addresses —
	// /wiki/Mercury_(planet) — and taking the first ) makes that link point at
	// half an address with a stray bracket printed after it.
	end, depth := -1, 0
	for i := 0; i < len(s[close+2:]) && i < maxLinkURL; i++ {
		switch s[close+2+i] {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				end = i
			} else {
				depth--
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return "", "", 0, false
	}
	text = s[1:close]
	raw := s[close+2 : close+2+end]
	// A link with no words is one nobody can tell where it goes, least of
	// all somebody listening to the page.
	if find(text, "[") >= 0 || find(text, "]") >= 0 || strings.TrimSpace(text) == "" {
		return "", "", 0, false
	}
	// The URL arrives already HTML-escaped, because inline escaped the whole
	// string before scanning. escapeURL parses it, so it is unescaped for the
	// scheme check and escaped again for the attribute.
	return text, escapeURL(html.UnescapeString(raw)), close + 2 + end + 1, true
}

// EscapeProse is text written so Prose shows it as the words it is: every
// marker character escaped, and a line that would begin a heading, a list or
// a quotation escaped at its start. For whatever writes somebody else's words
// into this subset, such as a site brought from elsewhere.
func EscapeProse(text string) string {
	var b strings.Builder
	for i, line := range strings.Split(text, "\n") {
		if i > 0 {
			b.WriteByte('\n')
		}
		trimmed := strings.TrimLeft(line, " \t")
		lead := line[:len(line)-len(trimmed)]
		b.WriteString(lead)
		switch {
		case strings.HasPrefix(trimmed, "#"), strings.HasPrefix(trimmed, "> "), strings.HasPrefix(trimmed, "- "),
			strings.HasPrefix(trimmed, "+ "):
			b.WriteByte('\\')
		case isNumber(trimmed):
			// "1. " is a list; "1\. " is a number and a full stop.
			n := strings.Index(trimmed, ". ")
			b.WriteString(escapeMarkers(trimmed[:n]) + "\\")
			trimmed = trimmed[n:]
		}
		b.WriteString(escapeMarkers(trimmed))
	}
	return b.String()
}

// escapeMarkers escapes the inline markers and the backslash.
func escapeMarkers(s string) string {
	if !strings.ContainsAny(s, "\\*`[]") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.IndexByte("\\*`[]", s[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// PlainProse is words in the subset as plain text: its markers and escapes
// taken out, a link as its words. For a summary or a search result, where
// markup would be shown as it is.
func PlainProse(src string) string {
	var b strings.Builder
	for i := 0; i < len(src); i++ {
		switch c := src[i]; {
		case escaped(src, i):
			i++
			b.WriteByte(src[i])
		case c == '*' || c == '`':
		case c == '[':
			if text, _, n, ok := link(src[i:]); ok {
				b.WriteString(unescape(text))
				i += n - 1
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
