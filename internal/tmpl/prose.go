// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package tmpl

import (
	"html"
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
//
// # What it deliberately does not do
//
// Raw HTML in the source is escaped, never passed through. Every Markdown
// implementation in wide use allows inline HTML and that is exactly the
// property this cannot have — the input is content, and content is written by
// whoever can write content.
//
// No images. Media in this program goes through a library that will not store
// a picture without a description and tracks the licence it was used under, so
// an image syntax here would be a second way in that skips both.
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

func writeBlock(b *strings.Builder, lines []string) {
	first := strings.TrimSpace(lines[0])

	switch {
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
		case strings.HasPrefix(s[i:], "**"):
			if j := strings.Index(s[i+2:], "**"); j >= 0 {
				b.WriteString("<strong>" + inlineRest(s[i+2:i+2+j]) + "</strong>")
				i += 2 + j + 2
				continue
			}
		case s[i] == '*':
			if j := strings.IndexByte(s[i+1:], '*'); j >= 0 {
				b.WriteString("<em>" + inlineRest(s[i+1:i+1+j]) + "</em>")
				i += 1 + j + 1
				continue
			}
		case s[i] == '`':
			if j := strings.IndexByte(s[i+1:], '`'); j >= 0 {
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
		case strings.HasPrefix(s[i:], "**"):
			if j := strings.Index(s[i+2:], "**"); j >= 0 {
				b.WriteString("<strong>" + s[i+2:i+2+j] + "</strong>")
				i += 2 + j + 2
				continue
			}
		case s[i] == '`':
			if j := strings.IndexByte(s[i+1:], '`'); j >= 0 {
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

// link reads [text](url) from the front of s.
//
// The scheme is checked the same way a URL in a template attribute is, by the
// same table — so `javascript:` is refused here for the reason it is refused
// there, and the two cannot drift apart into a link that is safe in one place
// and not in the other.
func link(s string) (text, href string, n int, ok bool) {
	close := strings.IndexByte(s, ']')
	if close < 0 || !strings.HasPrefix(s[close+1:], "(") {
		return "", "", 0, false
	}
	// Balanced, not the first one. Wikipedia puts parentheses in addresses —
	// /wiki/Mercury_(planet) — and taking the first ) makes that link point at
	// half an address with a stray bracket printed after it.
	end, depth := -1, 0
	for i := 0; i < len(s[close+2:]); i++ {
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
	if strings.ContainsAny(text, "[]") {
		return "", "", 0, false
	}
	// The URL arrives already HTML-escaped, because inline escaped the whole
	// string before scanning. escapeURL parses it, so it is unescaped for the
	// scheme check and escaped again for the attribute.
	return text, escapeURL(html.UnescapeString(raw)), close + 2 + end + 1, true
}
