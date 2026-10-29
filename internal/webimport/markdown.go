// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webimport

import (
	"net/url"
	"regexp"
	"strings"
)

// Markdown, as Hugo, Jekyll, Eleventy, Astro, Docusaurus, Gatsby, Notion and
// Obsidian write it, read into blocks.
//
// The subset this site's pages take (internal/tmpl) is Markdown's own
// syntax, so most of a sentence passes through as it was written: bold,
// italic, code and links. What the subset does not take is turned into what
// it does: underscores into asterisks, reference links and autolinks into
// links, a link to another file into a link to where that page is now. A
// picture becomes a block of its own; HTML, a generator's shortcodes and a
// template's tags are left behind, their words kept.

var (
	reMDImage     = regexp.MustCompile(`!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)`)
	reMDLink      = regexp.MustCompile(`\[([^\]]+)\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)`)
	reMDRefLink   = regexp.MustCompile(`\[([^\]]+)\]\[([^\]]*)\]`)
	reMDRefDef    = regexp.MustCompile(`^\s{0,3}\[([^\]]+)\]:\s*<?(\S+?)>?(?:\s+["'(].*["')])?\s*$`)
	reMDAutolink  = regexp.MustCompile(`<(https?://[^\s>]+)>`)
	reMDBold      = regexp.MustCompile(`(^|[^\w_])__([^_\n]+?)__([^\w_]|$)`)
	reMDItalic    = regexp.MustCompile(`(^|[^\w_])_([^_\n]+?)_([^\w_]|$)`)
	reMDStrike    = regexp.MustCompile(`~~([^~\n]+)~~`)
	reShortcodes  = regexp.MustCompile(`\{\{[<%].*?[%>]\}\}`)
	reFigure      = regexp.MustCompile(`\{\{[<%]\s*(?:figure|image|img)\s+([^}]*?)[%>]\}\}`)
	reShortAttr   = regexp.MustCompile(`(\w+)\s*=\s*"([^"]*)"`)
	reLiquid      = regexp.MustCompile(`\{%.*?%\}|\{\{.*?\}\}`)
	reHTMLTag     = regexp.MustCompile(`</?[a-zA-Z][^>]*>`)
	reHTMLComment = regexp.MustCompile(`(?s)<!--.*?-->`)
	reHeading     = regexp.MustCompile(`^(#{1,6})\s+(.*?)\s*#*\s*$`)
	reBullet      = regexp.MustCompile(`^\s*(?:[-*+]|\d{1,3}[.)])\s+(.*)$`)
	reFence       = regexp.MustCompile("^\\s*(```|~~~)")
	reTableSep    = regexp.MustCompile(`^\s*\|?\s*:?-{3,}`)
)

// mdReader reads one file's Markdown; resolve says where a link or a
// picture it names is, and is nil for none.
type mdReader struct {
	resolve func(ref string, picture bool) *url.URL
	refs    map[string]string
}

// mdBlocks reads Markdown into blocks.
func mdBlocks(src string, resolve func(string, bool) *url.URL) []Block {
	r := &mdReader{resolve: resolve, refs: map[string]string{}}
	src = strings.ReplaceAll(strings.ReplaceAll(src, "\r\n", "\n"), "\t", "    ")
	src = reHTMLComment.ReplaceAllString(src, "")
	lines := strings.Split(src, "\n")
	// Reference definitions first, so a link can use one defined below it.
	kept := lines[:0]
	for _, l := range lines {
		if m := reMDRefDef.FindStringSubmatch(l); m != nil {
			r.refs[strings.ToLower(m[1])] = m[2]
			continue
		}
		kept = append(kept, l)
	}
	lines = kept

	var out []Block
	var para []string
	kind := "p"
	flush := func() {
		if len(para) == 0 {
			return
		}
		out = append(out, r.block(kind, strings.Join(para, " "))...)
		para, kind = nil, "p"
	}
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			flush()
		case reFence.MatchString(line):
			flush()
			fence := reFence.FindStringSubmatch(line)[1]
			var code []string
			for i++; i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), fence); i++ {
				code = append(code, lines[i])
			}
			if text := strings.TrimSpace(strings.Join(code, "\n")); text != "" {
				out = append(out, Block{Kind: "pre", Text: text})
			}
		case reHeading.MatchString(trimmed):
			flush()
			m := reHeading.FindStringSubmatch(trimmed)
			out = append(out, r.block("h"+string(rune('0'+len(m[1]))), m[2])...)
		case i+1 < len(lines) && len(para) == 0 && strings.Trim(strings.TrimSpace(lines[i+1]), "=") == "" &&
			strings.TrimSpace(lines[i+1]) != "":
			out = append(out, r.block("h1", trimmed)...)
			i++
		case i+1 < len(lines) && len(para) == 0 && isRule(lines[i+1]) &&
			strings.Trim(strings.TrimSpace(lines[i+1]), "-") == "" && !reBullet.MatchString(line):
			out = append(out, r.block("h2", trimmed)...)
			i++
		case isRule(line):
			flush()
		case strings.HasPrefix(trimmed, ">"):
			if kind != "quote" {
				flush()
				kind = "quote"
			}
			para = append(para, strings.TrimSpace(strings.TrimLeft(trimmed, "> ")))
		case reBullet.MatchString(line):
			flush()
			kind = "li"
			para = append(para, reBullet.FindStringSubmatch(line)[1])
		case strings.HasPrefix(trimmed, "|"):
			flush()
			if reTableSep.MatchString(trimmed) {
				continue
			}
			var cells []string
			for _, c := range strings.Split(strings.Trim(trimmed, "|"), "|") {
				if c = strings.TrimSpace(c); c != "" {
					cells = append(cells, c)
				}
			}
			if len(cells) > 0 {
				out = append(out, r.block("p", strings.Join(cells, " · "))...)
			}
		case strings.HasPrefix(trimmed, "<") && reHTMLTag.MatchString(trimmed) && len(para) == 0:
			// A block of HTML, read as a page's would be, to its end.
			var chunk []string
			for ; i < len(lines) && strings.TrimSpace(lines[i]) != ""; i++ {
				chunk = append(chunk, lines[i])
			}
			out = append(out, r.html(strings.Join(chunk, "\n"))...)
		default:
			if kind == "li" && strings.HasPrefix(line, "  ") {
				// A wrapped list item goes on.
				para = append(para, trimmed)
				continue
			}
			if kind != "p" {
				flush()
			}
			para = append(para, trimmed)
		}
	}
	flush()
	return out
}

// html reads a block of HTML in Markdown, resolving its pictures.
func (r *mdReader) html(chunk string) []Block {
	var out []Block
	for _, b := range Read([]byte("<main>"+chunk+"</main>"), &url.URL{Scheme: "https", Host: LocalHost, Path: "/"}).Blocks {
		if b.Kind == "img" {
			if b.Src == nil || r.resolve == nil {
				continue
			}
			ref := b.Src.Path
			if b.Src.Host != LocalHost {
				ref = b.Src.String()
			}
			if b.Src = r.resolve(ref, true); b.Src == nil {
				continue
			}
		}
		b.MD = ""
		out = append(out, b)
	}
	return out
}

// block is one block of Markdown's words, and the pictures it held after it.
func (r *mdReader) block(kind, text string) []Block {
	var pictures []Block
	text = reFigure.ReplaceAllStringFunc(text, func(m string) string {
		attrs := map[string]string{}
		for _, a := range reShortAttr.FindAllStringSubmatch(reFigure.FindStringSubmatch(m)[1], -1) {
			attrs[a[1]] = a[2]
		}
		if src := attrs["src"]; src != "" && r.resolve != nil {
			if u := r.resolve(src, true); u != nil {
				alt := attrs["alt"]
				if alt == "" {
					alt = attrs["caption"]
				}
				pictures = append(pictures, Block{Kind: "img", Text: strings.TrimSpace(alt), Src: u})
			}
		}
		return ""
	})
	text = reShortcodes.ReplaceAllString(text, "")
	text = reLiquid.ReplaceAllString(text, "")
	text = reMDImage.ReplaceAllStringFunc(text, func(m string) string {
		sub := reMDImage.FindStringSubmatch(m)
		if r.resolve != nil {
			if u := r.resolve(sub[2], true); u != nil {
				pictures = append(pictures, Block{Kind: "img", Text: strings.TrimSpace(sub[1]), Src: u})
			}
		}
		return ""
	})
	text = reMDAutolink.ReplaceAllString(text, "[$1]($1)")
	text = reMDRefLink.ReplaceAllStringFunc(text, func(m string) string {
		sub := reMDRefLink.FindStringSubmatch(m)
		id := sub[2]
		if id == "" {
			id = sub[1]
		}
		if target, ok := r.refs[strings.ToLower(id)]; ok {
			return "[" + sub[1] + "](" + target + ")"
		}
		return sub[1]
	})
	text = reHTMLTag.ReplaceAllString(text, "")
	text = reMDStrike.ReplaceAllString(text, "$1")
	text = reMDBold.ReplaceAllString(text, "$1**$2**$3")
	text = reMDItalic.ReplaceAllString(text, "$1*$2*$3")
	// Links resolved to where they go now, or to their words when they go
	// nowhere this can say.
	text = reMDLink.ReplaceAllStringFunc(text, func(m string) string {
		sub := reMDLink.FindStringSubmatch(m)
		if r.resolve != nil {
			if u := r.resolve(sub[2], false); u != nil {
				return "[" + sub[1] + "](" + u.String() + ")"
			}
		}
		return sub[1]
	})
	md := strings.Join(strings.Fields(text), " ")
	var out []Block
	if plain := mdPlain(md); plain != "" {
		out = append(out, Block{Kind: kind, Text: plain, MD: md})
	}
	return append(out, pictures...)
}

// mdPlain is words in the prose subset without their markers: what a
// heading, a lead or a summary says.
func mdPlain(md string) string {
	s := reMDLink.ReplaceAllString(md, "$1")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case c == '*' || c == '`':
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

// isRule says whether a line is a horizontal rule: three or more of one of
// -, * or _, with spaces between if it likes.
func isRule(line string) bool {
	t := strings.ReplaceAll(strings.TrimSpace(line), " ", "")
	if len(t) < 3 || strings.IndexByte("-*_", t[0]) < 0 {
		return false
	}
	return strings.Count(t, t[:1]) == len(t)
}
