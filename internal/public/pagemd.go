// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/seo"
)

// A Markdown copy of every published page, at /NAME.md: what a language
// model or a reader's agent wants from a page, its words in order, without
// the markup around them. llms.txt links these.
//
// Made from the content, not from the rendered HTML: titles become
// headings, a section's items become a list, links keep their address. It
// is never indexed, and names the page it copies as canonical, so it does
// not compete with the page in search results.

// mdKeys are the fields read as a section's words, in order.
var mdKeys = []string{"eyebrow", "lead", "subtitle", "intro", "summary", "description", "text", "body", "quote", "caption"}

// mdSkip are fields that are never words.
var mdSkip = map[string]bool{"id": true, "icon": true, "image": true, "images": true, "video": true, "layout": true,
	"form": true, "style": true, "variant": true, "slug": true, "listing": true, "block": true,
	"noindex": true, "canonical": true, "members_only": true, "expires": true, "starts": true}

var reMediaID = regexp.MustCompile(`^[0-9a-f]{64}$`)

const mdMaxDepth = 6

// markdownOf is a page's content as Markdown.
func markdownOf(body any) string {
	m, ok := body.(map[string]any)
	if !ok {
		return ""
	}
	var b strings.Builder
	if t, _ := m["title"].(string); strings.TrimSpace(t) != "" {
		fmt.Fprintf(&b, "# %s\n\n", oneLine(t))
	}
	mdWords(&b, m, 0)
	if paras, ok := m["body_paragraphs"].([]any); ok {
		for _, p := range paras {
			if s, ok := p.(string); ok && strings.TrimSpace(s) != "" {
				b.WriteString(strings.TrimSpace(s) + "\n\n")
			}
		}
	}
	if sections, ok := m["sections"].([]any); ok {
		for _, s := range sections {
			sec, ok := s.(map[string]any)
			if !ok {
				continue
			}
			for _, k := range sortedKeys(sec) {
				inner, ok := sec[k].(map[string]any)
				if !ok || mdSkip[k] {
					continue
				}
				mdSection(&b, inner, 0)
			}
		}
	}
	return strings.TrimSpace(b.String()) + "\n"
}

// mdSection writes one section: its heading, its words, its items.
func mdSection(b *strings.Builder, m map[string]any, depth int) {
	if depth > mdMaxDepth {
		return
	}
	if t, _ := m["title"].(string); strings.TrimSpace(t) != "" {
		fmt.Fprintf(b, "%s %s\n\n", strings.Repeat("#", min(2+depth, 6)), oneLine(t))
	}
	mdWords(b, m, depth)
	for _, k := range sortedKeys(m) {
		items, ok := m[k].([]any)
		if !ok || mdSkip[k] || k == "body_paragraphs" {
			continue
		}
		wrote := false
		for _, it := range items {
			switch v := it.(type) {
			case string:
				if s := oneLine(v); s != "" && !reMediaID.MatchString(s) {
					fmt.Fprintf(b, "- %s\n", s)
					wrote = true
				}
			case map[string]any:
				if line := mdItem(v); line != "" {
					fmt.Fprintf(b, "- %s\n", line)
					wrote = true
				}
			}
		}
		if wrote {
			b.WriteString("\n")
		}
	}
}

// mdWords writes the prose fields of a map, in a fixed order.
func mdWords(b *strings.Builder, m map[string]any, depth int) {
	for _, k := range mdKeys {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" && !reMediaID.MatchString(strings.TrimSpace(s)) {
			b.WriteString(strings.TrimSpace(s) + "\n\n")
		}
	}
	if cta, ok := m["cta"].(map[string]any); ok && depth < mdMaxDepth {
		if line := mdItem(cta); line != "" {
			b.WriteString(line + "\n\n")
		}
	}
}

// mdItem is one list item: its title or label, a link when it has one, and
// its text.
func mdItem(m map[string]any) string {
	label := ""
	for _, k := range []string{"title", "label", "name", "question", "value"} {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			label = oneLine(s)
			break
		}
	}
	href, _ := m["href"].(string)
	if href = strings.TrimSpace(href); label != "" && safeHref(href) {
		label = "[" + label + "](" + href + ")"
	}
	text := ""
	for _, k := range []string{"text", "answer", "summary", "description", "body"} {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			text = oneLine(s)
			break
		}
	}
	switch {
	case label != "" && text != "":
		return label + ": " + text
	case label != "":
		return label
	}
	return text
}

// safeHref is a link worth keeping in Markdown: a path on this site or an
// http(s) address, with nothing that ends the link early.
func safeHref(h string) bool {
	if h == "" || strings.ContainsAny(h, " ()<>\n") {
		return false
	}
	return strings.HasPrefix(h, "/") || strings.HasPrefix(h, "https://") || strings.HasPrefix(h, "http://")
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pageMarkdown serves /NAME.md, when NAME is a published page anybody may
// read and NAME.md is not a page itself. False when it is not one.
func (st *Site) pageMarkdown(w http.ResponseWriter, r *http.Request, pages map[string]any, name string) bool {
	base, ok := strings.CutSuffix(name, ".md")
	if !ok {
		return false
	}
	if base == "index" || base == "" {
		base = st.Index
	}
	body, ok := pages[base]
	if !ok {
		return false
	}
	h := w.Header()
	h.Set("Content-Type", "text/markdown; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Cache-Control", "public, max-age=0, must-revalidate")
	if c := seo.Canonical(st.BaseURL, base, st.Index, body); c != "" {
		h.Set("Link", "<"+c+`>; rel="canonical"`)
	}
	_, _ = w.Write([]byte(markdownOf(body)))
	return true
}
