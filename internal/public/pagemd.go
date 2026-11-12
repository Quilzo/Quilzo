// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/render"
)

// A Markdown copy of every published page, at /NAME.md: what a language
// model or a reader's agent wants from a page, its words in order, without
// the markup around them. llms.txt links these.
//
// Made from the content, not from the rendered HTML: titles become
// headings, a section's items become a list, links keep their address. It
// is never indexed, and names the page it copies as canonical, so it does
// not compete with the page in search results.
//
// The content as the page is drawn with it (Sources.For), not as it is
// stored. A listing's rows, a blog's posts and the events still to come are
// not in the page's own fields: they are read when the page is asked for.
// Made from the stored page, /shop.md was the shop's heading and intro and
// not one product, /blog.md not one post and /events.md not one event, and
// an agent that llms.txt sent there was told the shop sold nothing. A record
// that has a page of its own has a copy too (recordMarkdown).

// mdKeys are the fields read as a section's words, in order.
var mdKeys = []string{"eyebrow", "lead", "subtitle", "intro", "summary", "description", "text", "body", "quote", "caption"}

// mdSkip are fields that are never words. Not "listing": drawn, a listing
// section carries its rows.
var mdSkip = map[string]bool{"id": true, "icon": true, "image": true, "images": true, "video": true, "layout": true,
	"form": true, "style": true, "variant": true, "slug": true, "block": true,
	"noindex": true, "canonical": true, "members_only": true, "expires": true, "starts": true}

var reMediaID = regexp.MustCompile(`^[0-9a-f]{64}$`)

const mdMaxDepth = 6

// markdownOf is a page's content as Markdown: the page as it is drawn, and
// the listings it names by its page field, which a layout draws after it.
func markdownOf(body any, feeds []any) string {
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
	for _, f := range feeds {
		if feed, ok := f.(map[string]any); ok {
			mdSection(&b, feed, 0)
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
		// A video's caption tracks are a list the drawing adds, and are
		// files, not words.
		items, ok := m[k].([]any)
		if !ok || mdSkip[k] || k == "body_paragraphs" || strings.HasSuffix(k, "_tracks") {
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

// mdItem is one list item: its title or label, a link when it has one, when
// and where it is and what it costs, and its text.
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
	if d := mdDetails(m); d != "" && label != "" {
		label += " (" + d + ")"
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

// mdDetails is what a row says beside its name, as the page shows it: an
// event's or a post's date in words, an event's place, and a price as
// written out. A price stored as a number (pence) is not one a reader can
// read, and the page shows the written one.
func mdDetails(m map[string]any) string {
	var out []string
	for _, k := range []string{"when", "place"} {
		if s, ok := m[k].(string); ok && oneLine(s) != "" {
			out = append(out, oneLine(s))
		}
	}
	for _, k := range []string{"price_display", "buy_price", "price"} {
		if s, ok := m[k].(string); ok && oneLine(s) != "" {
			out = append(out, oneLine(s))
			break
		}
	}
	return strings.Join(out, " · ")
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
	markdownHeaders(w, st.canonicalIn(base, body, st.variants(pages)))
	// Drawn with no request arguments: the copy is one document for every
	// reader, as its cache header says, and a booking's or a sign-up's
	// arguments are one visitor's. A page that cannot be drawn (a listing
	// that does not resolve) still has its own words.
	page, feeds := body, []any(nil)
	if ctx, err := st.sources().For(base, body, nil); err == nil {
		page = ctx["page"]
		feeds, _ = ctx[render.Feeds].([]any)
	}
	_, _ = w.Write([]byte(markdownOf(page, feeds)))
	return true
}

// markdownHeaders are a copy's headers: never indexed, and naming the
// address it copies.
func markdownHeaders(w http.ResponseWriter, canonical string) {
	h := w.Header()
	h.Set("Content-Type", "text/markdown; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Cache-Control", "public, max-age=0, must-revalidate")
	if canonical != "" {
		h.Set("Link", "<"+canonical+`>; rel="canonical"`)
	}
}

// recordMarkdown serves the copy of one record's page, at /PAGE/KEY.md:
// its name, when and where it is, what it costs and who wrote it, as its
// page says them, then its words. Only the fields the listing exposes,
// because the row is the listing's (findRecord).
func (st *Site) recordMarkdown(w http.ResponseWriter, name, key string, d Detail, row listing.Row) {
	rec := map[string]any(row)
	var view map[string]any
	switch {
	case st.Events != "" && d.Listing == st.Events:
		view = st.eventView(row)
	case st.Blog != "" && d.Listing == st.Blog:
		view = postView(row, st.linksFor(st.Blog))
	}
	var b strings.Builder
	for _, k := range []string{"title", "name"} {
		if t, ok := rec[k].(string); ok && oneLine(t) != "" {
			fmt.Fprintf(&b, "# %s\n\n", oneLine(t))
			break
		}
	}
	about := map[string]any{}
	for k, v := range rec {
		about[k] = v
	}
	for k, v := range view {
		about[k] = v
	}
	var said []string
	if d := mdDetails(about); d != "" {
		said = append(said, d)
	}
	for _, k := range []string{"address", "byline"} {
		if s, ok := about[k].(string); ok && oneLine(s) != "" {
			said = append(said, oneLine(s))
		}
	}
	if len(said) > 0 {
		b.WriteString(strings.Join(said, " · ") + "\n\n")
	}
	mdWords(&b, rec, 0)
	markdownHeaders(w, st.recordURL(name, key))
	_, _ = w.Write([]byte(strings.TrimSpace(b.String()) + "\n"))
}
