// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package assistant is a chatbot a site owner declares, that answers from
// the site and can offer to do things on the visitor's behalf.
//
// # What everybody else ships, and the part they leave out
//
// Dify, Flowise and Langflow have made "a chatbot over your documents" a
// ten-minute job, and the ten minutes are real. What the ten minutes do not
// include is the step that decides whether the answer is true. The measured
// state of the art is that citations from generative systems are frequently
// unsupported, and that even correct citations often do not reflect the
// passage the model used. A site's own chatbot inventing a returns policy or
// a price is worse than no chatbot: it is the site saying something false in
// its own voice.
//
// So this checks every sentence. An answer is split into sentences, each must
// cite a passage it was given, and each is compared with what it cites: the
// words it rests on have to be there, and any number in it — a price, a
// date, a quantity, the thing a model most often makes up — has to appear in
// the cited text. A sentence that fails is removed and the removal is
// reported. If nothing survives, or nothing relevant was found, the assistant
// says it does not know. "I could not find that on this site" is an answer a
// visitor can act on; a confident invention is not.
//
// # Retrieval, and why not a vector database
//
// Passages, not pages: a page about delivery that also mentions returns
// should be cited for the paragraph about returns. Each passage carries its
// page title and heading as a header, which is the cheap half of contextual
// retrieval — a paragraph that says "within 30 days" means nothing without
// the heading that says what it is about.
//
// Two rankers, fused. BM25 over the passages, which is the strongest single
// retriever on out-of-domain text and a site is always out of domain, and
// TF-IDF cosine through internal/vector, which ranks by overall overlap
// rather than by the rarest term. Reciprocal rank fusion (k = 60) combines
// them by rank, so neither needs its scores calibrated against the other. At
// the size of any site this program serves, an exact scan is milliseconds;
// the cost of dense retrieval is the embedding model, and internal/vector's
// Provider is where one plugs in when an operator wants it.
//
// # Works with no model at all
//
// Without a model configured the assistant answers extractively: the most
// relevant sentences from the best passages, each cited. That is a useful
// assistant on its own, needs no key and no network, and is the fallback when
// a model's answer fails verification.
package assistant

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/quilzo/quilzo/internal/plaintext"
)

// Passage is one retrievable piece of a published page.
type Passage struct {
	// ID is page#n, stable for a given commit.
	ID      string `json:"id"`
	Page    string `json:"page"`
	Title   string `json:"title,omitempty"`
	Heading string `json:"heading,omitempty"`
	Text    string `json:"text"`
	// Doc is the media library id when the passage is from a document
	// rather than a page, and DocName its file name.
	Doc     string `json:"doc,omitempty"`
	DocName string `json:"doc_name,omitempty"`
}

// Link is where a citation of this passage points.
func (p Passage) Link() string {
	if p.Doc != "" {
		return "/media/" + p.Doc
	}
	return "/" + p.Page
}

// Header is what the passage is about, prepended when it is indexed.
func (p Passage) Header() string {
	if p.Title == "" && p.DocName != "" {
		if p.Heading != "" {
			return p.DocName + " › " + p.Heading
		}
		return p.DocName
	}
	switch {
	case p.Title != "" && p.Heading != "":
		return p.Title + " › " + p.Heading
	case p.Title != "":
		return p.Title
	}
	return p.Heading
}

// Target words per passage. Long enough to hold a whole answer to a
// question, short enough that citing it points at something specific.
const (
	targetWords = 120
	maxWords    = 220
)

// skipField are page fields that are wiring rather than content. A layout
// name or a listing reference retrieved as an answer would be nonsense.
//
// So is a page's furniture. A section page carries its arrangement — a
// hero's style and surface, a section's tone and columns — its buttons and
// the addresses they go to, and, on a page with a question box, the
// questions it suggests asking. Read as knowledge, those were quoted back
// as answers: asked "what happens when an agent wants to publish?", the
// chatbot found the suggestion with exactly those words and answered with
// the question.
var skipField = map[string]bool{
	"layout": true, "screen": true, "detail": true, "detail_key": true,
	"listings": true, "listing": true, "template": true, "slug": true,
	"id": true, "href": true, "url": true, "src": true, "image": true,
	// Arrangement.
	"style": true, "surface": true, "tone": true, "columns": true,
	"flip": true, "align": true, "view": true, "shape": true,
	"header_class": true, "og_type": true, "lang": true, "featured": true,
	"state": true, "pct": true, "legend": true, "eyebrow": true, "chip": true,
	"brand_mark": true, "breadcrumbs": true, "filters": true, "form": true,
	"starts": true, "expires": true, "poster": true, "showcase": true,
	// The colophon a layout repeats under every page. The same sentences
	// on every page rank every page alike, and padded the answer from
	// whichever page won with a copyright line.
	"footer": true,
	// Buttons, and what a question box offers to ask.
	"cta_label": true, "secondary_label": true, "header_cta_label": true,
	"button": true, "placeholder": true, "suggestions": true,
	"suggestions_label": true, "assistant": true,
}

// wiring reports whether a field holds wiring rather than content, by its
// name: the list above, and any link, picture or source set by its suffix.
func wiring(k string) bool {
	if skipField[k] {
		return true
	}
	for _, suffix := range []string{"_href", "_image", "_srcset", "_url", "_tracks"} {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}

// Chunk splits pages into passages.
//
// allow decides which pages the assistant may read. Called per page name,
// so an owner can confine a support assistant to /help without it answering
// from the pricing negotiations draft somebody published by mistake.
func Chunk(pages map[string]any, allow func(page string) bool) []Passage {
	names := make([]string, 0, len(pages))
	for n := range pages {
		if allow == nil || allow(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	var out []Passage
	for _, name := range names {
		body, ok := pages[name].(map[string]any)
		if !ok {
			continue
		}
		title, _ := body["title"].(string)
		title = oneLine(title)
		var blocks []block
		collect(body, "", &blocks, 0)
		out = append(out, pack(name, title, blocks)...)
	}
	return out
}

// headingKeys are the fields that name what an object inside a page is
// about, in the order they are looked for.
var headingKeys = []string{"q", "question", "title", "name", "heading"}

// maxHeading is the longest value taken as a heading; longer, it is prose.
const maxHeading = 160

// shortField is how many words a field value may have before it is treated
// as prose rather than as a labelled value.
const shortField = 4

// fieldLabel turns a field name into words: last_updated is "Last updated".
func fieldLabel(k string) string {
	k = strings.NewReplacer("_", " ", "-", " ").Replace(k)
	if k == "" {
		return k
	}
	return strings.ToUpper(k[:1]) + k[1:]
}

// block is a paragraph with the heading it sits under.
type block struct {
	heading string
	text    string
}

// collect walks a page's fields in a stable order, keeping text and noting
// markdown headings as it passes them.
func collect(v any, heading string, out *[]block, depth int) string {
	if depth > 8 {
		return heading
	}
	switch t := v.(type) {
	case string:
		for _, para := range splitParagraphs(t) {
			if h, ok := headingOf(para); ok {
				heading = h
				continue
			}
			if para = oneLine(para); para != "" {
				*out = append(*out, block{heading: heading, text: para})
			}
		}
	case map[string]any:
		// Inside a page, an object's own title — a section's, a card's, a
		// step's, or an FAQ's question — is what its text is about, so it
		// is the heading that text is filed under, and only for as long as
		// the object lasts. Read as one more field, in alphabetical order,
		// an FAQ's answer ("a") came before its question ("q") and a card's
		// body before its title, so each passage held one item's answer and
		// the next one's question, and the extractive answer to a question
		// was the question.
		before := heading
		own := ""
		if depth > 0 {
			for _, k := range headingKeys {
				if v, ok := t[k].(string); ok {
					if line := oneLine(v); line != "" && len(line) <= maxHeading {
						own = k
						heading = line
						break
					}
				}
			}
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			if k == own || wiring(k) || strings.HasPrefix(k, "_") || k == "title" && depth == 0 {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		start := len(*out)
		for _, k := range keys {
			// A short value means little without its field's name: a page's
			// "updated: 2026-06-01" retrieved as the sentence "2026-06-01" is
			// noise, and "price: £46" retrieved as "£46" answers nothing. So
			// a value of a few words carries the name it was stored under.
			if v, ok := t[k].(string); ok {
				if line := oneLine(v); line != "" && len(strings.Fields(line)) <= shortField {
					if _, isHeading := headingOf(line); !isHeading {
						*out = append(*out, block{heading: heading,
							text: fieldLabel(k) + ": " + line + "."})
						continue
					}
				}
			}
			heading = collect(t[k], heading, out, depth+1)
		}
		if own != "" {
			// A title with nothing under it is still something the page says.
			if len(*out) == start {
				*out = append(*out, block{heading: before, text: heading})
			}
			return before
		}
	case []any:
		for _, x := range t {
			heading = collect(x, heading, out, depth+1)
		}
	}
	return heading
}

func splitParagraphs(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var out []string
	for _, p := range strings.Split(s, "\n\n") {
		// A heading line at the top of a paragraph is its own block.
		lines := strings.Split(strings.TrimSpace(p), "\n")
		var rest []string
		for _, l := range lines {
			if _, ok := headingOf(l); ok {
				if len(rest) > 0 {
					out = append(out, strings.Join(rest, " "))
					rest = nil
				}
				out = append(out, l)
				continue
			}
			rest = append(rest, l)
		}
		if len(rest) > 0 {
			out = append(out, strings.Join(rest, " "))
		}
	}
	return out
}

// headingOf recognises a markdown heading line.
func headingOf(line string) (string, bool) {
	l := strings.TrimSpace(line)
	if !strings.HasPrefix(l, "#") {
		return "", false
	}
	h := strings.TrimSpace(strings.TrimLeft(l, "#"))
	if h == "" || len(l)-len(strings.TrimLeft(l, "#")) > 6 {
		return "", false
	}
	return oneLine(h), true
}

// pack groups blocks into passages near the target size, never across a
// heading, so a passage is about one thing.
func pack(page, title string, blocks []block) []Passage {
	var out []Passage
	var cur []string
	var words int
	heading := ""
	flush := func() {
		if len(cur) == 0 {
			return
		}
		out = append(out, Passage{
			ID: fmt.Sprintf("%s#%d", page, len(out)+1), Page: page,
			Title: title, Heading: heading, Text: strings.Join(cur, " "),
		})
		cur, words = nil, 0
	}
	for _, b := range blocks {
		if b.heading != heading {
			flush()
			heading = b.heading
		}
		n := len(strings.Fields(b.text))
		if words > 0 && words+n > maxWords {
			flush()
		}
		cur = append(cur, b.text)
		words += n
		if words >= targetWords {
			flush()
		}
	}
	flush()
	return out
}

// oneLine collapses whitespace and strips control characters.
func oneLine(s string) string {
	// What draws nothing is taken out first: an instruction written in
	// invisible characters is read by a model and by nobody who reviewed
	// the page. See internal/plaintext.
	s = plaintext.Clean(s)
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// ChunkDocument splits a file from the media library into passages.
//
// Markdown and plain text keep their headings and paragraphs; a PDF has its
// text extracted first, and one whose text cannot be read is an error that
// says why rather than an empty contribution nobody notices.
func ChunkDocument(id, name, format string, body []byte) ([]Passage, error) {
	var text string
	switch format {
	case "md", "txt", "csv":
		text = string(body)
	case "pdf":
		t, err := PDFText(body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		text = pdfParagraphs(t)
	default:
		return nil, fmt.Errorf("%s is a %s, which holds no text a chatbot can "+
			"read; use a PDF, a Markdown or a text file", name, format)
	}
	var blocks []block
	collect(text, "", &blocks, 0)
	key := "doc:" + id
	if len(id) > 12 {
		key = "doc:" + id[:12]
	}
	ps := pack(key, "", blocks)
	for i := range ps {
		ps[i].Doc, ps[i].DocName = id, name
	}
	return ps, nil
}

// pdfParagraphs turns a PDF's lines into paragraphs and headings.
//
// A PDF has lines of layout, not paragraphs: a title and the sentence under
// it arrive as two lines, and joined they read "Warranty Every pen carries".
// A short line that does not end a sentence is taken as a heading, which is
// what it nearly always is in a policy or a price list; other lines run on
// into their paragraph.
func pdfParagraphs(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			b.WriteString("\n\n")
			continue
		}
		words := len(strings.Fields(line))
		last := line[len(line)-1]
		if words <= 8 && !strings.ContainsRune(".?!:;,", rune(last)) {
			b.WriteString("\n\n## " + line + "\n\n")
			continue
		}
		b.WriteString(line + " ")
	}
	return b.String()
}
