// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"html"
	"net/url"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/section"
)

// Editing from the page, rather than from a form that describes it.
//
// # What this is the answer to
//
// Every headless CMS comparison written this year puts visual and in-context
// editing at the top of what people ask for, and the README already refuses
// the usual implementation of it: "a drag-and-drop editor would mean an
// exception for the most attacker-interesting surface in the system." That
// argument is about drag and drop — an editor, a transport and a document
// model in the browser — and it holds.
//
// It is not an argument against in-context editing. The preview already serves
// the real page for a stated reason: "a preview panel that approximates the
// page is a second renderer that can disagree with the one readers get". What
// it did not do was offer any way back into the thing you were looking at, so
// finding the paragraph you wanted to change meant leaving, opening the
// editor, and finding it again among the fields.
//
// So: the real page, with the ways into it attached. Server-rendered links and
// nothing else. The result is in-context editing that works with JavaScript
// switched off, which as far as I can tell no other CMS offers.
//
// # Why it is a panel and not a pencil beside each paragraph
//
// A pencil floating over the paragraph it edits needs to know where that
// paragraph rendered, and only the layout knows: a layout is the operator's
// own file, and sections can be rendered in any shape or not at all. Injecting
// markup inside somebody's template on a guess produces an edit link attached
// to the wrong thing, which is worse than one attached to nothing.
//
// The panel says what the page is made of, in the order the page declares it,
// and every entry is one click from the control that changes it. That is the
// part that was missing; spatial anchoring would need the layout to cooperate,
// and a template language that can say "this is section three" is a template
// language with an index expression in it.
//
// # Why it is injected rather than wrapped in a frame
//
// A frame means the preview is a document inside a document, and then the
// links inside the page navigate the frame while the toolbar navigates the
// outer one — which is the arrangement where "back" does something different
// depending on what you last clicked. One document, one history.

// previewBar returns the panel to inject into a preview.
//
// It is built from what the page actually carries: its type's fields when it
// has a type, and its sections when it has sections. A page with neither gets
// the page-level links and nothing invented.
func previewBar(page string, body any, t schema.Type, typed bool) string {
	var b strings.Builder
	esc := html.EscapeString
	q := url.QueryEscape

	b.WriteString(`<div class="qz-bar"><details class="qz-panel" open>`)
	fmt.Fprintf(&b, `<summary><span class="qz-mark">Preview</span> %s</summary>`,
		esc(page))
	b.WriteString(`<div class="qz-body">`)

	// The page as a whole, first and always.
	fmt.Fprintf(&b,
		`<p class="qz-row"><a href="/page/%s">Edit this page</a> · `+
			`<a href="/sections?page=%s">Arrange sections</a> · `+
			`<a href="/">All pages</a></p>`,
		q(page), q(page))

	if fields := previewFields(body, t, typed); len(fields) > 0 {
		b.WriteString(`<p class="qz-what">Fields</p><ul class="qz-list">`)
		for _, f := range fields {
			// Into the editor and down to the field. The editor gives every
			// control id="f-KEY", so a fragment lands on the one you clicked
			// rather than at the top of a form with eleven boxes in it.
			fmt.Fprintf(&b,
				`<li><a href="/page/%s#f-%s">%s</a>`, q(page), q(f.key), esc(f.label))
			if f.preview != "" {
				fmt.Fprintf(&b, ` <span class="qz-peek">%s</span>`, esc(f.preview))
			}
			b.WriteString(`</li>`)
		}
		b.WriteString(`</ul>`)
	}

	// section.On rather than a second reader of the same shape. It already
	// knows that a section is a one-key object, which key wins when a
	// malformed one has two, and which kinds this build has — and a panel that
	// disagreed with the sections screen about what is on a page would be the
	// more confusing of the two.
	if placed := section.On(body); len(placed) > 0 {
		b.WriteString(`<p class="qz-what">Sections</p><ol class="qz-list">`)
		for _, sec := range placed {
			fmt.Fprintf(&b,
				`<li><a href="/sections/fields?page=%s&amp;at=%d">%s</a>`,
				q(page), sec.Index, esc(sec.Kind))
			if sec.Unknown {
				b.WriteString(` <span class="qz-peek">not a kind this build ` +
					`knows, so it renders as nothing</span>`)
			} else if sec.Label != "" {
				fmt.Fprintf(&b, ` <span class="qz-peek">%s</span>`, esc(sec.Label))
			}
			b.WriteString(`</li>`)
		}
		b.WriteString(`</ol>`)
	}

	b.WriteString(`<p class="qz-note">This is the draft, rendered by the ` +
		`renderer readers get. Nothing here is public until somebody ` +
		`publishes.</p>`)
	b.WriteString(`</div></details></div>`)
	return b.String()
}

// barField is one row in the panel.
type barField struct {
	key     string
	label   string
	preview string
}

// previewFields lists what can be edited, labelled the way the type labels it.
//
// A typed page is listed in the order the type declares, for the same reason
// the editor is: "the declaration is the author's sequence of thought". An
// untyped page is listed alphabetically, because there is no declared order to
// preserve and a map's own order is not one.
func previewFields(body any, t schema.Type, typed bool) []barField {
	m, ok := body.(map[string]any)
	if !ok {
		return nil
	}

	if typed {
		out := make([]barField, 0, len(t.Fields))
		for _, f := range t.Fields {
			label := f.Label
			if label == "" {
				label = f.Name
			}
			out = append(out, barField{f.Name, label, peek(m[f.Name])})
		}
		return out
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		// The arrangement is listed separately and the layout is not content.
		if k == "sections" || k == "layout" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]barField, 0, len(keys))
	for _, k := range keys {
		out = append(out, barField{k, k, peek(m[k])})
	}
	return out
}

// peek is enough of a value to recognise which field it is.
//
// Short, and cut on a rune boundary rather than a byte: cutting a multi-byte
// character in half produces a replacement glyph in the panel, and the panel
// is a thing somebody reads.
func peek(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	s = strings.Join(strings.Fields(s), " ")
	const max = 48
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return strings.TrimSpace(string(runes[:max])) + "…"
}

// PreviewBarCSS is the panel's stylesheet, served at /preview.css.
//
// A file rather than a <style> element, because the policy on every response
// here is `style-src 'self'`: an inline stylesheet is refused, silently, and
// the panel would render as unstyled markup on top of somebody's page. Served
// from this origin is what that directive permits, and it also means the
// browser caches it instead of carrying it in every preview.
//
// Every selector begins .qz-, and the panel sets its own font rather than
// inheriting: it is sitting inside somebody else's design, and a toolbar that
// takes on the page's typography is a toolbar that disappears into the page it
// is a toolbar for. It must also not move the page — position: fixed, so the
// layout below it is exactly the layout a reader gets.
const PreviewBarCSS = `
.qz-bar{position:fixed;top:0;left:0;right:0;z-index:2147483647;
  font:14px/1.4 system-ui,-apple-system,"Segoe UI",sans-serif;
  color:#f4f4f5;background:#18181b;border-bottom:1px solid #3f3f46;
  box-shadow:0 1px 8px rgba(0,0,0,.3);max-height:70vh;overflow-y:auto}
.qz-bar a{color:#7dd3fc;text-decoration:underline}
.qz-bar a:hover{color:#bae6fd}
.qz-panel>summary{cursor:pointer;padding:.5rem .9rem;list-style:none;
  display:flex;gap:.5rem;align-items:center;font-weight:600}
.qz-panel>summary::-webkit-details-marker{display:none}
.qz-panel>summary::after{content:"▾";margin-left:auto;opacity:.7}
.qz-panel[open]>summary::after{content:"▴"}
.qz-mark{background:#f4f4f5;color:#18181b;border-radius:999px;
  padding:.05rem .5rem;font-size:12px;font-weight:700;letter-spacing:.04em;
  text-transform:uppercase}
.qz-body{padding:0 .9rem .8rem}
.qz-row{margin:0 0 .6rem}
.qz-what{margin:.6rem 0 .2rem;font-size:12px;font-weight:700;opacity:.75;
  letter-spacing:.06em;text-transform:uppercase}
.qz-list{margin:0;padding-left:1.2rem}
.qz-list li{margin:.15rem 0}
.qz-peek{opacity:.6}
.qz-note{margin:.7rem 0 0;opacity:.7;font-size:12px}
/* The page keeps its own top: the bar is fixed, so it covers rather than
   pushes, and a preview that shifted its content down would not be a preview
   of what a reader sees. Padding is added to the document instead of a margin
   on the body, which a page may already set. */
html{scroll-padding-top:3rem}
`

// injectBar puts the stylesheet in the head and the panel inside the body.
//
// Two insertions rather than one blob, because a <link rel="stylesheet"> in
// the body is something browsers accept and the specification does not. This
// is a document somebody may run through a validator, and producing markup
// that only works because parsers are forgiving is not what to leave in
// somebody else's page.
//
// Case-insensitive, because a layout is the operator's own file and <BODY> is
// valid. Nothing is replaced and nothing is removed: the page is exactly what
// the renderer produced with two elements added, so a preview cannot differ
// from the published page because of the preview's own furniture.
func injectBar(page, bar string) string {
	const link = `<link rel="stylesheet" href="/preview.css">`
	out := insertAfterTag(page, "<head", link)
	if out == page {
		// No head. The browser makes one, and a stylesheet at the top of the
		// body is what would end up in it — worth doing rather than dropping
		// the styles, and a fragment is not a document to validate anyway.
		bar = link + bar
	}
	if withBar := insertAfterTag(out, "<body", bar); withBar != out {
		return withBar
	}
	return bar + out
}

// insertAfterTag puts s just after the opening tag named by open, or returns
// the input unchanged when there is none.
func insertAfterTag(doc, open, s string) string {
	i := strings.Index(strings.ToLower(doc), open)
	if i < 0 {
		return doc
	}
	end := strings.IndexByte(doc[i:], '>')
	if end < 0 {
		return doc
	}
	at := i + end + 1
	return doc[:at] + s + doc[at:]
}
