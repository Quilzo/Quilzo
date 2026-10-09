// SPDX-FileCopyrightText: 2026 Rashik Adhikari
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

	// A pill in the corner that opens a panel, rather than a panel across
	// the top that has to be closed. The panel was a <details open> fixed
	// over the page, so every preview began with the top two hundred pixels
	// of the page — its header, its navigation, its headline — hidden under
	// the furniture that was meant to help somebody look at it.
	//
	// The popover attribute gives the rest with no script, which this
	// response's policy forbids: the panel sits in the top layer rather than
	// in the page's stacking order, closes on Escape or a click elsewhere,
	// and the pill is a real button that keyboards and screen readers treat
	// as one. A browser without popover support shows the panel inline at
	// the foot of the page, which is still usable and still covers nothing.
	b.WriteString(`<div class="qz-bar">`)
	fmt.Fprintf(&b,
		`<button type="button" class="qz-pill" popovertarget="qz-preview-panel" `+
			`aria-label="Preview of %s: open the editing panel">`+
			`<span class="qz-mark">Preview</span><span class="qz-name">%s</span></button>`,
		esc(page), esc(page))
	b.WriteString(`<div id="qz-preview-panel" class="qz-panel" popover>`)
	fmt.Fprintf(&b, `<p class="qz-head"><span class="qz-mark">Preview</span> `+
		`<span class="qz-name">%s</span>`+
		`<button type="button" class="qz-close" popovertarget="qz-preview-panel" `+
		`popovertargetaction="hide" aria-label="Close the panel">Close</button></p>`,
		esc(page))
	b.WriteString(`<div class="qz-body">`)

	// The page as a whole, first and always.
	fmt.Fprintf(&b,
		`<p class="qz-row"><a href="/page/%s">Edit this page</a> · `+
			`<a href="/sections?page=%s">Arrange sections</a> · `+
			`<a href="/">All pages</a> · `+
			`<a href="/preview/%s?plain=1">Hide this panel</a></p>`,
		q(page), q(page), q(page))

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
	b.WriteString(`</div></div></div>`)
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
/* The page's own styles must not reach in. Everything inside the furniture is
   reverted to the browser's defaults first, then styled here; a page that
   sets a {color:white} or button {display:none} would otherwise decide what
   the panel looks like, or whether it can be opened at all. */
.qz-bar,.qz-bar *{all:revert;box-sizing:border-box}
.qz-bar{--qz-bg:#ffffff;--qz-fg:#1f1f1f;--qz-muted:#444746;--qz-line:#c4c7c5;
  --qz-accent:#0842a0;--qz-on-accent:#ffffff;--qz-link:#0842a0;
  font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  color:var(--qz-fg)}
/* Room at the foot of the page for the pill, so the page's last lines can be
   scrolled clear of it rather than read underneath it. */
@supports selector(:popover-open){.qz-bar{display:block;height:64px}}
@media (prefers-color-scheme:dark){.qz-bar{--qz-bg:#1e1f20;--qz-fg:#e3e3e3;
  --qz-muted:#c4c7c5;--qz-line:#444746;--qz-accent:#a8c7fa;--qz-on-accent:#062e6f;
  --qz-link:#a8c7fa}}
.qz-bar .qz-pill{position:fixed;z-index:2147483647;
  inset-inline-start:max(12px,env(safe-area-inset-left));
  inset-block-end:max(12px,env(safe-area-inset-bottom));
  display:inline-flex;align-items:center;gap:.5em;max-width:min(60vw,22rem);
  padding:.4em .8em .4em .45em;border:1px solid var(--qz-line);border-radius:999px;
  background:var(--qz-bg);color:var(--qz-fg);font:inherit;font-weight:600;
  box-shadow:0 2px 10px rgba(0,0,0,.18);cursor:pointer;opacity:.92}
.qz-bar .qz-pill:hover,.qz-bar .qz-pill:focus-visible{opacity:1}
.qz-bar :focus-visible{outline:2px solid var(--qz-accent);outline-offset:2px}
.qz-bar .qz-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  font-weight:600}
.qz-bar .qz-mark{background:var(--qz-accent);color:var(--qz-on-accent);
  border-radius:999px;padding:.1em .55em;font-size:11px;font-weight:700;
  letter-spacing:.06em;text-transform:uppercase;flex:none}
.qz-bar .qz-panel{margin:0;padding:0;border:1px solid var(--qz-line);
  border-radius:12px;background:var(--qz-bg);color:var(--qz-fg);
  box-shadow:0 8px 32px rgba(0,0,0,.28);
  width:min(26rem,calc(100vw - 24px));max-height:min(70vh,36rem);overflow:auto;
  inset:auto auto max(60px,calc(env(safe-area-inset-bottom) + 60px))
    max(12px,env(safe-area-inset-left))}
.qz-bar .qz-panel::backdrop{background:transparent}
.qz-bar .qz-head{display:flex;align-items:center;gap:.5em;margin:0;
  padding:.7em .9em;border-bottom:1px solid var(--qz-line);position:sticky;
  top:0;background:var(--qz-bg)}
.qz-bar .qz-close{margin-inline-start:auto;font:inherit;font-size:13px;
  padding:.25em .7em;border:1px solid var(--qz-line);border-radius:6px;
  background:transparent;color:var(--qz-fg);cursor:pointer}
.qz-bar .qz-body{padding:.6em .9em .9em}
.qz-bar a{color:var(--qz-link);text-decoration:underline;
  text-underline-offset:2px}
.qz-bar .qz-row{margin:0 0 .5em}
.qz-bar .qz-what{margin:.8em 0 .25em;font-size:11px;font-weight:700;
  color:var(--qz-muted);letter-spacing:.07em;text-transform:uppercase}
.qz-bar .qz-list{margin:0;padding-inline-start:1.2em}
.qz-bar .qz-list li{margin:.2em 0}
.qz-bar .qz-peek{color:var(--qz-muted)}
.qz-bar .qz-note{margin:.8em 0 0;color:var(--qz-muted);font-size:12px}
/* Without popover support the panel is an ordinary block at the foot of the
   page: nothing covered, everything reachable. */
@supports not selector(:popover-open){
  .qz-bar .qz-pill,.qz-bar .qz-close{display:none}
  .qz-bar .qz-panel{position:static;display:block;width:auto;max-height:none;
    margin:2rem 12px;box-shadow:none}
}
@media print{.qz-bar{display:none}}
@media (prefers-reduced-motion:no-preference){
  .qz-bar .qz-panel{transition:opacity .12s,display .12s allow-discrete,
    overlay .12s allow-discrete;opacity:0}
  .qz-bar .qz-panel:popover-open{opacity:1}
  @starting-style{.qz-bar .qz-panel:popover-open{opacity:0}}
}
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
