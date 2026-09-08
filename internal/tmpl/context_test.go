// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package tmpl

import (
	"strings"
	"testing"
)

// A value cannot close the attribute it sits in.
//
// This is the failure the context tracker replaced a 256-byte lookback to fix.
// The old code decided where a value landed by scanning back that far for a
// `<`; pad the output past it and an attribute looked like text, where quotes
// are not escaped because in text they are not special. The value then closed
// the attribute and opened an event handler.
//
// Both fields here are ordinary content. No template author has to make a
// mistake for this to happen, which is what made it worth fixing rather than
// documenting — the shipped demo theme has exactly this shape at
// internal/demo/assets/page.html, an <img> whose src and alt are both record
// fields.
func TestAValueCannotBreakOutOfAnAttribute(t *testing.T) {
	for _, pad := range []int{0, 100, 300, 5000} {
		out, err := Render(`<img src="/m/{{ p }}" alt="{{ x }}">`, map[string]any{
			"p": strings.Repeat("a", pad),
			"x": `" onerror="alert(1)`,
		})
		if err != nil {
			t.Fatalf("pad %d: %v", pad, err)
		}
		if strings.Contains(out, `onerror="`) || strings.Contains(out, `alt="" `) {
			t.Errorf("pad %d: the value escaped its attribute:\n  %s", pad, out)
		}
		if !strings.Contains(out, "&#34;") {
			t.Errorf("pad %d: the quote was not escaped:\n  %s", pad, out)
		}
	}
}

// Escaping cannot make a value safe inside <script> or <style>, so it is
// refused instead.
//
// HTML entities are not decoded in either element: &#34; arrives at the
// JavaScript or CSS parser as six characters, not as a quote. So the escaping
// is inert and the quote that ends the string is still a quote. Every engine
// that pretends otherwise has a CVE about it.
//
// Refusing costs this program nothing, because no template it ships puts a
// value in either place.
func TestAValueCannotGoInsideScriptOrStyle(t *testing.T) {
	for _, tpl := range []string{
		`<script>var a = "{{ x }}";</script>`,
		`<script type="module">let a = {{ x }};</script>`,
		`<style>body { color: {{ x }} }</style>`,
		`<SCRIPT>var a = "{{ x }}";</SCRIPT>`,
	} {
		if _, err := Render(tpl, map[string]any{"x": "1"}); err == nil {
			t.Errorf("rendered a value inside a raw text element: %s", tpl)
		}
	}
	// And the refusal ends with the element, rather than poisoning the
	// rest of the document.
	out, err := Render(`<script>var a=1;</script><p>{{ x }}</p>`, map[string]any{"x": "ok"})
	if err != nil {
		t.Fatalf("a value after </script> should render: %v", err)
	}
	if !strings.Contains(out, "<p>ok</p>") {
		t.Errorf("after the script closed, this should be text again: %s", out)
	}
}

// An unquoted attribute value cannot start a second attribute.
//
// Nothing needs a quote to end an unquoted value — a space does. So escaping
// the quotes is not enough here, and `class={{ x }}` with "a onmouseover=b"
// would otherwise be two attributes, the second an event handler.
func TestAnUnquotedValueCannotStartAnotherAttribute(t *testing.T) {
	out, err := Render(`<div class={{ x }}>y</div>`, map[string]any{
		"x": `a onmouseover=alert(1)`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, " onmouseover=") {
		t.Errorf("the value started a second attribute:\n  %s", out)
	}
}

// A comment is not markup, and an apostrophe in one is an apostrophe.
//
// This is a regression test for a bug introduced by the fix above rather than
// by the code it replaced. Tracking attribute quotes means an apostrophe looks
// like an opening quote — and `<!-- the record's name -->` in a shipped
// starter template then swallowed the rest of the document, so every value
// after it was escaped as though it sat inside an attribute.
//
// Nothing was insecure about that; it changed rendered output, which is how it
// was caught: rendering every shipped template before and after the change and
// diffing the results.
func TestACommentIsNotMarkup(t *testing.T) {
	out, err := Render(`<!-- the record's name --><p>{{ x }}</p>`,
		map[string]any{"x": `it's fine`})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `<p>it's fine</p>`) {
		t.Errorf("text after a comment should be text:\n  %s", out)
	}
}

// A quoted angle bracket does not end the tag.
//
// `<a title="a > b">` contains a `>` that belongs to the attribute, not to the
// tag. Scanning back for the last `>` finds it and concludes the tag closed.
func TestAQuotedAngleBracketDoesNotEndTheTag(t *testing.T) {
	out, err := Render(`<a title="a > b" href="{{ x }}">y</a>`,
		map[string]any{"x": "javascript:alert(1)"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "#unsafe-url") {
		t.Errorf("href was not read as a URL context, so the scheme was not "+
			"checked:\n  %s", out)
	}
}

// Text context still leaves quotes alone.
//
// The fix must not become "escape everything everywhere". Quotes are not
// special in text, and escaping them there would change the bytes of every
// page this program has ever published — which for a project whose published
// sites are addressed by hash is not a cosmetic difference.
func TestTextContextStillLeavesQuotesAlone(t *testing.T) {
	out, err := Render(`<p>{{ x }}</p>`, map[string]any{"x": `it's "fine" & <ok>`})
	if err != nil {
		t.Fatal(err)
	}
	const want = `<p>it's "fine" &amp; &lt;ok&gt;</p>`
	if out != want {
		t.Errorf("text escaping changed:\n  got  %s\n  want %s", out, want)
	}
}
