// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package tmpl

import (
	"strings"
	"testing"
)

// Markup in the source never becomes markup in the output.
//
// This is the property the whole design rests on, and it holds because the
// text is escaped before any marker is looked at: after that there is no `<`
// left, so nothing the scanner does can produce a tag that was not written in
// prose.go as a literal.
//
// Every Markdown implementation in wide use allows inline HTML. This one
// cannot, and that is not a limitation to be lifted later — the input is
// content, and content is written by whoever can write content.
func TestProseNeverPassesMarkupThrough(t *testing.T) {
	for _, src := range []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`<b>bold</b>`,
		`<a href="javascript:alert(1)">x</a>`,
		`<!-- comment -->`,
		`<svg><use href="#x"/></svg>`,
		`</p><script>alert(1)</script><p>`,
		`<style>body{display:none}</style>`,
		`<iframe src="https://evil.test"></iframe>`,
		"**<script>alert(1)</script>**",
		"- <script>alert(1)</script>",
		"## <script>alert(1)</script>",
		"> <script>alert(1)</script>",
		"[<script>alert(1)</script>](https://e.test)",
		"`<script>alert(1)</script>`",
	} {
		if tag, ok := tagOutsideTheList(string(Prose(src))); !ok {
			t.Errorf("Prose(%q) emitted <%s>, which is not one of the tags "+
				"this transform writes:\n  %s", src, tag, Prose(src))
		}
	}
}

// A link's scheme is checked the same way a template attribute's is.
//
// Sharing safeSchemes rather than repeating the list, so a scheme refused in
// one place cannot be permitted in the other — a link that is safe in a
// template and not in prose would be the same bug twice with one of them
// fixed.
func TestProseRefusesASchemeThatCanExecute(t *testing.T) {
	for _, src := range []string{
		"[x](javascript:alert(1))",
		"[x](JavaScript:alert(1))",
		"[x](data:text/html,<script>alert(1)</script>)",
		"[x](vbscript:msgbox)",
		"[x](java\nscript:alert(1))",
	} {
		got := string(Prose(src))
		if strings.Contains(got, "javascript") || strings.Contains(got, "vbscript") ||
			strings.Contains(got, "data:") {
			t.Errorf("Prose(%q) kept an executable scheme:\n  %s", src, got)
		}
		if !strings.Contains(got, "#unsafe-url") {
			t.Errorf("Prose(%q) did not refuse the URL:\n  %s", src, got)
		}
	}
	// And the ones that are fine still work, including an address with
	// brackets in it — taking the first ) would cut Wikipedia links in half.
	for _, src := range []string{
		"[x](https://e.test/a)",
		"[x](http://e.test/a)",
		"[x](mailto:a@e.test)",
		"[x](/relative/path)",
		"[m](https://e.test/wiki/Mercury_(planet))",
	} {
		if got := string(Prose(src)); strings.Contains(got, "#unsafe-url") {
			t.Errorf("Prose(%q) refused a usable address:\n  %s", src, got)
		}
	}
}

// What it does, on the shapes somebody actually types.
func TestProseRendersTheSubset(t *testing.T) {
	for src, want := range map[string]string{
		"plain":                "<p>plain</p>",
		"a **bold** word":      "<p>a <strong>bold</strong> word</p>",
		"an *italic* word":     "<p>an <em>italic</em> word</p>",
		"some `code` here":     "<p>some <code>code</code> here</p>",
		"one\n\ntwo":           "<p>one</p><p>two</p>",
		"- a\n- b":             "<ul><li>a</li><li>b</li></ul>",
		"1. a\n2. b":           "<ol><li>a</li><li>b</li></ol>",
		"## head":              "<h2>head</h2>",
		"### head":             "<h3>head</h3>",
		"> quoted":             "<blockquote><p>quoted</p></blockquote>",
		"[t](https://e.test/)": `<p><a href="https://e.test/">t</a></p>`,
		"wrapped\nover two":    "<p>wrapped over two</p>",
		"ampersand & less <":   "<p>ampersand &amp; less &lt;</p>",
	} {
		if got := string(Prose(src)); got != want {
			t.Errorf("Prose(%q)\n  got  %s\n  want %s", src, got, want)
		}
	}
}

// An unclosed marker is text, not an unclosed tag.
//
// The failure that would matter is a marker opening a tag and nothing closing
// it, which would swallow the rest of the page into a <strong>. A marker with
// no partner is simply left where it is.
func TestProseLeavesAnUnclosedMarkerAlone(t *testing.T) {
	for _, src := range []string{
		"unclosed **bold",
		"unclosed *em",
		"unclosed `code",
		"a lone * asterisk",
		"a lone ` backtick",
		"[unclosed](https://e.test",
		"[unclosed]",
		"***",
		"****",
		"`",
	} {
		got := string(Prose(src))
		if opens, closes := strings.Count(got, "<"), strings.Count(got, "</"); opens != closes*2 {
			t.Errorf("Prose(%q) is unbalanced (%d tags, %d closing):\n  %s",
				src, opens, closes, got)
		}
	}
}

// Nothing outside this package can make a Markup, and the renderer only writes
// one out where markup belongs.
//
// In an attribute it is escaped like any other string — a paragraph inside an
// alt text is a template mistake, and treating it as markup there would turn
// that mistake into an escaping bypass.
func TestMarkupIsWrittenOnlyWhereMarkupBelongs(t *testing.T) {
	data := map[string]any{"body": Prose("a **bold** word")}

	out, err := Render(`<div>{{ body }}</div>`, data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<strong>bold</strong>") {
		t.Errorf("markup was escaped in text context:\n  %s", out)
	}

	out, err = Render(`<img alt="{{ body }}">`, data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "<strong>") {
		t.Errorf("markup was written into an attribute unescaped:\n  %s", out)
	}
	if !strings.Contains(out, "&lt;strong&gt;") {
		t.Errorf("markup in an attribute should be escaped like any string:\n  %s", out)
	}
}

// The filter is opt-in, and is not a way to mark a string as safe.
//
// A template that does not ask for it gets what it always got, which is why
// this can be added without changing a single published page. And handing the
// filter HTML returns that HTML escaped, in a paragraph — it renders markup, it
// does not accept it.
func TestTheProseFilterIsOptInAndNotAnEscapeHatch(t *testing.T) {
	data := map[string]any{"body": "a **bold** <b>word</b>"}

	plain, err := Render(`<p>{{ body }}</p>`, data)
	if err != nil {
		t.Fatal(err)
	}
	if plain != `<p>a **bold** &lt;b&gt;word&lt;/b&gt;</p>` {
		t.Errorf("a field with no filter should be unchanged:\n  %s", plain)
	}

	filtered, err := Render(`<div>{{ body | prose }}</div>`, data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filtered, "<strong>bold</strong>") {
		t.Errorf("the filter did not render the markup:\n  %s", filtered)
	}
	if strings.Contains(filtered, "<b>word</b>") {
		t.Errorf("the filter passed source HTML through:\n  %s", filtered)
	}
}

// Nothing the transform produces contains a script, whatever it is given.
func FuzzProse(f *testing.F) {
	for _, s := range []string{
		"plain", "**b**", "*i*", "`c`", "[t](https://e.test)",
		"<script>alert(1)</script>", "- a\n- b", "## h", "> q",
		"[x](javascript:alert(1))", "***", "[[[", "]]]", "((()))",
		"1. a", "#### h", "\n\n\n", "*", "`", "[](", "![x](y)",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		got := string(Prose(src))
		if tag, ok := tagOutsideTheList(got); !ok {
			t.Fatalf("Prose(%q) emitted <%s>:\n  %s", src, tag, got)
		}
		// A scheme can only reach the output through an href, and every href
		// this writes comes from escapeURL — so one that can execute means
		// the scheme check was bypassed rather than merely that the word
		// appears, which it may legitimately as escaped text.
		for _, a := range hrefsOf(got) {
			low := strings.ToLower(a)
			if strings.HasPrefix(low, "javascript:") ||
				strings.HasPrefix(low, "vbscript:") ||
				strings.HasPrefix(low, "data:") {
				t.Fatalf("Prose(%q) linked to %q:\n  %s", src, a, got)
			}
		}
	})
}

// tagOutsideTheList reports the first tag in s that Prose does not write.
//
// The closed allowlist is the property, and checking it directly is the only
// honest way: looking for "<script" or "onerror" as substrings cannot tell a
// tag from the same characters escaped as text, and Prose escaping
// `<img src=x onerror=…>` into a paragraph is the transform working rather
// than failing.
func tagOutsideTheList(s string) (string, bool) {
	allowed := map[string]bool{
		"p": true, "strong": true, "em": true, "code": true, "a": true,
		"ul": true, "ol": true, "li": true, "blockquote": true,
		"h2": true, "h3": true, "h4": true,
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		j := i + 1
		if j < len(s) && s[j] == '/' {
			j++
		}
		k := j
		for k < len(s) && ((s[k] >= 'a' && s[k] <= 'z') || (s[k] >= '0' && s[k] <= '9')) {
			k++
		}
		name := s[j:k]
		if !allowed[name] {
			return name, false
		}
	}
	return "", true
}

// hrefsOf collects the addresses Prose wrote into links.
func hrefsOf(s string) []string {
	var out []string
	for _, seg := range strings.Split(s, `<a href="`)[1:] {
		if end := strings.IndexByte(seg, '"'); end >= 0 {
			out = append(out, seg[:end])
		}
	}
	return out
}
