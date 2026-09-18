// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package tmpl

import (
	"strings"
	"testing"
)

// The shared escaper must do exactly what the per-call one did.
//
// The change that made it shared was a performance change, and a performance
// change that alters escaping is a cross-site scripting bug wearing a
// benchmark. So the old expression is written out here and compared against.
func TestTheSharedEscaperMatchesTheOneItReplaced(t *testing.T) {
	was := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	for _, in := range []string{
		"", "plain text",
		"<script>alert(1)</script>",
		"a & b", "&amp;", "&&&", "<<>>",
		`"quoted" and 'single'`,
		"<img src=x onerror=alert(1)>",
		"héllo — em dash & ünicode",
		strings.Repeat("<&>", 50),
	} {
		if got, want := escapeTextContext.Replace(in), was.Replace(in); got != want {
			t.Errorf("%q escaped to %q, was %q", in, got, want)
		}
	}
}

// Quotes are deliberately not escaped in text context: they are not special
// there, and escaping them renders an apostrophe in a sentence as &#39;.
// Stated as a test so a later "tighten the escaping" change has to face it.
func TestQuotesAreLeftAloneInTextContext(t *testing.T) {
	const in = `she said "no" and didn't move`
	if got := escapeTextContext.Replace(in); got != in {
		t.Errorf("text context escaped quotes: %q", got)
	}
}

// One shared Replacer is read from every render at once. strings.Replacer is
// documented safe for concurrent use; this is the test that would catch a
// future replacement that is not.
func TestTheSharedEscaperIsSafeUnderConcurrency(t *testing.T) {
	const in = "<a> & <b>"
	const want = "&lt;a&gt; &amp; &lt;b&gt;"
	done := make(chan string, 64)
	for i := 0; i < 64; i++ {
		go func() { done <- escapeTextContext.Replace(in) }()
	}
	for i := 0; i < 64; i++ {
		if got := <-done; got != want {
			t.Fatalf("got %q", got)
		}
	}
}

// What the render loop used to do for every interpolated value on every page:
// compile the same three-pair trie again. Kept as a benchmark because the
// number is the argument.
func BenchmarkEscapePerCallReplacer(b *testing.B) {
	const text = "A sentence with an & in it and a <tag> or two, plus prose."
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sink = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").
			Replace(text)
	}
}

func BenchmarkEscapeSharedReplacer(b *testing.B) {
	const text = "A sentence with an & in it and a <tag> or two, plus prose."
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sink = escapeTextContext.Replace(text)
	}
}

var sink string
