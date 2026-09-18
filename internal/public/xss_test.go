// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/search"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// What a reader types must never become markup.
//
// CodeQL reports the response writes in this package as reflected cross-site
// scripting. It sees a request parameter reaching a response body and cannot
// model the template engine in between, which is a fair thing for a scanner
// not to know and a poor reason to believe the code is safe.
//
// So this tries the attack instead. Each case is a payload and the property
// that has to hold in the context it lands in — because the contexts differ,
// and a check that only looked for the string "onerror" would fail on
// "&lt;img onerror=…&gt;", which is inert text and exactly what escaping
// should produce.
//
// If any of these fails, the alerts were right.
func TestWhatSomebodyTypesCannotBecomeMarkup(t *testing.T) {
	// Text: angle brackets must be escaped, so nothing can open an element.
	t.Run("in text", func(t *testing.T) {
		for _, payload := range []string{
			`<script>alert(1)</script>`,
			`<img src=x onerror=alert(1)>`,
			`<svg/onload=alert(1)>`,
			`</title><script>alert(1)</script>`,
		} {
			out := renderWith(t, `<p>{{ page.q }}</p>`, payload)
			if strings.Contains(out, payload) {
				t.Errorf("%q reached the page verbatim:\n  %s", payload, out)
			}
			if strings.Contains(out, "<script") || strings.Contains(out, "<img") ||
				strings.Contains(out, "<svg") {
				t.Errorf("%q opened an element:\n  %s", payload, out)
			}
			if !strings.Contains(out, "&lt;") {
				t.Errorf("%q was not escaped:\n  %s", payload, out)
			}
		}
	})

	// Attribute values: the quote must be escaped, or the payload closes the
	// attribute and writes its own.
	t.Run("in an attribute", func(t *testing.T) {
		for _, payload := range []string{
			`" onmouseover="alert(1)`,
			`x" autofocus onfocus="alert(1)`,
		} {
			out := renderWith(t, `<a class="{{ page.q }}">x</a>`, payload)
			if strings.Contains(out, `" onmouseover=`) ||
				strings.Contains(out, `" autofocus`) {
				t.Errorf("%q broke out of the attribute:\n  %s", payload, out)
			}
			if !strings.Contains(out, "&#34;") {
				t.Errorf("%q left a raw quote in an attribute:\n  %s", payload, out)
			}
		}
	})

	// A URL attribute is its own context: escaping the quote is not enough,
	// because javascript: needs no quote to execute.
	t.Run("in a URL", func(t *testing.T) {
		out := renderWith(t, `<a href="{{ page.q }}">x</a>`, `javascript:alert(1)`)
		if strings.Contains(out, "javascript:") {
			t.Errorf("a javascript: URL survived into an href:\n  %s", out)
		}
	})
}

func renderWith(t *testing.T, layout, value string) string {
	t.Helper()
	out, err := tmpl.Render(layout,
		map[string]any{"page": map[string]any{"q": value}})
	if err != nil {
		t.Fatalf("rendering %q: %v", value, err)
	}
	return out
}

// The same claim, through the whole handler rather than the engine alone.
//
// The engine escaping is one thing; what CodeQL actually reports is about the
// bytes that leave the server, and those go through a layout, a head
// injection and a response writer before anybody sees them.
func TestTheSearchPageEscapesWhatWasTyped(t *testing.T) {
	st := searchSite(t)

	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, httptest.NewRequest("GET",
		"/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", nil))

	if rec.Code >= 500 {
		t.Fatalf("the search page failed on a hostile query (%d)", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert") {
		t.Errorf("a typed script tag reached the response:\n%s",
			firstLinesOf(body, 8))
	}
}

func firstLinesOf(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// The same claim again, on the compressed representation.
//
// CodeQL moved its report when internal/compress went in: the sink it names
// is now the middleware's own Write, because a query parameter reaches the
// template, the template reaches the handler, and the handler reaches the
// compressor. A compressor cannot escape anything and escaping is not its job
// — but "a pass-through cannot change the bytes" is a claim, and this is the
// test of it.
//
// Decompressed and then checked, because a scanner reading the source cannot
// tell a gzip stream from an escaped one, and neither can a reviewer.
func TestTheCompressedResponseEscapesWhatWasTyped(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A long body, so the response crosses the compressor's floor and this is
	// really the compressed path rather than the pass-through.
	pages := map[string]any{"search": map[string]any{
		"title": "Search",
		"body":  strings.Repeat("a paragraph of ordinary prose. ", 80),
	}}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	// The query reaches the page through search.query, which is the flow
	// CodeQL traces to the compressor's Write.
	st := New(s, render.OneLayout(
		`<!doctype html><html lang="en"><head><title>{{ page.title }}</title>`+
			`</head><body><input name="q" value="{{ search.query }}">`+
			`<p>{{ search.query }}</p><p>{{ page.body }}</p></body></html>`))
	live, _, perr := st.pages()
	if perr != nil {
		t.Fatal(perr)
	}
	st.Search = search.Build(s.GetRef(site.RefLive), live)

	payload := `<script>alert(1)</script>`
	req := httptest.NewRequest("GET", "/search?q="+url.QueryEscape(payload), nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("the page failed on a hostile query (%d): %s",
			rec.Code, firstLinesOf(rec.Body.String(), 3))
	}
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("this did not take the compressed path (%q), so it proved "+
			"nothing", got)
	}

	zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("the body was labelled gzip and is not: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("truncated gzip stream: %v", err)
	}
	body := string(out)

	if strings.Contains(body, payload) {
		t.Errorf("the payload reached the decompressed response verbatim:\n%s",
			firstLinesOf(body, 8))
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the payload is not in the page escaped either, so this "+
			"tested the wrong thing:\n%s", firstLinesOf(body, 8))
	}
}
