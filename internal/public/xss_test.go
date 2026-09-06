package public

import (
	"net/http/httptest"
	"strings"
	"testing"

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
