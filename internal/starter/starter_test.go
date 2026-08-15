package starter

import (
	"sort"
	"strings"
	"testing"

	"github.com/rsh1k/scrivet/internal/a11y"
	"github.com/rsh1k/scrivet/internal/tmpl"
)

// A starter template is the first HTML most people will publish with this tool.
// Shipping one that fails the gate the tool enforces would be the most
// embarrassing bug available: the product blocking its own examples.
func TestEveryStarterTemplatePassesTheAccessibilityGate(t *testing.T) {
	for _, st := range All() {
		t.Run(st.Name, func(t *testing.T) {
			html := render(t, st)
			r := a11y.Check(st.Name, html)
			if !r.Blocks() {
				return
			}
			for _, f := range r.Findings {
				if f.Severity == a11y.Blocking {
					t.Errorf("%s: %s (%s) — %s", st.Name, f.Rule, f.Criterion, f.Detail)
				}
			}
			t.Fatalf("the %s starter cannot be published by the tool that ships it",
				st.Name)
		})
	}
}

func render(t *testing.T, st Template) string {
	t.Helper()
	src, err := st.HTML()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmpl.Parse(src); err != nil {
		t.Fatalf("%s does not parse: %v", st.Name, err)
	}
	// The sample is the page body; the renderer namespaces it under "page",
	// which is what every template reads.
	out, err := tmpl.Render(src, map[string]any{"page": st.Sample})
	if err != nil {
		t.Fatalf("%s does not render with its own sample content: %v", st.Name, err)
	}
	return out
}

// The sample is the fixture the tests render, so it cannot drift from the
// template without something failing. This is the check that keeps that true:
// every field the template reads must appear in the sample, or the rendered
// example has holes in it and nobody notices until a user copies it.
func TestSampleContentFillsEveryDeclaredField(t *testing.T) {
	for _, st := range All() {
		src, err := st.HTML()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range st.Fields {
			if !strings.Contains(src, "page."+f) {
				t.Errorf("%s declares field %q that the template never reads",
					st.Name, f)
			}
		}
		out := render(t, st)
		// An unfilled top-level field renders as nothing, so a template whose
		// output is much shorter than its source has holes.
		if len(out) < 400 {
			t.Errorf("%s rendered only %d bytes; the sample does not fill it",
				st.Name, len(out))
		}
	}
}

// Not one of these may reach a third-party origin. A published page that fetches
// a stylesheet or a font from someone else's server has handed that server the
// ability to change what the page says, and the CSP cannot help because the page
// asked for it.
func TestNoStarterReachesAnExternalOrigin(t *testing.T) {
	for _, st := range All() {
		src, _ := st.HTML()
		for _, bad := range []string{
			"http://", "https://", "//fonts.", "cdn.", "@import url(",
		} {
			if strings.Contains(src, bad) {
				t.Errorf("%s contains %q — a starter must be self-contained",
					st.Name, bad)
			}
		}
	}
	if strings.Contains(CSS(), "@import") || strings.Contains(CSS(), "https://") {
		t.Error("the shared stylesheet reaches outside itself")
	}
}

// The template language has no way to execute anything, and `raw` is the one
// construct that emits without escaping. A starter using it teaches the habit
// on the first page somebody writes.
func TestNoStarterDisablesEscaping(t *testing.T) {
	for _, st := range All() {
		src, _ := st.HTML()
		if sites := tmpl.RawSites(src); len(sites) > 0 {
			t.Errorf("%s uses raw at %v; a starting point should not teach that",
				st.Name, sites)
		}
	}
}

// Rendered output must survive hostile content, because content is the thing
// users supply. This is the same set of payloads the template engine is tested
// against, run through the actual starters rather than a fixture.
func TestStartersEscapeHostileContent(t *testing.T) {
	payloads := []string{
		`<script>alert(1)</script>`,
		`" onmouseover="alert(1)`,
		`javascript:alert(1)`,
		`</title><script>alert(1)</script>`,
	}
	for _, st := range All() {
		src, _ := st.HTML()
		if _, err := tmpl.Parse(src); err != nil {
			t.Fatal(err)
		}
		for _, p := range payloads {
			content := map[string]any{}
			for k, v := range st.Sample {
				content[k] = v
			}
			// Poison every string field the template might read.
			for _, f := range st.Fields {
				if _, isString := content[f].(string); isString {
					content[f] = p
				}
			}
			out, err := tmpl.Render(src, map[string]any{"page": content})
			if err != nil {
				continue // a refusal is a correct outcome too
			}
			if strings.Contains(out, "<script>") {
				t.Errorf("%s emitted a script tag for payload %q", st.Name, p)
			}
			if strings.Contains(out, `href="javascript:`) ||
				strings.Contains(out, `src="javascript:`) {
				t.Errorf("%s emitted a javascript: URL for %q", st.Name, p)
			}
			// Look for the handler inside a tag, not anywhere in the document.
			// `" onmouseover="` sitting in a paragraph is literal text and does
			// nothing; the question is only whether a quote in an attribute
			// value closed the attribute. Grepping the whole output confuses
			// the payload appearing with the payload working.
			if attr := handlerInTag(out); attr != "" {
				t.Errorf("%s broke out of an attribute for %q: %s",
					st.Name, p, attr)
			}
		}
	}
}

// Every starter has to declare what it is for and what it needs. A template
// nobody can choose between is a template library of one.
func TestEveryStarterDescribesItself(t *testing.T) {
	if len(All()) < 4 {
		t.Fatalf("only %d starters", len(All()))
	}
	for _, st := range All() {
		if len(st.Summary) < 40 {
			t.Errorf("%s does not say what it is for", st.Name)
		}
		if len(st.Fields) < 5 {
			t.Errorf("%s declares only %d fields", st.Name, len(st.Fields))
		}
		if len(st.Sample) == 0 {
			t.Errorf("%s has no sample content", st.Name)
		}
	}
}

// The shared stylesheet must keep its reduced-motion escape hatch: the
// Expressive springs overshoot by design, and overshoot is what 2.3.3 is about.
func TestTheSharedStylesheetRespectsReducedMotionAndForcedColours(t *testing.T) {
	css := CSS()
	for _, want := range []string{
		"prefers-reduced-motion", "forced-colors", ":focus-visible",
		"prefers-color-scheme",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("the shared stylesheet has no %s handling", want)
		}
	}
	flat := strings.ReplaceAll(strings.ReplaceAll(css, " ", ""), "\n", "")
	for _, bad := range []string{"outline:none", "outline:0"} {
		if strings.Contains(flat, bad) {
			t.Errorf("the shared stylesheet contains %q", bad)
		}
	}
}

// handlerInTag returns the first event-handler *attribute* found in any tag.
//
// This has to model the parser rather than search the text, and the difference
// is the whole point of the test. `datetime="&#34; onmouseover=&#34;alert(1)"`
// contains the characters `onmouseover=` and is completely inert: the quotes
// are escaped, so the attribute value never closes and the browser sees one
// attribute called datetime. A grep cannot tell that apart from a real
// breakout, which means a grep would either pass a live handler or fail on a
// safe one. So this walks each tag the way a parser does — tracking whether it
// is inside a quoted value — and only reports names it reaches at the top
// level.
func handlerInTag(html string) string {
	for i := 0; i < len(html); i++ {
		if html[i] != '<' {
			continue
		}
		end := strings.IndexByte(html[i:], '>')
		if end < 0 {
			break
		}
		if name := handlerAttr(html[i+1 : i+end]); name != "" {
			return name + " in <" + html[i+1:i+end] + ">"
		}
		i += end
	}
	return ""
}

// handlers is the set this looks for. A prefix test on "on" was the first
// version and it reported `once=` and `only=` as event handlers — the
// HTML event handler attributes are a specified list, so matching the list is
// both simpler and correct.
var handlers = map[string]bool{
	"onclick": true, "onmouseover": true, "onmouseout": true, "onerror": true,
	"onload": true, "onfocus": true, "onblur": true, "oninput": true,
	"onchange": true, "onsubmit": true, "onkeydown": true, "onkeyup": true,
	"onanimationstart": true, "ontoggle": true, "onpointerover": true,
	"onbeforetoggle": true, "onscrollend": true, "oncontentvisibilityautostatechange": true,
}

// handlerAttr scans one tag's interior and returns an event-handler attribute
// name if one is present at the top level.
func handlerAttr(tag string) string {
	var name strings.Builder
	inValue, quote := false, byte(0)

	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case inValue:
			// Inside a quoted value nothing is an attribute. An escaped quote
			// arrives as `&#34;` and never reaches here as a bare `"`, which is
			// exactly why the escaping is what makes this safe.
			if c == quote {
				inValue = false
			}
		case c == '=':
			// The characters gathered since the last separator are the name.
			n := strings.ToLower(strings.TrimSpace(name.String()))
			name.Reset()
			if i+1 < len(tag) && (tag[i+1] == '"' || tag[i+1] == '\'') {
				inValue, quote = true, tag[i+1]
				i++
			}
			if handlers[n] {
				return n
			}
		case c == ' ' || c == '\t' || c == '\n':
			name.Reset()
		default:
			name.WriteByte(c)
		}
	}
	return ""
}

// A starter has to degrade rather than break. Pages arrive with fields missing
// — a draft half-written, a page created before the template changed, content
// migrated from somewhere else — and a structural element whose label comes
// from absent content must not render at all. An empty <a> is announced as
// just "link", which is a blocking failure the tool's own gate will refuse.
//
// This was found by running the real gate over a real store: a page left over
// from an unrelated demo had no `brand` field, and the header rendered an empty
// link on it.
func TestStartersDegradeWhenContentIsMissing(t *testing.T) {
	for _, st := range All() {
		src, _ := st.HTML()
		for _, content := range []map[string]any{
			{},                                    // nothing at all
			{"title": "Only a title"},             // the bare minimum
			{"title": "T", "body": "Some prose."}, // a page from another template
		} {
			out, err := tmpl.Render(src, map[string]any{"page": content})
			if err != nil {
				t.Errorf("%s failed to render sparse content: %v", st.Name, err)
				continue
			}
			r := a11y.Check(st.Name, out)
			for _, f := range r.Findings {
				if f.Severity != a11y.Blocking {
					continue
				}
				// An absent title is the page's problem, not the template's:
				// there is nothing a template can do about content that has
				// no name.
				if f.Rule == "empty-title" && content["title"] == nil {
					continue
				}
				t.Errorf("%s with content %v: %s (%s) — %s",
					st.Name, keysOf(content), f.Rule, f.Criterion, f.Detail)
			}
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Every stylesheet this project ships has to tell the browser which palette to
// use for the parts nobody styles — the inside of a select, checkboxes,
// scrollbars. Without it those are drawn light while the page is dark, and the
// result is invisible text that no contrast check over the DOM can catch,
// because the dropdown is not in the DOM.
func TestTheStarterStylesheetDeclaresAColourScheme(t *testing.T) {
	if !strings.Contains(CSS(), "color-scheme") {
		t.Error("the starter stylesheet does not declare color-scheme, so a " +
			"site built from it renders native controls with the wrong palette")
	}
}
