package tmpl

import (
	"strings"
	"testing"
)

func render(t *testing.T, src string, data map[string]any) string {
	t.Helper()
	out, err := Render(src, data)
	if err != nil {
		t.Fatalf("render %q: %v", src, err)
	}
	return out
}

// The capability competitors get from embedding a scripting language.
func TestFiltersDoTheThingAScriptingLanguageIsUsuallyAddedFor(t *testing.T) {
	data := map[string]any{"page": map[string]any{
		"title":     "the quarterly results are in",
		"summary":   "A long summary that keeps going well past any sensible headline length for a card",
		"published": "2026-03-04",
		"author":    "",
		"tags":      []any{"finance", "results", "q1"},
		"score":     4.567,
	}}
	for _, tc := range []struct{ src, want string }{
		{`{{ page.title | upper }}`, "THE QUARTERLY RESULTS ARE IN"},
		{`{{ page.title | title }}`, "The Quarterly Results Are In"},
		{`{{ page.title | slug }}`, "the-quarterly-results-are-in"},
		{`{{ page.published | date:"2 Jan 2006" }}`, "4 Mar 2026"},
		{`{{ page.published | date:iso }}`, "2026-03-04"},
		{`{{ page.author | default:"Anonymous" }}`, "Anonymous"},
		{`{{ page.tags | join:", " }}`, "finance, results, q1"},
		{`{{ page.tags | count }}`, "3"},
		{`{{ page.tags | sort | first }}`, "finance"},
		{`{{ page.tags | take:2 | join:"/" }}`, "finance/results"},
		{`{{ page.score | round:1 }}`, "4.6"},
	} {
		if got := render(t, tc.src, data); got != tc.want {
			t.Errorf("%s\n  got  %q\n  want %q", tc.src, got, tc.want)
		}
	}
	if got := render(t, `{{ page.summary | truncate:30 }}`, data); len(got) > 34 ||
		!strings.HasSuffix(got, "…") {
		t.Errorf("truncate gave %q", got)
	}
}

// -- the property that makes this not a language ------------------------------

// Escaping happens after the filters, on the result, in the context it lands
// in. A filter cannot opt out of it — which is exactly what `| safe` does in
// every engine that has one, and is how a pipeline becomes an XSS.
func TestAFilterCannotEscapeEscaping(t *testing.T) {
	data := map[string]any{"page": map[string]any{
		"title": `<script>alert(1)</script>`,
		"tags":  []any{"<b>", "<i>"},
	}}
	for _, src := range []string{
		`{{ page.title }}`,
		`{{ page.title | upper }}`,
		`{{ page.title | trim | default:"x" }}`,
		`{{ page.tags | join:"," }}`,
		`{{ page.title | replace:a,b }}`,
	} {
		out := render(t, src, data)
		if strings.Contains(out, "<script>") || strings.Contains(out, "<b>") {
			t.Errorf("%s produced unescaped markup: %s", src, out)
		}
	}
}

// A filter argument is a literal and never a path. That is the line: an
// argument naming another value would need evaluation, evaluation needs an
// evaluator, and an evaluator is what every template-injection advisory is
// about.
func TestAFilterArgumentIsNotEvaluated(t *testing.T) {
	data := map[string]any{
		"page":   map[string]any{"title": ""},
		"secret": "hunter2",
	}
	out := render(t, `{{ page.title | default:secret }}`, data)
	if strings.Contains(out, "hunter2") {
		t.Fatal("a filter argument was resolved as a path, which makes the " +
			"argument position an expression and the language a language")
	}
	if out != "secret" {
		t.Errorf("got %q, want the literal text", out)
	}
}

// There is no way to add one from a template, so an unknown name is an error
// rather than a silent no-op — a silent one would let a typo remove an
// intended transformation without saying so.
func TestAnUnknownFilterIsAnError(t *testing.T) {
	_, err := Render(`{{ page.title | exec }}`,
		map[string]any{"page": map[string]any{"title": "x"}})
	if err == nil {
		t.Fatal("an unknown filter rendered")
	}
	if !strings.Contains(err.Error(), "no filter called") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// A pipeline is bounded. Each filter is cheap, but repetition is work an
// author can ask for by typing.
func TestAPipelineIsBounded(t *testing.T) {
	long := "{{ page.title" + strings.Repeat(" | upper", 20) + " }}"
	if _, err := Render(long, map[string]any{
		"page": map[string]any{"title": "x"}}); err == nil {
		t.Fatal("a twenty-filter pipeline was accepted")
	}
}

// A separator containing a pipe must not split the expression it is in.
func TestASeparatorMayContainAPipe(t *testing.T) {
	got := render(t, `{{ page.tags | join:"|" }}`, map[string]any{
		"page": map[string]any{"tags": []any{"a", "b"}}})
	if got != "a|b" {
		t.Errorf("got %q, want a|b", got)
	}
}

// -- filters must not crash on the wrong type ---------------------------------

// Content is author-supplied and a field holds whatever the author typed, so
// every filter has to survive the wrong kind of value without taking the site
// down.
func TestFiltersSurviveTheWrongType(t *testing.T) {
	values := []any{nil, "", "text", 3.5, true, []any{1, "two"},
		map[string]any{"a": 1}}
	for _, f := range Filters() {
		for _, v := range values {
			for _, arg := range []string{"", "2", "x,y", "bad"} {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("%s panicked on %#v with arg %q: %v",
								f.Name, v, arg, r)
						}
					}()
					f.Apply(v, arg) // an error is fine; a panic is not
				}()
			}
		}
	}
}

func TestEveryFilterIsDocumented(t *testing.T) {
	for _, f := range Filters() {
		if len(f.Summary) < 4 {
			t.Errorf("%s has no summary", f.Name)
		}
		if f.Apply == nil {
			t.Errorf("%s does nothing", f.Name)
		}
	}
	if len(Filters()) < 10 {
		t.Errorf("only %d filters; the point is to cover what people would "+
			"otherwise need a scripting language for", len(Filters()))
	}
}

// A filter must not hand back a view onto the page data it was given.
// Templates render repeatedly against data the server holds, so a filter that
// returned a slice sharing its backing array would let a later one reorder the
// content itself for every subsequent request.
func TestAListFilterDoesNotAliasThePageData(t *testing.T) {
	original := []any{"c", "a", "b"}
	data := map[string]any{"page": map[string]any{"tags": original}}

	render(t, `{{ page.tags | sort | join:"," }}`, data)
	render(t, `{{ page.tags | take:2 | sort | join:"," }}`, data)

	if got := render(t, `{{ page.tags | join:"," }}`, data); got != "c,a,b" {
		t.Errorf("rendering reordered the page's own data: %q", got)
	}
}
