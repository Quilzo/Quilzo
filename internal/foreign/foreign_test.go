package foreign

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// The output of a conversion has to be a template this renderer accepts. This is
// the check that makes the feature worth having: a converter whose output does
// not parse has moved the work rather than done it.
func TestEveryConversionProducesATemplateThatParses(t *testing.T) {
	for name, src := range samples {
		t.Run(name, func(t *testing.T) {
			r := Adopt(src)
			if _, err := tmpl.Parse(r.Template); err != nil {
				t.Fatalf("%s converted to something that does not parse: %v\n\n%s",
					name, err, r.Template)
			}
		})
	}
}

// Nothing executable may survive a conversion. These are the payloads a real
// downloaded theme carries — an analytics snippet, a handler on a menu, a
// javascript: link — and every one of them is the vulnerability class this
// program is built to not have, arriving inside a file somebody trusted.
func TestNothingExecutableSurvivesAConversion(t *testing.T) {
	hostile := `<!doctype html>
<html lang="en"><head><title>{{ page.title }}</title>
<script src="https://cdn.example.com/analytics.js"></script>
<script>window.dataLayer=[];alert(1)</script>
</head>
<body>
<a href="javascript:alert(1)" onclick="track('nav')">Home</a>
<img src="x" onerror="alert(1)" alt="">
<div onmouseover="steal()">hover</div>
<iframe src="https://example.com/embed"></iframe>
<?php echo $secret; ?>
<% render_partial %>
</body></html>`

	r := Adopt(hostile)
	out := strings.ToLower(r.Template)
	for _, forbidden := range []string{
		"<script", "javascript:", "onclick", "onerror", "onmouseover",
		"<iframe", "<?php", "<%",
	} {
		if strings.Contains(out, forbidden) {
			t.Errorf("%q survived the conversion:\n%s", forbidden, r.Template)
		}
	}
	if len(r.Removed) == 0 {
		t.Error("nothing was reported as removed, so a conversion that stripped " +
			"half the file would look clean")
	}
	if _, err := tmpl.Parse(r.Template); err != nil {
		t.Fatalf("the sanitised output does not parse: %v", err)
	}
}

// An else is the construct every real template has and this language does not.
// Silently dropping it renders the wrong branch, so it has to be reported — and
// it has to be reported as unsupported rather than as a note, because that is
// what stops the layout being written.
func TestAnElseIsRefusedRatherThanDropped(t *testing.T) {
	for _, src := range []string{
		`{% if page.a %}A{% else %}B{% endif %}`,
		`{% if page.a %}A{% elsif page.b %}B{% endif %}`,
		`{{#if a}}A{{else}}B{{/if}}`,
	} {
		r := Adopt(src)
		if len(r.Unsupported) == 0 {
			t.Errorf("%q converted with nothing reported", src)
			continue
		}
		joined := strings.Join(r.Unsupported, " ")
		if !strings.Contains(joined, "unlinked") && !strings.Contains(joined, "sibling") {
			t.Errorf("%q was reported without saying what to do instead: %s",
				src, joined)
		}
	}
}

// Liquid's raw and this language's raw are opposites, and a converter that
// passed the word through would turn a block of literal text into an unescaped
// value — the one mistake in this area that matters.
func TestLiquidRawIsNotTranslatedToThisLanguagesRaw(t *testing.T) {
	r := Adopt(`{% raw %}{{ not_a_field }}{% endraw %}`)
	if strings.Contains(r.Template, "{% raw ") {
		t.Errorf("a Liquid raw block became an unescaped value:\n%s", r.Template)
	}
	if len(r.Unsupported) == 0 {
		t.Error("the raw block was dropped without saying so")
	}
}

// An unqualified name has to be pointed at the page, or every value in the
// converted template resolves to nothing and the result looks like a template
// that works against empty content.
func TestUnqualifiedNamesArePointedAtThePage(t *testing.T) {
	r := Adopt(`<p>{{ title }}</p><p>{{ site.name }}</p><p>{{ page.body }}</p>`)
	for _, want := range []string{"page.title", "site.name", "page.body"} {
		if !strings.Contains(r.Template, want) {
			t.Errorf("expected %s in:\n%s", want, r.Template)
		}
	}
	if strings.Contains(r.Template, "page.page.") {
		t.Errorf("an already-qualified name was qualified twice:\n%s", r.Template)
	}
	if strings.Contains(r.Template, "page.site.") {
		t.Errorf("a context root was treated as content:\n%s", r.Template)
	}
}

// A comparison cannot be approximated. `{% if price > 100 %}` rewritten as
// `{% if price %}` renders the block for every price, which is wrong in the way
// that ships — so it is reported and left as a marker.
func TestAComparisonIsReportedRatherThanApproximated(t *testing.T) {
	r := Adopt(`{% if page.price > 100 %}Expensive{% endif %}`)
	if len(r.Unsupported) == 0 {
		t.Fatal("a comparison converted silently")
	}
	if strings.Contains(r.Template, "{% if page.price %}") {
		t.Errorf("the comparison was flattened into a presence test:\n%s", r.Template)
	}
}

// Filters that exist because the other system does not escape by default are
// dropped, and the drop is reported — somebody reading the converted file must
// not conclude that the escaping went with them.
func TestEscapeFiltersAreDroppedAndSaidSo(t *testing.T) {
	r := Adopt(`{{ title | escape }}{{ body | safe }}`)
	if strings.Contains(r.Template, "escape") || strings.Contains(r.Template, "safe") {
		t.Errorf("an escaping filter survived:\n%s", r.Template)
	}
	if len(r.Changes) < 2 {
		t.Errorf("expected both drops reported, got %d: %v", len(r.Changes), r.Changes)
	}
}

// Filters that mean the same thing are translated, because a template that
// loses its formatting is one somebody has to rewrite anyway.
func TestEquivalentFiltersAreTranslated(t *testing.T) {
	r := Adopt(`{{ title | upcase }} {{ body | truncate: 60 }} {{ tags | size }}`)
	for _, want := range []string{"| upper", "| truncate:60", "| count"} {
		if !strings.Contains(r.Template, want) {
			t.Errorf("expected %q in:\n%s", want, r.Template)
		}
	}
}

// A whole-document conversion should pass the gate that refuses a publish, or
// the feature hands somebody a layout they cannot use. Checked against the real
// checker with real content rather than asserted.
func TestAConvertedDocumentCanPassTheAccessibilityGate(t *testing.T) {
	r := Adopt(samples["liquid"])
	out, err := tmpl.Render(r.Template, map[string]any{
		"page": map[string]any{
			"title": "A page", "body": "Some prose.",
			"posts": []any{
				map[string]any{"title": "One", "url": "/one", "excerpt": "First."},
			},
		},
		"site": map[string]any{"name": "Example"},
	})
	if err != nil {
		t.Fatalf("the converted template did not render: %v", err)
	}
	report := a11y.Check("adopted", out)
	for _, f := range report.Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("the converted layout fails the gate: %s\n%s", f, out)
		}
	}
}

// The dialect guess is printed, so somebody adopting a Handlebars file that was
// read as Liquid can see it. A wrong guess with no output is a silent bug.
func TestTheDialectIsIdentified(t *testing.T) {
	cases := map[string]string{
		"liquid":     "Liquid",
		"handlebars": "Handlebars",
		"hugo":       "Hugo",
		"php":        "PHP",
		"plain":      "plain HTML",
	}
	for name, want := range cases {
		got := Adopt(samples[name]).Dialect
		if !strings.Contains(got, want) {
			t.Errorf("%s was read as %q, expected something containing %q",
				name, got, want)
		}
	}
}

// A layout name comes from a filename and lands in both a file path and a page's
// content, so the set it can produce has to be narrow.
func TestLayoutNamesAreDerivedSafely(t *testing.T) {
	cases := map[string]string{
		"product.liquid":         "product",
		"Blog Post.html":         "blog-post",
		"themes/x/single.gohtml": "single",
		"../../etc/passwd":       "passwd",
		"____":                   "adopted",
		"9lives.hbs":             "adopted",
	}
	for in, want := range cases {
		if got := LayoutNameFor(in); got != want {
			t.Errorf("LayoutNameFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every unqualified field the converted template reads is listed, so somebody
// knows what a page has to carry before they publish one.
func TestTheFieldsReadAreListed(t *testing.T) {
	r := Adopt(`{{ title }}{% if subtitle %}{{ subtitle }}{% endif %}`)
	found := map[string]bool{}
	for _, f := range r.Fields {
		found[f] = true
	}
	for _, want := range []string{"title", "subtitle"} {
		if !found[want] {
			t.Errorf("%q is read by the template and not listed: %v", want, r.Fields)
		}
	}
}

var samples = map[string]string{
	// A Shopify-shaped Liquid layout, with the constructs these actually use.
	"liquid": `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{ page_title | escape }}</title>
  <link rel="stylesheet" href="/site.css">
  <script src="https://cdn.shopify.com/s/theme.js" defer></script>
</head>
<body>
  <a class="skip" href="#main">Skip to main content</a>
  <header>
    <a href="/">{{ shop.name }}</a>
    <nav aria-label="Main">
      <ul>
      {% for link in linklists.main.links %}
        <li><a href="{{ link.url }}">{{ link.title }}</a></li>
      {% endfor %}
      </ul>
    </nav>
  </header>
  <main id="main">
    <h1>{{ title }}</h1>
    {% if body %}<p>{{ body }}</p>{% endif %}
    <ul>
    {% for post in posts limit: 6 %}
      <li>
        <h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
        <p>{{ post.excerpt | truncate: 120 }}</p>
      </li>
    {% endfor %}
    </ul>
  </main>
  <footer><p>&copy; {{ shop.name }}</p></footer>
</body>
</html>`,

	"handlebars": `<!doctype html>
<html lang="en"><head><title>{{title}}</title>
<link rel="stylesheet" href="/site.css"></head>
<body><main id="main">
<h1>{{title}}</h1>
{{#if subtitle}}<p>{{subtitle}}</p>{{/if}}
{{#each features}}
  <div><h2>{{this.name}}</h2><p>{{this.body}}</p></div>
{{/each}}
{{#unless published}}<p>Draft</p>{{/unless}}
</main></body></html>`,

	"hugo": `<!doctype html>
<html lang="{{ .Site.LanguageCode }}">
<head><title>{{ .Title }} — {{ .Site.Title }}</title>
<link rel="stylesheet" href="/site.css"></head>
<body><main id="main">
<h1>{{ .Title }}</h1>
{{ if .Params.subtitle }}<p>{{ .Params.subtitle }}</p>{{ end }}
{{ range .Pages }}
  <article><h2>{{ .Title }}</h2></article>
{{ end }}
{{ partial "footer.html" . }}
</main></body></html>`,

	"php": `<!doctype html>
<html lang="en"><head><title><?php the_title(); ?></title></head>
<body><main id="main"><?php while (have_posts()) : the_post(); ?>
<h1><?php the_title(); ?></h1>
<?php endwhile; ?></main></body></html>`,

	"twig": `<!doctype html>
<html lang="en"><head><title>{{ page.title }}</title>
<link rel="stylesheet" href="/site.css"></head>
<body><main id="main">
{% extends "base.html.twig" %}
{% block content %}
<h1>{{ title|upper }}</h1>
{% set total = items|length %}
{% for item in items %}<p>{{ item.name }}</p>{% endfor %}
{% endblock %}
</main></body></html>`,

	"plain": `<!doctype html>
<html lang="en"><head><title>A page</title>
<link rel="stylesheet" href="/site.css"></head>
<body><main id="main"><h1>Hello</h1><p>Ordinary markup.</p></main></body></html>`,
}
