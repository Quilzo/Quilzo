package tmpl

import "testing"

// A template engine advertising "cannot execute anything" is a claim, and a
// security claim is worth exactly what its tests are worth. The payloads below
// are the ones that break real engines.

func TestRefusesSandboxEscapes(t *testing.T) {
	data := map[string]any{"page": map[string]any{"title": "hello"}}

	cases := []struct{ name, src string }{
		{"field access", "{{ page.Title.Len }}"},
		{"method call", "{{ page.title.upper() }}"},
		{"arbitrary expression", "{{ 1+1 }}"},
		{"underscore-prefixed name", "{{ _secret }}"},
		{"dunder walk", "{{ page.__class__ }}"},
		{"mro", "{{ page.__class__.__mro__ }}"},
		{"globals", "{{ page.__init__.__globals__ }}"},
		{"pipe to a filter", "{{ page.title | system }}"},
		{"index syntax", "{{ page['title'] }}"},
		{"parenthesised", "{{ (page.title) }}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Render(tc.src, data)
			if err == nil && out != "" {
				t.Fatalf("payload produced output %q instead of being refused", out)
			}
		})
	}
}

func TestUnknownTagsAreErrors(t *testing.T) {
	// An unknown tag must not be echoed as output either: that would let an
	// attacker inject markup through a construct that merely looks inert.
	for _, src := range []string{
		"{% exec %}x{% end %}",
		"{% include /etc/passwd %}",
		"{% eval page %}",
		"{% template other %}",
	} {
		if _, err := Render(src, nil); err == nil {
			t.Errorf("%q was accepted", src)
		}
	}
}

func TestEscapesPerContext(t *testing.T) {
	cases := []struct {
		name, src string
		data      map[string]any
		mustNot   string
		must      string
	}{
		{
			name:    "script in text",
			src:     "<p>{{ c.body }}</p>",
			data:    map[string]any{"c": map[string]any{"body": "<script>alert(1)</script>"}},
			mustNot: "<script>",
		},
		{
			name:    "attribute break-out",
			src:     `<div class="{{ c.cls }}">x</div>`,
			data:    map[string]any{"c": map[string]any{"cls": `" onload="alert(1)`}},
			mustNot: `onload="alert`,
		},
		{
			// The one many engines miss: HTML-escaping does nothing to this.
			name:    "javascript: in href",
			src:     `<a href="{{ c.url }}">go</a>`,
			data:    map[string]any{"c": map[string]any{"url": "javascript:alert(1)"}},
			mustNot: "javascript:",
			must:    "#unsafe-url",
		},
		{
			name:    "data: URL",
			src:     `<a href="{{ c.url }}">go</a>`,
			data:    map[string]any{"c": map[string]any{"url": "data:text/html,<script>x</script>"}},
			mustNot: "data:text/html",
			must:    "#unsafe-url",
		},
		{
			name: "vbscript: URL",
			src:  `<img src="{{ c.url }}">`,
			data: map[string]any{"c": map[string]any{"url": "vbscript:msgbox(1)"}},
			must: "#unsafe-url",
		},
		{
			name: "an ordinary URL still works",
			src:  `<a href="{{ c.url }}">go</a>`,
			data: map[string]any{"c": map[string]any{"url": "https://example.com/a?b=1"}},
			must: "https://example.com/a?b=1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Render(tc.src, tc.data)
			if err != nil {
				t.Fatalf("render failed: %v", err)
			}
			if tc.mustNot != "" && contains(out, tc.mustNot) {
				t.Errorf("output still contains %q: %s", tc.mustNot, out)
			}
			if tc.must != "" && !contains(out, tc.must) {
				t.Errorf("output lacks %q: %s", tc.must, out)
			}
		})
	}
}

func TestRawPassesThroughAndIsAuditable(t *testing.T) {
	out, err := Render("<p>{% raw c.body %}</p>",
		map[string]any{"c": map[string]any{"body": "<em>trusted</em>"}})
	if err != nil || !contains(out, "<em>trusted</em>") {
		t.Fatalf("raw did not pass markup through: %q %v", out, err)
	}
	sites := RawSites("<p>{% raw c.body %}</p>{{ x }}{% raw other.thing %}")
	if len(sites) != 2 || sites[0] != "c.body" || sites[1] != "other.thing" {
		t.Fatalf("raw sites not listed correctly: %v", sites)
	}
}

func TestRenderingAlwaysTerminates(t *testing.T) {
	t.Run("depth is capped", func(t *testing.T) {
		src := ""
		for i := 0; i < 20; i++ {
			src += "{% for a in xs %}"
		}
		src += "x"
		for i := 0; i < 20; i++ {
			src += "{% end %}"
		}
		if _, err := Render(src, map[string]any{"xs": []any{1.0}}); err == nil {
			t.Fatal("excessive nesting was accepted")
		}
	})

	t.Run("iteration is capped", func(t *testing.T) {
		xs := make([]any, 400)
		for i := range xs {
			xs[i] = float64(i)
		}
		src := "{% for a in xs %}{% for b in xs %}{% for c in xs %}x{% end %}{% end %}{% end %}"
		if _, err := Render(src, map[string]any{"xs": xs}); err == nil {
			t.Fatal("64M iterations completed instead of being capped")
		}
	})

	t.Run("unclosed block is an error", func(t *testing.T) {
		if _, err := Render("{% if page.x %}forever", nil); err == nil {
			t.Fatal("an unclosed block was accepted")
		}
	})
}

func TestMissingDataDegrades(t *testing.T) {
	out, err := Render("<p>{{ a.b.c.d }}</p>", map[string]any{"a": map[string]any{}})
	if err != nil || out != "<p></p>" {
		t.Fatalf("missing path should render empty, got %q %v", out, err)
	}
	out, err = Render("{% for x in nope %}{{ x }}{% end %}ok", nil)
	if err != nil || out != "ok" {
		t.Fatalf("looping over nothing should be fine, got %q %v", out, err)
	}
}

func TestLoopVariableDoesNotLeak(t *testing.T) {
	// If the loop variable escaped its block, a later reference would resolve and
	// templates would stop being locally reasoned about.
	out, err := Render("{% for x in xs %}a{% end %}[{{ x }}]",
		map[string]any{"xs": []any{1.0, 2.0}})
	if err != nil {
		t.Fatal(err)
	}
	if out != "aa[]" {
		t.Fatalf("loop variable leaked out of its block: %q", out)
	}
}

func TestNestedLoopsAndConditionals(t *testing.T) {
	data := map[string]any{"nav": []any{
		map[string]any{"label": "One", "url": "/one", "kids": []any{
			map[string]any{"label": "Deep", "url": "/deep"},
		}},
		map[string]any{"label": "Two", "url": "/two"},
	}}
	src := `{% for i in nav %}<a href="{{ i.url }}">{{ i.label }}</a>` +
		`{% if i.kids %}<ul>{% for k in i.kids %}<li>{{ k.label }}</li>{% end %}</ul>{% end %}{% end %}`
	out, err := Render(src, data)
	if err != nil {
		t.Fatal(err)
	}
	want := `<a href="/one">One</a><ul><li>Deep</li></ul><a href="/two">Two</a>`
	if out != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
