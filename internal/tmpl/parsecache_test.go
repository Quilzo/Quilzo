// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package tmpl

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// reset empties the memo so a test starts from a known state.
func reset(t *testing.T) {
	t.Helper()
	trees.Lock()
	trees.bySource = nil
	trees.Unlock()
}

func held() int {
	trees.Lock()
	defer trees.Unlock()
	return len(trees.bySource)
}

func TestATemplateIsParsedOnce(t *testing.T) {
	reset(t)
	const src = `<p>{{ page.title }}</p>{% for r in rows %}<li>{{ r }}</li>{% end %}`

	for i := 0; i < 5; i++ {
		if _, err := Render(src, map[string]any{
			"page": map[string]any{"title": "x"},
			"rows": []any{"a", "b"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := held(); got != 1 {
		t.Errorf("five renders of one template left %d trees in the memo", got)
	}
}

// The memo must not become the answer. Different data through the same
// template has to render differently, and this is the mistake a cache keyed on
// the template that stored the output would make.
func TestTheSameTemplateRendersDifferentData(t *testing.T) {
	reset(t)
	const src = `<p>{{ name }}</p>`
	for _, want := range []string{"Ada", "Grace", "Barbara"} {
		got, err := Render(src, map[string]any{"name": want})
		if err != nil {
			t.Fatal(err)
		}
		if got != "<p>"+want+"</p>" {
			t.Errorf("got %q for %q", got, want)
		}
	}
}

// A changed template is a different string and therefore a different key,
// which is what makes this memo impossible to invalidate wrongly.
func TestAChangedTemplateIsADifferentTemplate(t *testing.T) {
	reset(t)
	one, err := Render(`<p>{{ x }}</p>`, map[string]any{"x": "1"})
	if err != nil {
		t.Fatal(err)
	}
	two, err := Render(`<h1>{{ x }}</h1>`, map[string]any{"x": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatalf("both rendered as %q", one)
	}
	if got := held(); got != 2 {
		t.Errorf("two templates left %d trees", got)
	}
}

// The property the sharing rests on: a render reads the tree and changes
// nothing in it. A filter that memoised something into a node would break
// this, and this is where it would be caught.
func TestManyRendersOfOneTemplateAgree(t *testing.T) {
	reset(t)
	const src = `{% for r in rows %}<li>{{ r.name | upper }}</li>{% end %}` +
		`{% if flag %}<b>{{ n }}</b>{% end %}`

	render := func(n int) (string, error) {
		return Render(src, map[string]any{
			"rows": []any{
				map[string]any{"name": fmt.Sprintf("a%d", n)},
				map[string]any{"name": fmt.Sprintf("b%d", n)},
			},
			"flag": n%2 == 0,
			"n":    n,
		})
	}

	// What each one should be, computed before any sharing can have happened.
	want := make([]string, 32)
	for i := range want {
		out, err := render(i)
		if err != nil {
			t.Fatal(err)
		}
		want[i] = out
	}

	reset(t)
	var wg sync.WaitGroup
	got := make([]string, len(want))
	errs := make([]error, len(want))
	for i := range want {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = render(i)
		}(i)
	}
	wg.Wait()

	for i := range want {
		if errs[i] != nil {
			t.Fatalf("%d: %v", i, errs[i])
		}
		if got[i] != want[i] {
			t.Errorf("%d rendered %q under concurrency and %q alone",
				i, got[i], want[i])
		}
	}
}

// A template that does not parse is not remembered: the caller reports the
// error and somebody fixes the template, so a cached failure would be read
// once and then be wrong.
func TestABrokenTemplateIsNotRemembered(t *testing.T) {
	reset(t)
	if _, err := Render(`{% wat %}`, nil); err == nil {
		t.Fatal("an unknown tag rendered without complaint")
	}
	if got := held(); got != 0 {
		t.Errorf("a failed parse left %d entries", got)
	}
}

// The bound exists because one caller renders a template from a path somebody
// typed, and an unbounded map keyed on arbitrary file contents is a leak
// rather than a cache.
func TestTheMemoIsBounded(t *testing.T) {
	reset(t)
	for i := 0; i < maxTrees*3; i++ {
		src := strings.Repeat(" ", i) + `<p>{{ x }}</p>`
		if _, err := Render(src, map[string]any{"x": "1"}); err != nil {
			t.Fatal(err)
		}
		if got := held(); got > maxTrees {
			t.Fatalf("after %d templates the memo holds %d", i+1, got)
		}
	}
}

// And being emptied does not lose correctness, only the saving.
func TestRenderingStillWorksAfterTheMemoIsEmptied(t *testing.T) {
	reset(t)
	const src = `<p>{{ x }}</p>`
	if _, err := Render(src, map[string]any{"x": "first"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxTrees+1; i++ {
		if _, err := Render(strings.Repeat("\t", i)+src,
			map[string]any{"x": "1"}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Render(src, map[string]any{"x": "second"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "<p>second</p>" {
		t.Errorf("after the memo was emptied the template rendered %q", got)
	}
}

func BenchmarkRenderALayout(b *testing.B) {
	src := `<!doctype html><html><head><title>{{ page.title }}</title></head>` +
		`<body><h1>{{ page.title }}</h1>` +
		strings.Repeat(`<section><h2>{{ page.title }}</h2>`+
			`{% for r in rows %}<li>{{ r.name }} — {{ r.note }}</li>{% end %}`+
			`</section>`, 20) +
		`</body></html>`
	rows := make([]any, 20)
	for i := range rows {
		rows[i] = map[string]any{"name": "a name", "note": "a note"}
	}
	data := map[string]any{
		"page": map[string]any{"title": "Home"},
		"rows": rows,
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Render(src, data); err != nil {
			b.Fatal(err)
		}
	}
}
