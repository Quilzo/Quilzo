package tmpl

import (
	"strings"
	"testing"
)

// Red-team probe: every shape an SSTI payload takes in other template
// languages, against the claim that this one cannot execute anything.
func TestRedTeamSSTI(t *testing.T) {
	ctx := map[string]any{
		"page":   map[string]any{"title": "hi", "secret": "S3CRET"},
		"nested": map[string]any{"a": map[string]any{"b": "deep"}},
		"list":   []any{"x", "y"},
	}
	for _, p := range []string{
		`{{ page.title.__class__ }}`,
		`{{ page.__proto__ }}`,
		`{{ page.constructor }}`,
		`{{ ''.__class__.__mro__[1].__subclasses__() }}`,
		`{{ 7*7 }}`,
		`{{ 7|attr("__class__") }}`,
		`{% for x in page %}{{ x }}{% end %}`,
		`{% raw page.secret %}`,
		`{% exec "id" %}`,
		`{% include "/etc/passwd" %}`,
		`{% import os %}`,
		`{{ page["title"] }}`,
		`{{ page.title | upper }}`,
		`{{ ../../etc/passwd }}`,
		`{{ page..title }}`,
		`{%if page%}{%end%}{%end%}`,
		`{{ config }}`,
		`{{ self }}`,
		`${7*7}`,
		`#{7*7}`,
		`<%= 7*7 %>`,
		`{{= 7*7 }}`,
	} {
		out, err := Render(p, ctx)
		t.Logf("%-46s err=%v out=%q", trunc(p, 44), errShort(err), trunc(out, 40))
		// The only thing that must never happen: arbitrary evaluation.
		if strings.Contains(out, "49") {
			t.Errorf("ARITHMETIC EVALUATED: %q -> %q", p, out)
		}
		if strings.Contains(out, "root:") || strings.Contains(out, "uid=") {
			t.Errorf("FILE OR COMMAND OUTPUT: %q -> %q", p, out)
		}
	}
}

func errShort(err error) string {
	if err == nil {
		return "nil"
	}
	return trunc(err.Error(), 46)
}
func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
