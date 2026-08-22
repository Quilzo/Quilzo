package codescan

import "testing"

// HTML escaping is not CSS escaping, and a value in a style attribute is the one
// place in a template where that difference is exploitable. The rule has to fire
// on the unguarded shape and stay quiet on the guarded one — a rule that fired
// on both would be turned off in a week, and one that fired on neither would be
// decoration.
func TestAStyleInterpolationIsAFindingUnlessItIsGuaranteedNumeric(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		fires bool
	}{
		{"a bare value in a style attribute",
			`<div class="bar"><span style="--pct:{{ row.pct }}"></span></div>`, true},
		{"the same value through round is a numeral or an error",
			`<div class="bar"><span style="--pct:{{ row.pct | round }}"></span></div>`, false},
		{"count also cannot return anything else",
			`<span style="--n:{{ items | count }}"></span>`, false},
		{"a filter that does not guarantee a number is not a guard",
			`<span style="--pct:{{ row.pct | default:0 }}"></span>`, true},
		{"a colour interpolated into a style attribute is the same problem",
			`<div style="background:{{ page.brand_colour }}">x</div>`, true},
		{"a style attribute with no interpolation is not a finding",
			`<div style="display:flex">x</div>`, false},
		{"an interpolation outside a style attribute is not this rule's business",
			`<p>{{ page.title }}</p>`, false},
	}
	for _, c := range cases {
		found := false
		for _, f := range Scan([]Input{{Name: "page.html", Kind: Template, Body: c.body}}) {
			if f.Rule == "css.unfiltered-interpolation" {
				found = true
			}
		}
		if found != c.fires {
			t.Errorf("%s: fired=%v, wanted %v\n  %s", c.name, found, c.fires, c.body)
		}
	}
}
