// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package theme

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/dtcg"
)

func file(t *testing.T, src string) *dtcg.File {
	t.Helper()
	f, err := dtcg.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	return f
}

const sample = `{
  "palette": {
    "$type": "color",
    "white": { "$value": "#ffffff" },
    "ink":   { "$value": { "colorSpace": "srgb", "components": [0.05, 0.06, 0.07] } },
    "blue":  { "$value": "#0b4f6c" }
  },
  "semantic": {
    "$type": "color",
    "background": { "$value": "{palette.white}" },
    "text":       { "$value": "{palette.ink}" }
  },
  "size":  { "$type": "dimension", "radius": { "$value": { "value": 2, "unit": "px" } } },
  "scale": { "$type": "number", "step": { "$value": 1.2 } },
  "font":  { "$type": "fontFamily",
             "sans": { "$value": ["Helvetica Neue", "Arial", "sans-serif"] },
             "odd":  { "$value": ["Nothing Anybody Has"] } }
}`

func TestAMappingFillsTheTokensItNames(t *testing.T) {
	values, problems := Import(file(t, sample), map[string]string{
		"surface":    "semantic.background",
		"on-surface": "semantic.text",
		"radius":     "size.radius",
		"scale":      "scale.step",
	})
	for _, p := range problems {
		if p.Blocking {
			t.Fatalf("a mapping that names real paths was refused: %s", p.Detail)
		}
	}
	for key, want := range map[string]string{
		"surface":    "#ffffff",
		"on-surface": "#0d0f12",
		"radius":     "2px",
		"scale":      "1.2",
	} {
		if values[key] != want {
			t.Fatalf("%s came out %q, wanted %q", key, values[key], want)
		}
	}
}

func TestTheConverterIsChosenByTheTokenBeingFilled(t *testing.T) {
	// Not by the file's $type. A file may legitimately declare none, and a
	// mapping always names both ends — so the kind of the thing being filled
	// is the only side that is always known.
	values, problems := Import(file(t, `{
	  "untyped": { "brand": { "$value": "#0b4f6c" },
	               "gap":   { "$value": "8px" } }
	}`), map[string]string{"primary": "untyped.brand", "radius": "untyped.gap"})
	for _, p := range problems {
		if p.Blocking {
			t.Fatalf("an untyped file was refused: %s", p.Detail)
		}
	}
	if values["primary"] != "#0b4f6c" || values["radius"] != "8px" {
		t.Fatalf("an untyped file read as %v", values)
	}
}

func TestATokenThisProgramDoesNotHaveIsRefused(t *testing.T) {
	// The set is closed, and a mapping line that fills nothing is a setting
	// somebody believes they made.
	_, problems := Import(file(t, sample),
		map[string]string{"elevation-3": "semantic.background"})
	if !Blocks(problems) {
		t.Fatal("a mapping naming a token that does not exist was accepted")
	}
}

func TestAPathTheFileDoesNotHaveIsRefused(t *testing.T) {
	_, problems := Import(file(t, sample),
		map[string]string{"surface": "semantic.nothing"})
	if !Blocks(problems) {
		t.Fatal("a mapping pointing at nothing was accepted")
	}
}

func TestHalfAPaletteIsNotImported(t *testing.T) {
	// The whole reason a bad line blocks rather than warns. A site filled
	// half from one design and half from another wears both, and the half
	// that stayed behind is the half nobody notices until somebody complains
	// the dark mode looks wrong.
	values, problems := Import(file(t, sample), map[string]string{
		"surface":    "semantic.background",
		"on-surface": "semantic.does-not-exist",
	})
	if !Blocks(problems) {
		t.Fatal("a mapping with a bad line was accepted")
	}
	if _, filled := values["surface"]; !filled {
		t.Skip("nothing to assert: the good line produced no value")
	}
	// The caller is the one that stops; what matters here is that it is told
	// something blocking happened, not that the good half was thrown away.
}

func TestATypeDisagreementIsSaidAndNotRefused(t *testing.T) {
	// The value read. So this is worth a line and not a refusal — but it is
	// also exactly what a mapping pointing one path off looks like.
	values, problems := Import(file(t, sample),
		map[string]string{"radius": "palette.blue"})
	if Blocks(problems) {
		t.Fatal("a value that converted was refused over its declared type")
	}
	if len(problems) == 0 {
		t.Fatal("a colour was used as a radius and nothing was said")
	}
	if values["radius"] == "" {
		t.Fatal("the value was dropped as well as reported")
	}
}

func TestAKnownTypefaceBecomesTheStackThatLeadsWithIt(t *testing.T) {
	// A design system's font token is a whole stack. Keeping only the first
	// name would throw away the fallbacks, which are what the page is set in
	// on most of the machines that load it — and this program has a stack
	// that leads with the same face and carries fallbacks it can promise.
	values, problems := Import(file(t, sample),
		map[string]string{"font-body": "font.sans"})
	if Blocks(problems) {
		t.Fatalf("a real font stack was refused: %v", problems)
	}
	if values["font-body"] != "grotesque" {
		t.Fatalf("the stack came out %q, and grotesque leads with the same "+
			"face", values["font-body"])
	}
	head, _, _ := strings.Cut(stacks["grotesque"], ",")
	if strings.Trim(strings.TrimSpace(head), `"`) != "Helvetica Neue" {
		t.Fatalf("this test assumes grotesque leads with Helvetica Neue, "+
			"and it now leads with %q", head)
	}
}

func TestAFaceThisProgramDoesNotHaveIsPassedThrough(t *testing.T) {
	// Not refused here. Whether the site serves it is a question about the
	// site, and New answers it with the message that says where to put the
	// file.
	values, _ := Import(file(t, sample),
		map[string]string{"font-body": "font.odd"})
	if values["font-body"] != "Nothing Anybody Has" {
		t.Fatalf("an unknown face came out %q", values["font-body"])
	}
	if _, problems := New(values, nil); !Blocks(problems) {
		t.Fatal("a face nothing serves was accepted by New")
	}
}

func TestASchemeSuffixSurvivesTheImport(t *testing.T) {
	values, problems := Import(file(t, sample),
		map[string]string{"surface.dark": "semantic.text"})
	if Blocks(problems) {
		t.Fatalf("a scheme-suffixed key was refused: %v", problems)
	}
	if values["surface.dark"] != "#0d0f12" {
		t.Fatalf("the suffix was eaten: %v", values)
	}
}

// -- two keys, one setting ---------------------------------------------------

func TestAKeyAndItsSchemeSuffixCollide(t *testing.T) {
	// The bug this exists for: "primary" and "primary.dark" are different
	// strings and the same setting for the dark scheme. A command comparing
	// the strings finds no clash, writes both, and leaves whichever sorts
	// later quietly in charge of a scheme the operator thought they had
	// replaced.
	for _, pair := range [][2]string{
		{"primary", "primary.dark"},
		{"primary", "primary.light"},
		{"primary", "primary"},
	} {
		if !Collide(pair[0], pair[1]) {
			t.Fatalf("%q and %q were called separate settings", pair[0], pair[1])
		}
		if !Collide(pair[1], pair[0]) {
			t.Fatalf("%q and %q collide in one direction only", pair[0], pair[1])
		}
	}
}

func TestTheTwoSchemesDoNotCollideWithEachOther(t *testing.T) {
	if Collide("primary.light", "primary.dark") {
		t.Fatal("the two schemes were treated as one setting; filling one " +
			"would then be refused for touching the other")
	}
	if Collide("primary", "surface") {
		t.Fatal("two different tokens were treated as one setting")
	}
}

func TestCollidingFindsWhatWouldBeOverwritten(t *testing.T) {
	have := map[string]string{
		"primary":      "#111111",
		"primary.dark": "#222222",
		"surface":      "#ffffff",
	}
	want := map[string]string{"primary.light": "#333333"}
	got := Colliding(have, want)
	if len(got) != 1 || got[0] != "primary" {
		t.Fatalf("colliding gave %v; primary covers light and is the one "+
			"being overwritten, primary.dark is not", got)
	}
}

// -- out and back ------------------------------------------------------------

func TestAThemeSurvivesBeingExportedAndReadBack(t *testing.T) {
	// The property that says the two halves agree. Every token this program
	// has, written out, parsed by the reader, mapped back, and compared --
	// so a value the writer cannot express or the reader cannot read is a
	// failure here rather than a surprise on somebody's site.
	th, problems := New(map[string]string{
		"primary":      "#0b4f6c",
		"primary.dark": "#93d0dc",
		"radius":       "4px",
		"scale":        "1.333",
		"font-body":    "geometric",
	}, nil)
	if Blocks(problems) {
		t.Fatalf("the theme under test is not valid: %v", problems)
	}

	out := Export(th)
	var tree map[string]any
	if err := json.Unmarshal(out, &tree); err != nil {
		t.Fatalf("the export is not valid JSON: %v", err)
	}
	f, err := dtcg.Parse(out)
	if err != nil {
		t.Fatalf("this program cannot read its own export: %v", err)
	}

	mapping := map[string]string{}
	for _, tok := range Tokens() {
		mapping[tok.Name] = "light." + tok.Group + "." + tok.Name
		if tok.Kind == Colour {
			mapping[tok.Name+".dark"] = "dark." + tok.Group + "." + tok.Name
		}
	}
	back, problems := Import(f, mapping)
	for _, p := range problems {
		if p.Blocking {
			t.Fatalf("reading the export back: %s", p.Detail)
		}
	}

	for _, tok := range Tokens() {
		for _, scheme := range []struct {
			key  string
			dark bool
		}{{tok.Name, false}, {tok.Name + ".dark", true}} {
			if scheme.dark && tok.Kind != Colour {
				continue
			}
			want := th.value(tok, scheme.dark)
			got := back[scheme.key]
			if tok.Kind == Colour {
				want, got = expand(want), expand(got)
			}
			if !strings.EqualFold(got, want) {
				t.Fatalf("%s went out as %q and came back as %q",
					scheme.key, want, got)
			}
		}
	}

	// And the theme the round trip produces is still a valid theme, which is
	// the part that matters to whoever runs it.
	again, problems := New(back, nil)
	if Blocks(problems) {
		t.Fatalf("the re-imported theme does not validate: %v", problems)
	}
	if Blocks(again.Check()) {
		t.Fatal("the re-imported theme fails contrast, and the one it came " +
			"from passes")
	}
}

// expand turns #abc into #aabbcc, since the export writes six digits and the
// theme may hold three. Same colour, different spelling.
func expand(hex string) string {
	s := strings.TrimPrefix(hex, "#")
	if len(s) != 3 {
		return strings.ToLower(hex)
	}
	return strings.ToLower("#" + string([]byte{
		s[0], s[0], s[1], s[1], s[2], s[2]}))
}

func TestTheExportWritesNoTypeForAUnitCssHasAndTheFormatDoesNot(t *testing.T) {
	// measure is in ch and tracking is in em. Neither is a dimension there,
	// and writing 68ch as 68px would be a number that means something else on
	// every machine that reads it.
	th, _ := New(nil, nil)
	var tree map[string]any
	if err := json.Unmarshal(Export(th), &tree); err != nil {
		t.Fatalf("the export is not valid JSON: %v", err)
	}
	light, _ := tree["light"].(map[string]any)
	typeGroup, _ := light["type"].(map[string]any)
	measure, _ := typeGroup["measure"].(map[string]any)
	if measure == nil {
		t.Fatal("measure is not in the export")
	}
	if _, typed := measure["$type"]; typed {
		t.Fatalf("measure is %v and carries a $type; ch is not a unit the "+
			"format has", measure["$value"])
	}
	if s, isString := measure["$value"].(string); !isString || !strings.HasSuffix(s, "ch") {
		t.Fatalf("measure came out as %v, which is not the value it holds",
			measure["$value"])
	}
}

func TestSuggestNamesEverySettableKey(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Suggest() {
		seen[m.Key] = true
	}
	for _, tok := range Tokens() {
		if !seen[tok.Name] {
			t.Fatalf("%s cannot be found from the suggested list", tok.Name)
		}
		if tok.Kind == Colour && !seen[tok.Name+".dark"] {
			t.Fatalf("%s has two schemes and the list offers one", tok.Name)
		}
	}
}
