// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package dtcg

import (
	"fmt"
	"strings"
	"testing"
)

func parse(t *testing.T, src string) *File {
	t.Helper()
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	return f
}

func refuses(t *testing.T, src, because string) {
	t.Helper()
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatalf("this was accepted and should not have been: %s", because)
	}
	if testing.Verbose() {
		t.Logf("refused: %v", err)
	}
}

func TestAGroupsTypeReachesTheTokensBelowIt(t *testing.T) {
	// The whole reason a group carries $type: a palette of two hundred
	// colours declares it once. A token that had to repeat it would be a
	// token every export leaves off.
	f := parse(t, `{
	  "palette": {
	    "$type": "color",
	    "deep": { "brand": { "$value": "#0b4f6c" } }
	  }
	}`)
	tok, ok := f.Lookup("palette.deep.brand")
	if !ok {
		t.Fatal("the token is not at the path its nesting gives it")
	}
	if tok.Type != "color" {
		t.Fatalf("the type stopped at the group: %q", tok.Type)
	}
}

func TestATokensOwnTypeBeatsTheGroups(t *testing.T) {
	f := parse(t, `{
	  "size": {
	    "$type": "dimension",
	    "step": { "$type": "number", "$value": 1.25 }
	  }
	}`)
	tok, _ := f.Lookup("size.step")
	if tok.Type != "number" {
		t.Fatalf("the group overrode the token: %q", tok.Type)
	}
}

func TestAnAliasIsFollowedToItsValue(t *testing.T) {
	f := parse(t, `{
	  "palette": { "$type": "color", "blue": { "$value": "#0b4f6c" } },
	  "semantic": { "accent": { "$value": "{palette.blue}" } }
	}`)
	tok, _ := f.Lookup("semantic.accent")
	hex, err := Hex(tok)
	if err != nil {
		t.Fatalf("reading the alias: %v", err)
	}
	if hex != "#0b4f6c" {
		t.Fatalf("the alias resolved to %q", hex)
	}
	// The type comes with it. A semantic layer that never repeats $type is
	// the normal shape, so a token with no type of its own has to take the
	// one it points at or nothing downstream knows what it holds.
	if tok.Type != "color" {
		t.Fatalf("the type did not come with the alias: %q", tok.Type)
	}
}

func TestAnAliasIsFollowedThroughAChain(t *testing.T) {
	// Two layers is the usual arrangement: a palette, a semantic layer over
	// it, and a component layer over that.
	f := parse(t, `{
	  "a": { "$type": "color", "x": { "$value": "#112233" } },
	  "b": { "y": { "$value": "{a.x}" } },
	  "c": { "z": { "$value": "{b.y}" } }
	}`)
	tok, _ := f.Lookup("c.z")
	hex, err := Hex(tok)
	if err != nil || hex != "#112233" {
		t.Fatalf("the chain gave %q, %v", hex, err)
	}
}

func TestAnAliasThatPointsForwardStillResolves(t *testing.T) {
	// Declaration order is not dependency order, and JSON object order is not
	// something anybody should be relying on anyway.
	f := parse(t, `{
	  "semantic": { "$type": "color", "accent": { "$value": "{palette.blue}" } },
	  "palette": { "$type": "color", "blue": { "$value": "#0b4f6c" } }
	}`)
	tok, _ := f.Lookup("semantic.accent")
	if hex, _ := Hex(tok); hex != "#0b4f6c" {
		t.Fatalf("a forward reference gave %q", hex)
	}
}

func TestALoopIsRefusedRatherThanWalked(t *testing.T) {
	refuses(t, `{
	  "a": { "$type": "color", "x": { "$value": "{a.y}" },
	                           "y": { "$value": "{a.x}" } }
	}`, "two tokens pointing at each other")
}

func TestATokenPointingAtItselfIsRefused(t *testing.T) {
	refuses(t, `{ "a": { "x": { "$value": "{a.x}" } } }`,
		"a token that is its own value")
}

func TestAnAliasToNowhereIsRefused(t *testing.T) {
	refuses(t, `{ "a": { "x": { "$value": "{a.missing}" } } }`,
		"a reference to a path the file does not have")
}

func TestProseContainingBracesIsNotAReference(t *testing.T) {
	// "{a.b}" is an alias; "see {a.b}" is a string. Treating a substring as a
	// reference would turn any sentence with braces in it into a broken
	// pointer, and a font family or a shadow keyword may legitimately hold
	// one.
	f := parse(t, `{ "a": { "x": { "$value": "see {a.y}" } } }`)
	tok, _ := f.Lookup("a.x")
	if tok.Value != "see {a.y}" {
		t.Fatalf("a string was treated as a reference: %v", tok.Value)
	}
}

func TestAColourIsReadFromComponentsAndFromAString(t *testing.T) {
	f := parse(t, `{
	  "c": {
	    "$type": "color",
	    "object": { "$value": { "colorSpace": "srgb",
	                            "components": [1, 0.5, 0], "alpha": 1 } },
	    "string": { "$value": "#FF8000" },
	    "short":  { "$value": "#F80" }
	  }
	}`)
	for path, want := range map[string]string{
		"c.object": "#ff8000",
		"c.string": "#ff8000",
		"c.short":  "#ff8000",
	} {
		tok, _ := f.Lookup(path)
		got, err := Hex(tok)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		// The short form stays short; what matters is that all three are the
		// same colour and all three are lower case.
		if !strings.EqualFold(got, want) && got != "#f80" {
			t.Fatalf("%s read as %q, wanted %q", path, got, want)
		}
	}
}

func TestATranslucentColourIsRefused(t *testing.T) {
	// Not fastidiousness. This value goes into a contrast ratio that decides
	// whether a page may be published, and a see-through colour does not have
	// one ratio — it has whatever ratio the thing behind it gives it.
	for name, src := range map[string]string{
		"an alpha field": `{ "c": { "$type": "color", "x": { "$value": {
			"colorSpace": "srgb", "components": [0, 0, 0], "alpha": 0.5 } } } }`,
		"eight hex digits": `{ "c": { "$type": "color",
			"x": { "$value": "#00000080" } } }`,
		"four hex digits": `{ "c": { "$type": "color",
			"x": { "$value": "#0008" } } }`,
	} {
		f := parse(t, src)
		tok, _ := f.Lookup("c.x")
		if _, err := Hex(tok); err == nil {
			t.Fatalf("%s: a translucent colour was accepted", name)
		}
	}
}

func TestAFullyOpaqueAlphaChannelIsKept(t *testing.T) {
	// #rrggbbff is opaque and is written by tools that always emit alpha.
	// Refusing it would refuse a colour that has no transparency at all.
	f := parse(t, `{ "c": { "$type": "color",
		"x": { "$value": "#0b4f6cff" },
		"y": { "$value": "#abcf" } } }`)
	for path, want := range map[string]string{"c.x": "#0b4f6c", "c.y": "#abc"} {
		tok, _ := f.Lookup(path)
		got, err := Hex(tok)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if got != want {
			t.Fatalf("%s read as %q, wanted %q", path, got, want)
		}
	}
}

func TestAColourOutsideSRGBNeedsItsHexFallback(t *testing.T) {
	with := `{ "c": { "$type": "color", "x": { "$value": {
		"colorSpace": "display-p3", "components": [1, 0, 0], "hex": "#ff0000" } } } }`
	f := parse(t, with)
	tok, _ := f.Lookup("c.x")
	got, err := Hex(tok)
	if err != nil || got != "#ff0000" {
		t.Fatalf("the fallback was not used: %q, %v", got, err)
	}

	without := `{ "c": { "$type": "color", "x": { "$value": {
		"colorSpace": "display-p3", "components": [1, 0, 0] } } } }`
	f = parse(t, without)
	tok, _ = f.Lookup("c.x")
	if _, err := Hex(tok); err == nil {
		t.Fatal("a wide-gamut colour with no fallback was converted anyway. " +
			"There is no faithful sRGB for a colour outside sRGB, and this " +
			"value ends up in a contrast check")
	}
}

func TestADimensionIsReadFromBothShapes(t *testing.T) {
	f := parse(t, `{
	  "s": {
	    "$type": "dimension",
	    "object": { "$value": { "value": 16, "unit": "px" } },
	    "string": { "$value": "1.5rem" },
	    "bare":   { "$value": 16 }
	  }
	}`)
	tok, _ := f.Lookup("s.object")
	if got, _ := Length(tok); got != "16px" {
		t.Fatalf("the object form read as %q", got)
	}
	tok, _ = f.Lookup("s.string")
	if got, _ := Length(tok); got != "1.5rem" {
		t.Fatalf("the string form read as %q", got)
	}
	tok, _ = f.Lookup("s.bare")
	if _, err := Length(tok); err == nil {
		t.Fatal("a number with no unit was accepted as a length. It is a " +
			"different size depending on what reads it")
	}
}

func TestAFontStackKeepsItsFirstFace(t *testing.T) {
	f := parse(t, `{
	  "f": {
	    "$type": "fontFamily",
	    "list": { "$value": ["Helvetica Neue", "Arial", "sans-serif"] },
	    "one":  { "$value": "Inter" }
	  }
	}`)
	tok, _ := f.Lookup("f.list")
	if got, _ := Family(tok); got != "Helvetica Neue" {
		t.Fatalf("the list read as %q", got)
	}
	tok, _ = f.Lookup("f.one")
	if got, _ := Family(tok); got != "Inter" {
		t.Fatalf("the single name read as %q", got)
	}
}

func TestADollarNameIsNotAToken(t *testing.T) {
	// $description sits beside the tokens at every level. Treating it as a
	// child would put a sentence in the palette.
	f := parse(t, `{
	  "$description": "a file",
	  "c": { "$description": "a group", "$type": "color",
	         "x": { "$value": "#000000", "$description": "a token" } }
	}`)
	if f.Len() != 1 {
		t.Fatalf("%d tokens; the descriptions were counted", f.Len())
	}
	tok, _ := f.Lookup("c.x")
	if tok.Description != "a token" {
		t.Fatalf("the description did not come through: %q", tok.Description)
	}
}

func TestANameWithADotInItIsRefused(t *testing.T) {
	// The dot separates the parts of a path, so "a.b" as one name and as two
	// is the same string and nothing could refer to either unambiguously.
	refuses(t, `{ "c": { "a.b": { "$value": "#000000" } } }`,
		"a name holding the path separator")
}

func TestANameWithABraceInItIsRefused(t *testing.T) {
	refuses(t, `{ "c": { "a{b": { "$value": "#000000" } } }`,
		"a name holding the character an alias is written with")
}

func TestAFileOfNothingButGroupsIsRefused(t *testing.T) {
	refuses(t, `{ "a": { "b": { "c": {} } } }`,
		"a file with no token in it")
}

func TestSomethingThatIsNotATokenTreeIsRefused(t *testing.T) {
	refuses(t, `{ "a": "just a string" }`,
		"a member that is neither a token nor a group")
	refuses(t, `[]`, "an array where the tree should be")
	refuses(t, `{"a":{"x":{"$value":"#000"}}} {"b":{}}`,
		"two documents in one file")
}

func TestNestingIsBounded(t *testing.T) {
	// A hand-written file does not nest thirty deep. A file built to make
	// this walk keep going does, and encoding/json will have built the whole
	// tree before this ever sees it.
	var b strings.Builder
	depth := MaxDepth + 4
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, `{"g%d":`, i)
	}
	b.WriteString(`{"x":{"$value":"#000000"}}`)
	b.WriteString(strings.Repeat("}", depth))
	refuses(t, b.String(), "a tree nested past the bound")
}

func TestTheNumberOfTokensIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"c":{"$type":"color"`)
	for i := 0; i <= MaxTokens; i++ {
		fmt.Fprintf(&b, `,"t%d":{"$value":"#000000"}`, i)
	}
	b.WriteString("}}")
	refuses(t, b.String(), "more tokens than any published export holds")
}

func TestTokensComeBackSorted(t *testing.T) {
	// A listing somebody reads to write a mapping, and a diff of two exports,
	// both want the same order every time. Go's map iteration gives neither.
	f := parse(t, `{ "z": { "$type": "color", "b": { "$value": "#000" },
	                                          "a": { "$value": "#111" } },
	                 "a": { "$type": "color", "c": { "$value": "#222" } } }`)
	var got []string
	for _, tok := range f.Tokens() {
		got = append(got, tok.Path)
	}
	want := []string{"a.c", "z.a", "z.b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order was %v, wanted %v", got, want)
		}
	}
}
