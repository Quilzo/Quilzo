// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package dtcg reads a W3C Design Tokens file.
//
// # Why this and not a theme per design system
//
// The obvious way to offer somebody the look of a design system they already
// use is to ship a theme named after it. That is the one way this cannot be
// done. A design system has two licences and people read only the first: the
// code licence — MIT for GitHub's Primer, Apache-2.0 for IBM's Carbon and
// Adobe's Spectrum — which usually does permit a derived palette, and the
// trademark policy, which separately does not permit the name. Apache-2.0
// reserves marks explicitly in section 6; MIT simply never grants them. Two of
// the systems go further: Adobe's trademark guidelines bar copying "trade
// dress… the look and feel… distinctive colour combinations", and Shopify's
// main Polaris licence is a modified MIT whose rights apply only to apps that
// integrate with Shopify, requiring anything else to be "dissimilar and
// visually distinct". Apple's design resources may not be embedded in software
// at all.
//
// So this package ships nobody's palette and nobody's name. It reads the file
// the design system publishes, on the machine of the operator who is entitled
// to use it, and maps it onto the token set this program already checks. What
// a customer gets is their own design system, not an imitation of it.
//
// # The format
//
// Design Tokens Format Module 2025.10, the first stable version, published by
// the W3C Design Tokens Community Group on 28 October 2025 with around forty
// backing organisations including Adobe, Figma, Google, Microsoft, Shopify and
// Salesforce. It is a Community Group report rather than a Recommendation, and
// a later draft exists that is marked as not for implementation — so this
// reads 2025.10 and also accepts the string forms that earlier drafts used and
// that most exports in the wild still contain.
//
// A file is a tree. A leaf holding $value is a token; anything else is a
// group. $type is declared on a token or inherited from the nearest ancestor
// group that declares one. A $value that is exactly "{a.b.c}" is an alias for
// the token at that path.
//
// # What is refused rather than approximated
//
// A colour with alpha below 1, and a colour in a space that is not sRGB with
// no hex fallback. Both could be converted to something, and the something
// would be a guess. This file's values end up in a contrast ratio that decides
// whether a page may be published: a translucent colour's real contrast
// depends on whatever happens to be behind it, and a display-p3 colour outside
// the sRGB gamut has no faithful hex. A gate fed an approximation is a gate
// that passes pages nobody can read.
package dtcg

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// MaxDepth bounds how far the tree is walked.
//
// A hand-written file does not nest ten deep; a file built to make this
// program recurse until it dies does. The bound is on the walk rather than on
// the decoder because encoding/json will happily build the tree first.
const MaxDepth = 32

// MaxTokens bounds how many tokens are kept.
//
// Carbon's own DTCG export of every theme is about 93 KB, which is some
// thousands of tokens. Ten thousand is well past any real file and well short
// of anything that troubles this process.
const MaxTokens = 10000

// Token is one resolved leaf.
type Token struct {
	// Path is the dotted name, e.g. "color.text.primary".
	Path string
	// Type is $type after inheritance and alias resolution. Empty when the
	// file never said — legal, and the reason a value is checked by shape as
	// well as by type.
	Type string
	// Value is $value with aliases followed. Still the JSON shape: a string, a
	// number, or a map for the object forms.
	Value any
	// Description is $description, for a listing a person reads.
	Description string
}

// File is a parsed token file.
type File struct {
	tokens []Token
	byPath map[string]Token
}

// Tokens returns every token, sorted by path.
func (f *File) Tokens() []Token {
	out := make([]Token, len(f.tokens))
	copy(out, f.tokens)
	return out
}

// Lookup returns one token by its dotted path.
func (f *File) Lookup(path string) (Token, bool) {
	t, ok := f.byPath[path]
	return t, ok
}

// Len is how many tokens the file holds.
func (f *File) Len() int { return len(f.tokens) }

// raw is the tree as it arrives, before tokens and groups are told apart.
type raw map[string]any

// Parse reads a token file.
//
// Two passes. The first flattens the tree and records each token's declared or
// inherited type; the second follows aliases, which cannot be done in the
// first because an alias may point forwards.
func Parse(b []byte) (*File, error) {
	var root raw
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf(
			"this is not a design token file this can read: %w", err)
	}
	// One document, not a stream. A second value after the object is either a
	// concatenated file or something trying to be read twice, and neither is
	// what the caller asked to import.
	if dec.More() {
		return nil, fmt.Errorf(
			"there is more than one JSON document in this file; a token file " +
				"is a single object")
	}

	f := &File{byPath: map[string]Token{}}
	if err := f.walk(root, nil, "", 0); err != nil {
		return nil, err
	}
	if len(f.tokens) == 0 {
		return nil, fmt.Errorf(
			"no tokens in this file. A token is an object with a $value; a " +
				"file of nothing but groups has nothing to import")
	}
	if err := f.resolve(); err != nil {
		return nil, err
	}
	sort.Slice(f.tokens, func(i, j int) bool {
		return f.tokens[i].Path < f.tokens[j].Path
	})
	for _, t := range f.tokens {
		f.byPath[t.Path] = t
	}
	return f, nil
}

// walk flattens one group.
func (f *File) walk(node raw, path []string, inherited string, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf(
			"%s is nested more than %d deep. That is past any file a person "+
				"wrote and into one built to make this walk keep going",
			join(path), MaxDepth)
	}
	// $type on this node is inherited by everything below it.
	kind := inherited
	if v, ok := node["$type"]; ok {
		s, isString := v.(string)
		if !isString {
			return fmt.Errorf("%s declares a $type that is not a string",
				groupName(path))
		}
		kind = s
	}

	names := make([]string, 0, len(node))
	for name := range node {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if strings.HasPrefix(name, "$") {
			// $type, $description, $extensions, $deprecated and anything a
			// later version adds. Reserved at every level, so skipped rather
			// than treated as a child.
			continue
		}
		child, isObject := node[name].(map[string]any)
		if !isObject {
			return fmt.Errorf(
				"%s is not a token or a group. Every member of a group is an "+
					"object: a token has a $value, a group has more members",
				join(append(path, name)))
		}
		if err := checkName(name, path); err != nil {
			return err
		}
		next := append(append([]string{}, path...), name)

		if _, isToken := child["$value"]; !isToken {
			if err := f.walk(child, next, kind, depth+1); err != nil {
				return err
			}
			continue
		}
		if len(f.tokens) >= MaxTokens {
			return fmt.Errorf(
				"this file holds more than %d tokens. The largest published "+
					"export is some thousands, so a file past this is not one "+
					"of those", MaxTokens)
		}
		own := kind
		if v, ok := child["$type"]; ok {
			s, isString := v.(string)
			if !isString {
				return fmt.Errorf("%s declares a $type that is not a string",
					join(next))
			}
			own = s
		}
		desc, _ := child["$description"].(string)
		f.tokens = append(f.tokens, Token{
			Path:        join(next),
			Type:        own,
			Value:       child["$value"],
			Description: desc,
		})
	}
	return nil
}

// checkName applies the naming rules a path depends on.
//
// A dot in a name would make the path ambiguous — "a.b" as one name and as two
// is the same string — and braces are how an alias is written, so a name
// carrying either cannot be referred to at all.
func checkName(name string, path []string) error {
	switch {
	case name == "":
		return fmt.Errorf("%s has a member with an empty name", groupName(path))
	case strings.Contains(name, "."):
		return fmt.Errorf(
			"%q in %s has a dot in it. The dot separates the parts of a path, "+
				"so a name holding one cannot be referred to",
			name, groupName(path))
	case strings.ContainsAny(name, "{}"):
		return fmt.Errorf(
			"%q in %s has a brace in it, which is how an alias is written",
			name, groupName(path))
	}
	return nil
}

// resolve follows aliases, refusing a cycle.
func (f *File) resolve() error {
	index := map[string]int{}
	for i, t := range f.tokens {
		if _, dup := index[t.Path]; dup {
			// JSON with two identical keys is already decoded to one, so this
			// is two paths that collide some other way. Worth saying rather
			// than resolving by order.
			return fmt.Errorf("two tokens are called %s", t.Path)
		}
		index[t.Path] = i
	}
	for i := range f.tokens {
		seen := map[string]bool{f.tokens[i].Path: true}
		chain := []string{f.tokens[i].Path}
		at := i
		for {
			target, isAlias := aliasOf(f.tokens[at].Value)
			if !isAlias {
				break
			}
			next, known := index[target]
			if !known {
				return fmt.Errorf(
					"%s refers to {%s}, and there is no token at that path",
					f.tokens[i].Path, target)
			}
			chain = append(chain, target)
			if seen[target] {
				// The chain rather than the two ends. A loop three tokens
				// long between a palette, a semantic layer and a component
				// layer is a real mistake somebody makes, and "a refers to
				// itself" does not say where to cut it.
				return fmt.Errorf(
					"%s is in a loop: %s. Nothing can be resolved from one",
					f.tokens[i].Path, strings.Join(chain, " -> "))
			}
			seen[target] = true
			at = next
		}
		f.tokens[i].Value = f.tokens[at].Value
		if f.tokens[i].Type == "" {
			// A token that says nothing about its own type takes the type of
			// what it points at, which is the only thing it could have meant.
			f.tokens[i].Type = f.tokens[at].Type
		}
	}
	return nil
}

// aliasOf reports whether a value is exactly a reference, and to what.
//
// Exactly: "{a.b}" is an alias and "see {a.b}" is a string that happens to
// contain one. The spec's form is the whole value, and treating a substring as
// a reference would make any prose containing braces into a broken pointer.
func aliasOf(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	inner, found := strings.CutPrefix(s, "{")
	if !found {
		return "", false
	}
	inner, found = strings.CutSuffix(inner, "}")
	if !found || inner == "" || strings.ContainsAny(inner, "{}") {
		return "", false
	}
	return inner, true
}

func join(path []string) string { return strings.Join(path, ".") }

func groupName(path []string) string {
	if len(path) == 0 {
		return "the top level"
	}
	return join(path)
}

// Hex returns a token's colour as #rrggbb.
//
// Three shapes are accepted, because three are published. 2025.10 gives a
// colour as an object with a colour space and components; earlier drafts, and
// most exports still in circulation, give a hex string; and the object form
// may also carry a hex fallback, which is the only way a colour outside sRGB
// can be read here at all.
func Hex(t Token) (string, error) {
	switch v := t.Value.(type) {
	case string:
		return normaliseHex(t.Path, v)
	case map[string]any:
		return hexFromObject(t.Path, v)
	default:
		return "", fmt.Errorf("%s is not a colour this can read", t.Path)
	}
}

func hexFromObject(path string, v map[string]any) (string, error) {
	if a, ok := v["alpha"]; ok {
		f, err := asFloat(a)
		if err == nil && f < 1 {
			return "", fmt.Errorf(
				"%s is %g transparent. A see-through colour has no one "+
					"contrast ratio — it has whatever ratio the thing behind "+
					"it gives it — and a contrast ratio is what decides "+
					"whether a page may be published here", path, 1-f)
		}
	}
	space, _ := v["colorSpace"].(string)
	hex, hasHex := v["hex"].(string)

	if space != "" && !strings.EqualFold(space, "srgb") {
		if hasHex {
			// The fallback exists for exactly this: a colour authored in a
			// wider space, carrying the sRGB value its author chose for
			// somewhere that cannot show the original.
			return normaliseHex(path, hex)
		}
		return "", fmt.Errorf(
			"%s is in %s and carries no hex fallback. Converting it would "+
				"mean choosing a substitute for a colour that is outside what "+
				"sRGB can show, and this value goes into a contrast check",
			path, space)
	}

	comps, ok := v["components"].([]any)
	if !ok || len(comps) != 3 {
		if hasHex {
			return normaliseHex(path, hex)
		}
		return "", fmt.Errorf(
			"%s has neither three sRGB components nor a hex value", path)
	}
	out := make([]int, 3)
	for i, c := range comps {
		if s, isString := c.(string); isString && s == "none" {
			// "none" is a missing component, which for a channel means zero.
			out[i] = 0
			continue
		}
		f, err := asFloat(c)
		if err != nil {
			return "", fmt.Errorf("%s: component %d is not a number", path, i+1)
		}
		out[i] = channel(f)
	}
	return fmt.Sprintf("#%02x%02x%02x", out[0], out[1], out[2]), nil
}

// channel turns a 0..1 component into 0..255, clamping rather than wrapping.
func channel(f float64) int {
	switch {
	case f <= 0:
		return 0
	case f >= 1:
		return 255
	}
	return int(f*255 + 0.5)
}

func normaliseHex(path, s string) (string, error) {
	h := strings.TrimSpace(s)
	body, found := strings.CutPrefix(h, "#")
	if !found {
		return "", fmt.Errorf(
			"%s is %q, which is not a hex colour. A named colour, rgb() and "+
				"hsl() are all refused: this value is written into a "+
				"stylesheet this site serves", path, s)
	}
	switch len(body) {
	case 3, 6:
	case 4, 8:
		// #rgba and #rrggbbaa. The alpha is the part that cannot be kept.
		if !opaque(body) {
			return "", fmt.Errorf(
				"%s is %q, which has an alpha channel. A see-through colour "+
					"has no one contrast ratio, and a contrast ratio is what "+
					"decides whether a page may be published here", path, s)
		}
		body = body[:len(body)-len(body)/4]
	default:
		return "", fmt.Errorf("%s is %q, which is not three or six hex digits",
			path, s)
	}
	for _, r := range body {
		if !isHexDigit(r) {
			return "", fmt.Errorf("%s is %q, which is not hex", path, s)
		}
	}
	return "#" + strings.ToLower(body), nil
}

// opaque reports whether the alpha digits of #rgba or #rrggbbaa are full.
func opaque(body string) bool {
	n := len(body) / 4
	a := strings.ToLower(body[len(body)-n:])
	return a == strings.Repeat("f", n)
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// Length returns a dimension as a CSS length.
//
// 2025.10 writes a dimension as an object with a value and a unit; earlier
// drafts wrote "16px". Both are here for the same reason both colour forms
// are: the files people actually have were written against both.
func Length(t Token) (string, error) {
	switch v := t.Value.(type) {
	case string:
		return strings.TrimSpace(v), nil
	case json.Number:
		// A bare number where a length belongs is almost always pixels in a
		// file that predates the unit, but "almost always" is not something to
		// write into a stylesheet.
		return "", fmt.Errorf(
			"%s is %s with no unit. Say px or rem: a bare number is a "+
				"different size depending on what reads it", t.Path, v.String())
	case map[string]any:
		unit, _ := v["unit"].(string)
		if unit == "" {
			return "", fmt.Errorf("%s is a dimension with no unit", t.Path)
		}
		n, err := asFloat(v["value"])
		if err != nil {
			return "", fmt.Errorf("%s has no numeric value", t.Path)
		}
		return trim(n) + unit, nil
	default:
		return "", fmt.Errorf("%s is not a dimension this can read", t.Path)
	}
}

// Number returns a unitless number, for a scale or a line height.
func Number(t Token) (string, error) {
	n, err := asFloat(t.Value)
	if err != nil {
		return "", fmt.Errorf("%s is not a number", t.Path)
	}
	return trim(n), nil
}

// Family returns a font family name.
//
// A fontFamily value is one name or a list in preference order. Only the first
// is taken: the rest of the stack is this program's to supply, because a
// theme's font token names a family and the fallbacks come from the site's own
// stacks.
func Family(t Token) (string, error) {
	switch v := t.Value.(type) {
	case string:
		return strings.Trim(strings.TrimSpace(v), `"'`), nil
	case []any:
		if len(v) == 0 {
			return "", fmt.Errorf("%s is an empty font stack", t.Path)
		}
		s, ok := v[0].(string)
		if !ok {
			return "", fmt.Errorf("%s starts with something that is not a name",
				t.Path)
		}
		return strings.Trim(strings.TrimSpace(s), `"'`), nil
	default:
		return "", fmt.Errorf("%s is not a font family this can read", t.Path)
	}
}

// Display is a token's value written out for somebody choosing from a list.
//
// Lossy on purpose: a composite value is shown as its type rather than as its
// contents, because the list exists to let somebody find the path of the
// colour they want, not to reproduce the file.
func Display(t Token) string {
	if s, err := Hex(t); err == nil && looksColour(t) {
		return s
	}
	switch v := t.Value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case []any:
		parts := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, ", ")
		}
	case map[string]any:
		if s, err := Length(t); err == nil {
			return s
		}
		if t.Type != "" {
			return "(" + t.Type + ")"
		}
	}
	return "(composite)"
}

func looksColour(t Token) bool {
	if t.Type == "color" {
		return true
	}
	if t.Type != "" {
		return false
	}
	s, ok := t.Value.(string)
	return ok && strings.HasPrefix(strings.TrimSpace(s), "#")
}

func asFloat(v any) (float64, error) {
	switch n := v.(type) {
	case json.Number:
		return n.Float64()
	case float64:
		return n, nil
	case int:
		return float64(n), nil
	}
	return 0, fmt.Errorf("not a number")
}

// trim writes a float without a trailing ".0", so 16 is "16" and not "16.000".
func trim(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
