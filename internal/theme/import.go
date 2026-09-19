// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package theme

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/dtcg"
)

// Bringing somebody else's design system in, without guessing which token is
// which.
//
// # Why the mapping is written down rather than inferred
//
// The temptation is to match names: a design system has a token with "primary"
// or "text" in it, this program has tokens called primary and on-surface, so
// pair them up and save everybody the typing. It would work often enough to be
// trusted and be wrong in the way that matters.
//
// Naming is where design systems differ most. One calls its page background
// "background", another "layer-01", another "elevation.surface"; one has
// "primary" meaning the brand colour and another has it meaning the main text
// colour, which is the opposite end of the contrast range. A matcher that gets
// those two the wrong way round produces a theme that is coherent, plausible,
// and inverted — and because every value came from a real design system, every
// one of them looks right in isolation.
//
// The contrast gate would catch the worst of it and not all of it, and "the
// importer guessed and the checker disagreed" is a bad error to hand somebody
// who did not make either choice. So the mapping is a file a person writes,
// once, and `theme import --list` exists to make writing it a matter of
// reading rather than of guessing.
//
// # Conversion is by this program's token, not by the file's type
//
// Which converter runs is decided by the kind of the token being filled — a
// colour is read as a colour because primary is a colour. The file's own $type
// is used to warn when the two disagree, and not to choose, because a file may
// legitimately not declare one and a mapping always names both ends.

// Mapped is one line of a mapping: a token here, a path there.
type Mapped struct {
	// Key is the theme key, which may carry a .dark or .light suffix.
	Key string
	// Path is the dotted path in the token file.
	Path string
}

// Import resolves a mapping against a token file.
//
// Returns the overrides to hand to New, and findings for everything that could
// not be read. A path that is missing or a value that cannot be converted is
// blocking: an import that silently filled half a palette would leave a site
// wearing two designs at once, and the half that stayed behind is the half
// nobody would notice.
func Import(f *dtcg.File, mapping map[string]string) (map[string]string, []Finding) {
	out := map[string]string{}
	var problems []Finding

	keys := make([]string, 0, len(mapping))
	for k := range mapping {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		path := strings.TrimSpace(mapping[key])
		if path == "" {
			continue
		}
		name := strings.TrimSpace(key)
		for _, suffix := range []string{".dark", ".light"} {
			if base, cut := strings.CutSuffix(name, suffix); cut {
				name = base
				break
			}
		}
		tok, known := Lookup(name)
		if !known {
			problems = append(problems, Finding{
				Token: name, Blocking: true,
				Detail: fmt.Sprintf(
					"the mapping fills %q, and there is no such token here. "+
						"The set is closed — `quilzo theme tokens` is the "+
						"whole list", name),
			})
			continue
		}
		src, found := f.Lookup(path)
		if !found {
			problems = append(problems, Finding{
				Token: name, Blocking: true,
				Detail: fmt.Sprintf(
					"%s is mapped to %s, and that file has no token at that "+
						"path. `quilzo theme import FILE --list` prints every "+
						"path it does have", name, path),
			})
			continue
		}
		value, err := convert(tok, src)
		if err != nil {
			problems = append(problems, Finding{
				Token: name, Blocking: true,
				Detail: fmt.Sprintf("%s is mapped to %s: %s", name, path, err),
			})
			continue
		}
		if advisory := mismatch(tok, src); advisory != "" {
			problems = append(problems, Finding{
				Token: name, Blocking: false, Detail: advisory,
			})
		}
		out[strings.TrimSpace(key)] = value
	}
	return out, problems
}

// convert reads the file's value as whatever this token holds.
func convert(tok Token, src dtcg.Token) (string, error) {
	switch tok.Kind {
	case Colour:
		return dtcg.Hex(src)
	case Length:
		return dtcg.Length(src)
	case Ratio:
		return dtcg.Number(src)
	case FontStack:
		family, err := dtcg.Family(src)
		if err != nil {
			return "", err
		}
		if stack, ok := stackLeadingWith(family); ok {
			return stack, nil
		}
		return family, nil
	}
	return "", fmt.Errorf("%s holds a %s, which cannot be imported", tok.Name, tok.Kind)
}

// stackLeadingWith finds the built-in stack whose first face is this one.
//
// A design system's font token is a whole stack — "Helvetica Neue, Helvetica,
// Arial, sans-serif" — and this program's font token holds either the name of
// a built-in stack or a face the site itself serves. Taking only the first
// name would throw away the part that matters: the fallbacks, which are what
// the page is actually set in on most of the machines that load it.
//
// So when a built-in stack leads with the same face, that stack is the answer.
// This is not a guess about which design was meant: it is an exact match on
// the face the file named first, and the built-in stack is this program's own
// way of writing down the same typeface with fallbacks it can promise. A face
// that leads no built-in stack is returned as itself, and validation then says
// whether this site serves it.
func stackLeadingWith(family string) (string, bool) {
	want := strings.ToLower(strings.TrimSpace(family))
	if want == "" {
		return "", false
	}
	names := StackNames()
	for _, name := range names {
		head, _, _ := strings.Cut(stacks[name], ",")
		head = strings.ToLower(strings.Trim(strings.TrimSpace(head), `"`))
		if head == want {
			return name, true
		}
	}
	return "", false
}

// wants is the $type a token of each kind would normally be filled from.
var wants = map[Kind][]string{
	Colour:    {"color"},
	Length:    {"dimension"},
	Ratio:     {"number"},
	FontStack: {"fontFamily"},
}

// mismatch describes a type disagreement, without stopping the import.
//
// Advisory rather than blocking because the value converted: whatever the file
// calls it, it read as the thing this token holds. A design system that types
// its line height as a dimension, or leaves $type off entirely, is not wrong
// enough to refuse — but it is worth one line, because it is also what a
// mapping that points at the wrong path looks like.
func mismatch(tok Token, src dtcg.Token) string {
	if src.Type == "" {
		return ""
	}
	for _, ok := range wants[tok.Kind] {
		if src.Type == ok {
			return ""
		}
	}
	return fmt.Sprintf(
		"%s holds a %s and %s is typed %q in that file. The value read, so "+
			"this is only worth a look: a mapping pointing one line off looks "+
			"exactly like this", tok.Name, tok.Kind, src.Path, src.Type)
}

// Export writes a theme as a design token file.
//
// The other direction, and the cheaper half: a designer asking for this site's
// tokens should not be handed a stylesheet to read by eye. The output is
// 2025.10 — colours as objects with a colour space and components, dimensions
// as a value and a unit — because that is the version tools have settled on.
//
// Both schemes are written, as two top-level groups, because a design with one
// scheme documented is a design half of its readers never see. There is no
// scheme concept in the format itself, so this is the convention every system
// that has both arrives at.
func Export(t *Theme) []byte {
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString(`  "$description": "Tokens for one Quilzo site. `)
	b.WriteString(`Design Tokens Format Module 2025.10.",` + "\n")
	for i, scheme := range []struct {
		name string
		dark bool
	}{{"light", false}, {"dark", true}} {
		fmt.Fprintf(&b, "  %q: {\n", scheme.name)
		writeGroups(&b, t, scheme.dark)
		b.WriteString("  }")
		if i == 0 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

func writeGroups(b *strings.Builder, t *Theme, dark bool) {
	// Grouped by the same groups the screens use, so somebody reading the
	// export and somebody reading `quilzo theme show` see one arrangement.
	var order []string
	byGroup := map[string][]Token{}
	for _, tok := range tokens {
		if _, seen := byGroup[tok.Group]; !seen {
			order = append(order, tok.Group)
		}
		byGroup[tok.Group] = append(byGroup[tok.Group], tok)
	}
	for gi, group := range order {
		fmt.Fprintf(b, "    %q: {\n", group)
		members := byGroup[group]
		for mi, tok := range members {
			kind, value := dtcgOf(tok, t.value(tok, dark))
			fmt.Fprintf(b, "      %q: {\n", tok.Name)
			if kind != "" {
				fmt.Fprintf(b, "        \"$type\": %q,\n", kind)
			}
			fmt.Fprintf(b, "        \"$description\": %q,\n", tok.Summary)
			fmt.Fprintf(b, "        \"$value\": %s\n", value)
			b.WriteString("      }")
			if mi < len(members)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString("    }")
		if gi < len(order)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
}

// dtcgOf writes one token as a $type and a $value.
//
// The type is empty for the values the format has no type for. That is not an
// omission to tidy up later: the format's dimension is px or rem, and this
// program's lengths include a measure in ch, letter spacing in em and a
// gradient angle in degrees, all of which are ordinary CSS and none of which
// has an equivalent there. Writing 62ch as 62px would be a number that means
// something else on every machine, and a token with no $type is legal and
// common — it is what a reader infers from the value, which is the honest
// answer when the format cannot hold the truth.
func dtcgOf(tok Token, value string) (kind, out string) {
	switch tok.Kind {
	case Colour:
		r, g, bl, ok := rgb(value)
		if !ok {
			return "color", `""`
		}
		// The hex is carried beside the components rather than instead of
		// them. Components are the form the version says to write; the hex is
		// what a tool that has not caught up will read.
		return "color", fmt.Sprintf(
			`{ "colorSpace": "srgb", "components": [%s, %s, %s], `+
				`"alpha": 1, "hex": %q }`,
			trimF(r), trimF(g), trimF(bl), strings.ToLower(value))
	case Length:
		n, unit, ok := splitLength(value)
		if !ok {
			return "", fmt.Sprintf("%q", value)
		}
		return "dimension", fmt.Sprintf(`{ "value": %s, "unit": %q }`, n, unit)
	case Ratio:
		return "number", value
	case FontStack:
		if stack, built := stacks[value]; built {
			return "fontFamily", "[" + families(stack) + "]"
		}
		return "fontFamily", fmt.Sprintf("[%q]", value)
	}
	return "", fmt.Sprintf("%q", value)
}

// splitLength separates a CSS length into its number and its unit.
//
// Only px and rem come back as a dimension: those are the two units the format
// has. A ch measure or a percentage is a real CSS length with no equivalent
// there, and writing it as px would be a number that means something else.
func splitLength(value string) (number, unit string, ok bool) {
	for _, u := range []string{"rem", "px"} {
		if n, found := strings.CutSuffix(strings.TrimSpace(value), u); found && n != "" {
			return n, u, true
		}
	}
	return "", "", false
}

func families(stack string) string {
	parts := strings.Split(stack, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		name := strings.Trim(strings.TrimSpace(p), `"`)
		if name == "" {
			continue
		}
		out = append(out, fmt.Sprintf("%q", name))
	}
	return strings.Join(out, ", ")
}

// trimF writes a 0..1 component short, since three decimals is finer than the
// 8-bit value it came from.
func trimF(f float64) string {
	s := fmt.Sprintf("%.3f", f)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

// Suggest lists the mapping keys, so a person writing one has the left-hand
// side without having to transcribe it.
func Suggest() []Mapped {
	out := make([]Mapped, 0, len(tokens)*2)
	for _, tok := range tokens {
		out = append(out, Mapped{Key: tok.Name})
		if tok.Kind == Colour {
			out = append(out, Mapped{Key: tok.Name + ".dark"})
		}
	}
	return out
}

// Two keys can name the same token in the same scheme and not be equal.
//
// A theme key is a token, optionally suffixed with the scheme it applies to:
// "primary" sets both, "primary.dark" sets one. So "primary" and
// "primary.dark" are different strings and are not different settings — they
// overlap, and whichever sorts later wins for the scheme they share.
//
// Every command that writes a theme over an existing one has to know this, and
// comparing the strings gets it wrong in the direction that does not announce
// itself: nothing clashes, so nothing is refused, so the merge happens and
// half of it has no effect. A site left like that wears one design in light
// and another in dark, and the half that did not take is the half nobody
// looks at.

// Scope is the token a theme key sets, and the schemes it reaches.
func Scope(key string) (name string, light, dark bool) {
	name = strings.TrimSpace(key)
	if base, cut := strings.CutSuffix(name, ".dark"); cut {
		return base, false, true
	}
	if base, cut := strings.CutSuffix(name, ".light"); cut {
		return base, true, false
	}
	return name, true, true
}

// Collide reports whether two theme keys set the same token in a scheme they
// share.
func Collide(a, b string) bool {
	an, al, ad := Scope(a)
	bn, bl, bd := Scope(b)
	if an != bn {
		return false
	}
	return (al && bl) || (ad && bd)
}

// Colliding returns the keys in have that are overwritten by something in
// want, whether or not the strings match.
func Colliding(have, want map[string]string) []string {
	var out []string
	for h := range have {
		for w := range want {
			if Collide(h, w) {
				out = append(out, h)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
