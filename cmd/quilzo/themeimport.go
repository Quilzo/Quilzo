// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/dtcg"
	"github.com/quilzo/quilzo/internal/theme"
)

// Taking the design system a customer already has.
//
// The question behind this is "can we look like the design system we use
// everywhere else", and the answer this program can give is better than the
// one it is usually asked for. It cannot ship a theme called Carbon or Primer
// or Polaris — those are somebody's trademarks, and two of those systems
// separately bar copying the look. It can read the token file that system
// publishes, on the machine of somebody entitled to use it, and fill its own
// tokens from it. That is not an imitation of the design; it is the design.
//
// Three commands: --list to see what a file holds, the import itself, and an
// export going the other way for a designer who wants this site's tokens in a
// form their tools read.

// MaxTokenFile bounds what is read off disk.
//
// The largest published export is about 93 KB. Four megabytes is far past any
// of them and short of anything that matters to this process.
const MaxTokenFile = 4 << 20

func themeImport(root string, args []string) error {
	pos, flags := splitThemeArgs(args)
	fs, dir := dirFlag("import", flags)
	list := fs.Bool("list", false,
		"print every token the file holds, and stop")
	skeleton := fs.String("skeleton", "",
		"write a mapping file with every key and no paths, and stop")
	mapFile := fs.String("map", "",
		"a JSON file pairing this site's tokens with paths in that file")
	scheme := fs.String("scheme", "",
		"light or dark: fill only that scheme from this file")
	replace := fs.Bool("replace", false,
		"discard the tokens this site already sets")
	var one stringList
	fs.Var(&one, "set",
		"token=path, repeatable, for a mapping too short to be worth a file")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf(
			"usage: quilzo theme import FILE [--list] [--map mapping.json] " +
				"[--set token=path] [--scheme dark]")
	}

	f, err := readTokenFile(pos[0])
	if err != nil {
		return err
	}
	if *list {
		return listTokenFile(pos[0], f)
	}
	if *skeleton != "" {
		return writeSkeleton(*skeleton)
	}

	mapping, err := buildMapping(*mapFile, one, *scheme)
	if err != nil {
		return err
	}
	if len(mapping) == 0 {
		return fmt.Errorf(
			"nothing to import: no mapping was given.\n"+
				"  This file holds %d token(s), and which of them is this "+
				"site's page background is not something to guess — design "+
				"systems disagree about names more than about anything else, "+
				"and a wrong guess reads as a real design that is inverted.\n"+
				"  See what is in there:   quilzo theme import %s --list\n"+
				"  Then map one:           quilzo theme import %s "+
				"--set primary=color.text.accent",
			f.Len(), pos[0], pos[0])
	}

	values, problems := theme.Import(f, mapping)
	for _, p := range problems {
		if p.Blocking {
			return fmt.Errorf("%s", p.Detail)
		}
	}

	existing, err := loadThemeFile(*dir)
	if err != nil {
		return err
	}
	// Not a key comparison. "primary" and "primary.dark" are different
	// strings and the same setting for the dark scheme, so comparing the
	// strings finds no clash, writes both, and leaves whichever sorts later
	// silently in charge.
	clash := theme.Colliding(existing, values)
	if len(clash) > 0 && !*replace {
		return fmt.Errorf(
			"this site already sets %d of the tokens being imported, starting "+
				"with %s.\n  Importing would discard them. Say so if that is "+
				"what you mean: --replace", len(clash), clash[0])
	}

	next := map[string]string{}
	for k, v := range existing {
		next[k] = v
	}
	// Dropped rather than written over. --replace says to discard what is
	// there, and a key this import overlaps but does not equal would otherwise
	// survive and keep the scheme it still covers — half the old design, in
	// the half of the site fewer people look at.
	for _, k := range clash {
		delete(next, k)
	}
	for k, v := range values {
		next[k] = v
	}

	fonts, ferr := loadFontsFor(*dir)
	if ferr != nil {
		return ferr
	}
	// Through the same door a hand-written theme goes through. An imported
	// value is not more trusted for having come from a design system with a
	// reputation: the pattern match and the contrast check are the reason a
	// theme here cannot produce a page nobody can read, and skipping them for
	// an import would be skipping them for the largest change anybody makes.
	blocking, invalid := blockingFor(next, fonts)
	if invalid != nil {
		return invalid
	}
	if len(blocking) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "the imported theme fails %d contrast check(s):\n",
			len(blocking))
		for _, c := range blocking {
			fmt.Fprintf(&b, "  %s\n", c.Detail)
		}
		b.WriteString(reasonFor(blocking, mapping, values, existing, fonts, pos[0]))
		return fmt.Errorf("%s", b.String())
	}

	if err := writeThemeFile(*dir, next); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("theme.import", "/",
		audit.Success, map[string]string{
			// "filled" rather than "tokens": the audit package refuses a
			// detail key containing "token", because that is what a
			// credential is usually called, and it refuses the whole record
			// rather than redacting — so the wrong name here means the import
			// happens and nothing records it.
			"file": filepath.Base(pos[0]), "filled": fmt.Sprint(len(values)),
		}))

	// A palette that passes in both schemes because it is the same palette in
	// both is a thing this can notice and should say. It is not a failure —
	// light text on a light ground reads fine in the dark scheme too — it is
	// a site with no dark design, which is a choice somebody should make on
	// purpose rather than discover.
	shared := 0
	written, _ := theme.New(next, fonts)
	for key := range values {
		name, _, _ := theme.Scope(key)
		tok, ok := theme.Lookup(name)
		if !ok || tok.Kind != theme.Colour {
			continue
		}
		light, _ := written.Value(name, false)
		dark, _ := written.Value(name, true)
		if light == dark {
			shared++
		}
	}
	if w.JSON(map[string]any{
		"file": pos[0], "imported": len(values),
		"advisories": len(problems), "shared": shared,
	}) {
		return nil
	}
	w.Human("%s%d token(s) imported from %s%s\n",
		bold, len(values), filepath.Base(pos[0]), reset)
	for _, a := range problems {
		w.Human("  %s%s%s\n", yellow, a.Detail, reset)
	}
	w.Human("  %severy contrast pair checked, in both schemes%s\n", dim, reset)
	if shared > 0 {
		w.Human("\n  %s%d colour(s) are now the same in both schemes, so the "+
			"dark scheme is showing the light palette.%s\n", yellow, shared, reset)
		w.Human("  %sThe format has no way to say which scheme a file is "+
			"for. If this one is half a pair, import the other half:%s\n",
			dim, reset)
		w.Human("  %squilzo theme import FILE --map ... --scheme dark%s\n",
			dim, reset)
	}
	w.Human("\n  %ssee it:  quilzo theme show%s\n", dim, reset)
	return nil
}

// blockingFor validates a set of overrides and returns what fails contrast.
//
// The second return is a refusal of the values themselves — a colour that is
// not a colour — which is a different thing from a palette that is legal and
// unreadable, and wants a different message.
func blockingFor(values map[string]string, fonts []theme.Family) ([]theme.Finding, error) {
	th, invalid := theme.New(values, fonts)
	for _, p := range invalid {
		if p.Blocking {
			return nil, fmt.Errorf("%s", p.Detail)
		}
	}
	var blocking []theme.Finding
	for _, c := range th.Check() {
		if c.Blocking {
			blocking = append(blocking, c)
		}
	}
	return blocking, nil
}

// reasonFor says which of the two ways this goes wrong happened.
//
// There are two, and they want opposite advice. The first is that the file
// held one scheme and its colours were used for both, so one scheme is now
// wearing the other's palette. The second is a mapping a line off, which puts
// the page background where the body text goes.
//
// They look identical from the findings alone, and the first guess at telling
// them apart — every failure is in one scheme, so it must be the schemes — is
// wrong often enough to be worse than saying nothing. An inverted mapping
// against a site whose other scheme was already set produces exactly that
// shape.
//
// So this does not guess. The scheme explanation makes a claim that can be
// tested — that these colours are fine in the scheme they did not fail in —
// and the checker is arithmetic over hex values, so testing it costs nothing.
// Run it, and say the thing that is true.
func reasonFor(blocking []theme.Finding, mapping, values, existing map[string]string,
	fonts []theme.Family, file string) string {
	const mismapped = "  Nothing was written. Every value in it is a real " +
		"colour from a real palette, so this is the pairing rather than the " +
		"design system: a mapping one line off puts the page background " +
		"where the body text goes, and each half looks right on its own.\n" +
		"  Check the two ends:  quilzo theme import FILE --list"

	for k := range mapping {
		if strings.HasSuffix(k, ".dark") || strings.HasSuffix(k, ".light") {
			return mismapped
		}
	}
	failed := ""
	for _, f := range blocking {
		if f.Scheme == "" || (failed != "" && failed != f.Scheme) {
			return mismapped
		}
		failed = f.Scheme
	}
	if failed == "" {
		return mismapped
	}
	works := "light"
	if failed == "light" {
		works = "dark"
	}

	// The claim: confined to the scheme they did not fail in, these colours
	// are fine. Tested rather than assumed.
	narrowed := map[string]string{}
	for k, v := range existing {
		narrowed[k] = v
	}
	confined := map[string]string{}
	for k, v := range values {
		name := strings.TrimSpace(k)
		if tok, ok := theme.Lookup(name); ok && tok.Kind != theme.Colour {
			confined[name] = v
			continue
		}
		confined[name+"."+works] = v
	}
	for _, k := range theme.Colliding(narrowed, confined) {
		delete(narrowed, k)
	}
	for k, v := range confined {
		narrowed[k] = v
	}
	still, err := blockingFor(narrowed, fonts)
	if err != nil || len(still) > 0 {
		return mismapped
	}
	// Stated as the fact it is rather than as a verdict. Two things produce
	// exactly this and both are fixed the same way: a file holding one scheme
	// that was used for both, and a mapping with a light token and a dark one
	// swapped — because a swapped light palette is a working dark one, which
	// is not a mistake this can see and is a real possibility worth naming.
	return fmt.Sprintf(
		"  Nothing was written. Every failure is in the %s scheme, the "+
			"mapping names no scheme — so these colours were used for both — "+
			"and confined to %s alone every pair passes, which was checked "+
			"just now rather than assumed.\n"+
			"  So this file is a %s palette. Either it is the %s half of a "+
			"design system that ships its schemes separately, which the "+
			"format has no way to say, or two of the paths in the mapping "+
			"are the wrong way round. Both are fixed by saying which scheme "+
			"it is:\n"+
			"    quilzo theme import %s --map ... --scheme %s",
		failed, works, works, works, file, works)
}

// writeSkeleton writes a mapping with every key and no paths.
//
// The friction in this feature is not the idea, it is typing thirty-odd names
// correctly before anything happens at all. So the left-hand side is written
// out, an operator fills in the paths for the ones they care about, and a line
// left empty is skipped rather than refused — which makes a partial mapping a
// usable thing rather than an error to work through.
func writeSkeleton(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf(
			"%s is already there. A skeleton overwriting a mapping somebody "+
				"has filled in would be the worst moment to lose it", path)
	}
	var b strings.Builder
	b.WriteString("{\n")
	keys := theme.Suggest()
	for i, m := range keys {
		key, _ := json.Marshal(m.Key)
		fmt.Fprintf(&b, "  %s: \"\"", key)
		if i < len(keys)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return err
	}
	w.Human("%s%d key(s) written to %s%s\n", bold, len(keys), path, reset)
	w.Human("  %sfill in the paths you want and leave the rest empty; an "+
		"empty line is skipped%s\n", dim, reset)
	w.Human("  %squilzo theme import FILE --list   the right-hand side%s\n",
		dim, reset)
	return nil
}

// listTokenFile prints what a file holds.
//
// The whole point of the command: a mapping is written by reading this, and
// the alternative is reading somebody's 93 KB export by eye.
func listTokenFile(path string, f *dtcg.File) error {
	all := f.Tokens()
	if w.JSON(rowsOf(all)) {
		return nil
	}
	w.Human("%s%d token(s) in %s%s\n\n", bold, len(all), filepath.Base(path), reset)
	for _, t := range all {
		kind := t.Type
		if kind == "" {
			kind = "untyped"
		}
		w.Human("%s%-44s%s %s%-11s%s %s\n",
			bold, t.Path, reset, dim, kind, reset, dtcg.Display(t))
	}
	w.Human("\n  %sa mapping pairs one of these paths with a token here:%s\n",
		dim, reset)
	w.Human("  %squilzo theme tokens        the left-hand side%s\n", dim, reset)
	w.Human("  %squilzo theme import %s --set primary=PATH%s\n",
		dim, filepath.Base(path), reset)
	w.Human("  %squilzo theme import %s --skeleton pairs.json   all of them, "+
		"to fill in%s\n", dim, filepath.Base(path), reset)
	return nil
}

func rowsOf(all []dtcg.Token) []map[string]string {
	out := make([]map[string]string, 0, len(all))
	for _, t := range all {
		out = append(out, map[string]string{
			"path": t.Path, "type": t.Type, "value": dtcg.Display(t),
			"description": t.Description,
		})
	}
	return out
}

// readTokenFile reads and parses, bounded.
func readTokenFile(path string) (*dtcg.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if info.Size() > MaxTokenFile {
		return nil, fmt.Errorf(
			"%s is %d bytes. The largest design system export published is "+
				"about 93 KB, so this is not one of those", path, info.Size())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	f, err := dtcg.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// buildMapping merges a mapping file with any --set pairs.
//
// --set wins, because it is the thing somebody typed on this run, and a flag
// that a file silently overrode would be a flag nobody could use to try
// something.
func buildMapping(path string, sets stringList, scheme string) (map[string]string, error) {
	out := map[string]string{}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading the mapping %s: %w", path, err)
		}
		var pairs map[string]string
		if err := json.Unmarshal(raw, &pairs); err != nil {
			return nil, fmt.Errorf(
				"%s is not a mapping. It is a JSON object pairing a token "+
					"here with a path there: "+
					`{"primary": "color.text.accent"}: %w`, path, err)
		}
		for k, v := range pairs {
			// A line left empty is a line somebody has not filled in, which
			// is the whole shape of a skeleton straight off the disk.
			// Counting it would make an untouched skeleton look like sixty
			// requests, and the command would then quietly do nothing
			// instead of saying there is nothing to do.
			if strings.TrimSpace(v) == "" {
				continue
			}
			out[k] = v
		}
	}
	for _, s := range sets {
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not token=path", s)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}

	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "":
	case "light", "dark":
		// Two files is how a design system with two schemes usually ships, so
		// this is the flag that makes importing the second one one command
		// rather than a rewritten mapping. Only a colour has two schemes; a
		// radius suffixed .dark is refused downstream, so it is left alone
		// here rather than suffixed into an error.
		suffixed := make(map[string]string, len(out))
		for k, v := range out {
			name := strings.TrimSpace(k)
			if strings.HasSuffix(name, ".dark") || strings.HasSuffix(name, ".light") {
				suffixed[name] = v
				continue
			}
			if tok, ok := theme.Lookup(name); ok && tok.Kind != theme.Colour {
				suffixed[name] = v
				continue
			}
			suffixed[name+"."+strings.ToLower(scheme)] = v
		}
		out = suffixed
	default:
		return nil, fmt.Errorf(
			"--scheme is light or dark, not %q. Leave it off to fill both "+
				"from one file", scheme)
	}
	return out, nil
}

func themeExport(args []string) error {
	fs, dir := dirFlag("export", args)
	out := fs.String("out", "",
		"write here rather than to standard output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	values, err := loadThemeFile(*dir)
	if err != nil {
		return err
	}
	fonts, ferr := loadFontsFor(*dir)
	if ferr != nil {
		return ferr
	}
	th, problems := theme.New(values, fonts)
	for _, p := range problems {
		if p.Blocking {
			return fmt.Errorf("%s", p.Detail)
		}
	}
	b := theme.Export(th)
	if *out == "" {
		_, werr := os.Stdout.Write(b)
		return werr
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	w.Human("%s%d token(s) written to %s%s\n",
		bold, len(theme.Tokens())*2, *out, reset)
	w.Human("  %sboth schemes, as Design Tokens Format Module 2025.10%s\n",
		dim, reset)
	return nil
}

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ", ") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

var _ flag.Value = (*stringList)(nil)
