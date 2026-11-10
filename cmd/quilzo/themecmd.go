// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/starter"
	"github.com/quilzo/quilzo/internal/theme"
)

// The theme is the part of the design an operator owns.
//
// # Why a command rather than a stylesheet they edit
//
// Because a stylesheet cannot be checked. The tool that refuses to publish an
// image with no alternative text would happily publish grey-on-grey body text,
// and the reason it would is that contrast used to live somewhere the tool could
// not see. It does not any more: the values come through here, they are matched
// against a pattern rather than cleaned, and the contrast of every text pair is
// arithmetic this can do before anything is served.
//
// Editing the file by hand is still supported and does the same thing — the file
// is the state, this is a way to write it that tells you when you have made
// something unreadable.

func cmdTheme(root string, args []string) error {
	if len(args) == 0 {
		// The entry the privilege gate reads for a bare `quilzo theme`.
		args = []string{bareRuns["theme"]}
	}
	switch args[0] {
	case "show":
		return themeShow(args[1:])
	case "tokens":
		return themeTokens(args[1:])
	case "set":
		return themeSet(root, args[1:])
	case "unset":
		return themeUnset(root, args[1:])
	case "check":
		return themeCheck(args[1:])
	case "fonts":
		return themeFonts(args[1:])
	case "font":
		return themeFont(root, args[1:])
	case "css":
		return themeCSS(args[1:])
	case "apply":
		return themeApply(root, args[1:])
	case "generate":
		return themeGenerate(root, args[1:])
	case "import":
		return themeImport(root, args[1:])
	case "export":
		return themeExport(args[1:])
	case "styles":
		// The choices, for a script as well as a person: a site package or a
		// builder that names a style, a corner or a scheme needs to know
		// which there are, and this printed nothing under --json.
		if w.JSON(map[string]any{
			"styles":  namedChoices(theme.Styles, theme.StyleWords),
			"corners": namedChoices(theme.Corners, theme.CornerWords),
			"schemes": namedChoices(theme.SchemeChoices, theme.SchemeWords),
			"motions": theme.Motions,
		}) {
			return nil
		}
		for _, st := range theme.Styles {
			w.Human("  %s%-11s%s %s\n", bold, st, reset, theme.StyleWords[st])
		}
		w.Human("\n  %scorners%s\n", bold, reset)
		for _, c := range theme.Corners {
			w.Human("  %s%-11s%s %s\n", bold, c, reset, theme.CornerWords[c])
		}
		w.Human("\n  %sschemes%s\n", bold, reset)
		for _, sc := range theme.SchemeChoices {
			w.Human("  %s%-11s%s %s\n", bold, sc, reset, theme.SchemeWords[sc])
		}
		w.Human("\n  quilzo theme set style NAME; quilzo theme set motion subtle|expressive|none\n")
		w.Human("  quilzo theme set corner round|chamfer; quilzo theme set scheme both|dark|light\n")
		return nil
	case "layer":
		return themeLayer(root, args[1:])
	default:
		return fmt.Errorf("unknown theme command %q; try show, tokens, set, "+
			"unset, check, fonts, font add, css, apply, generate, import, export, "+
			"styles or layer", args[0])
	}
}

// dirFlag is the one flag every theme subcommand takes.
func dirFlag(name string, args []string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	dir := fs.String("dir", "templates", "where the theme and layouts live")
	return fs, dir
}

func themeShow(args []string) error {
	fs, dir := dirFlag("show", args)
	dark := fs.Bool("dark", false, "show the dark scheme's values")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := loadDesign(*dir)
	if err != nil {
		return err
	}

	type row struct {
		Token      string `json:"token"`
		Value      string `json:"value"`
		Group      string `json:"group"`
		Overridden bool   `json:"overridden"`
		Summary    string `json:"summary"`
	}
	rows := []row{}
	for _, tok := range theme.Tokens() {
		v, set := d.Theme.Value(tok.Name, *dark)
		rows = append(rows, row{tok.Name, v, tok.Group, set, tok.Summary})
	}
	if w.JSON(map[string]any{
		"scheme": schemeName(*dark), "tokens": rows,
		"own_stylesheet": d.OwnStylesheet,
		"fonts":          d.Fonts.Names(),
		"layouts":        d.Layouts.Names(),
	}) {
		return nil
	}

	w.Human("%stheme%s  %s%s scheme · %s%s\n\n", bold, reset, dim,
		schemeName(*dark), *dir, reset)

	group := ""
	for _, r := range rows {
		if r.Group != group {
			group = r.Group
			w.Human("%s%s%s\n", bold, group, reset)
		}
		marker := " "
		if r.Overridden {
			marker = "*"
		}
		w.Human("  %s %-26s %-32s %s%s%s\n", marker, r.Token, r.Value,
			dim, trim(r.Summary, 44), reset)
	}
	w.Human("\n  %s* set by this site; everything else is the shipped default%s\n",
		dim, reset)
	w.Human("  %slayouts: %s%s\n", dim, strings.Join(d.Layouts.Names(), ", "), reset)
	if names := d.Fonts.Names(); len(names) > 0 {
		w.Human("  %sfonts:   %s%s\n", dim, strings.Join(names, ", "), reset)
	}
	if d.OwnStylesheet {
		w.Human("\n  %s%s exists, so it is served as written and none of these "+
			"values are in effect.%s\n", dim, filepath.Join(*dir, "site.css"), reset)
	}
	if d.LayerServed {
		w.Human("  %sstyle layer: %s, %d bytes, served over the generated stylesheet%s\n",
			dim, filepath.Join(*dir, theme.LayerFile), len(d.Layer), reset)
	}
	for _, note := range d.Notes {
		w.Human("  %s%s%s\n", dim, note, reset)
	}
	return nil
}

// themeTokens is the closed list, with what each one does. Printed rather than
// documented elsewhere, because a knob nobody can find is a knob nobody uses.
func themeTokens(args []string) error {
	fs := flag.NewFlagSet("tokens", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	tokens := theme.Tokens()
	if w.JSON(tokens) {
		return nil
	}
	group := ""
	for _, t := range tokens {
		if t.Group != group {
			group = t.Group
			w.Human("\n%s%s%s\n", bold, group, reset)
		}
		w.Human("  %-26s %s%-8s%s %s\n", t.Name, dim, t.Kind, reset,
			wrapIndent(t.Summary, 44, 38))
		if t.Kind == theme.Colour {
			w.Human("  %s%-26s light %s · dark %s%s\n", dim, "", t.Light, t.Dark, reset)
		} else {
			w.Human("  %s%-26s %s%s\n", dim, "", t.Light, reset)
		}
	}
	w.Human("\n%sfont stacks%s %s(built in, already on the reader's device)%s\n",
		bold, reset, dim, reset)
	w.Human("  %s%s%s\n", dim, wrapIndent(strings.Join(theme.StackNames(), ", "), 70, 2), reset)
	w.Human("\n  %sa colour takes one value per scheme:%s\n", dim, reset)
	w.Human("    %squilzo theme set primary '#0b4f6c' primary.dark '#8ecfe8'%s\n",
		dim, reset)
	return nil
}

func themeSet(root string, args []string) error {
	pos, flags := splitThemeArgs(args)
	fs, dir := dirFlag("set", flags)
	force := fs.Bool("force", false,
		"save even though the result fails the contrast check")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) == 0 || len(pos)%2 != 0 {
		return fmt.Errorf("usage: quilzo theme set TOKEN VALUE [TOKEN VALUE …]")
	}

	existing, err := loadThemeFile(*dir)
	if err != nil {
		return err
	}
	next := map[string]string{}
	for k, v := range existing {
		next[k] = v
	}
	for i := 0; i < len(pos); i += 2 {
		next[strings.TrimSpace(pos[i])] = strings.TrimSpace(pos[i+1])
	}

	fonts, ferr := loadFontsFor(*dir)
	if ferr != nil {
		return ferr
	}
	th, problems := theme.New(next, fonts)
	for _, p := range problems {
		if p.Blocking {
			// A malformed value is refused rather than saved and ignored. The
			// alternative is a theme file with a line in it that does nothing,
			// which is indistinguishable from a setting that did not work.
			return fmt.Errorf("%s", p.Detail)
		}
	}

	findings := th.Check()
	blocking := 0
	for _, f := range findings {
		if f.Blocking {
			blocking++
		}
	}
	if blocking > 0 && !*force {
		w.Human("%s%d contrast failure(s)%s\n\n", bold, blocking, reset)
		for _, f := range findings {
			if f.Blocking {
				w.Human("  %s\n\n", wrapIndent(f.Detail, 72, 4))
			}
		}
		return fmt.Errorf(
			"not saved. These are the ratios a reader gets, and this is the " +
				"same standard the publish gate holds a page to.\n" +
				"  Adjust the colours, or pass --force to save it and be " +
				"refused at publish instead")
	}

	if err := writeThemeFile(*dir, next); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("theme.set", "/",
		audit.Success, map[string]string{"changed": fmt.Sprint(len(pos) / 2)}))

	for i := 0; i < len(pos); i += 2 {
		w.Human("%s%s%s = %s\n", bold, pos[i], reset, pos[i+1])
	}
	reportAdvisories(findings)
	if blocking > 0 {
		w.Human("\n  %s%d contrast failure(s) saved with --force; the publish "+
			"gate will refuse them%s\n", bold, blocking, reset)
	}
	// The veil over a backdrop is judged apart from the palette and refuses
	// only a page that has a backdrop, so it is not a reason to refuse this
	// change. It is said here all the same: `theme set scrim-strength 10%`
	// was answered with the new value and nothing else, and the first anybody
	// heard of it was a page refused at publish.
	if theme.Blocks(th.CheckBackdrop()) {
		w.Human("\n  %swords over a backdrop picture or video are now below their ratio, "+
			"so a page with a backdrop will not publish; `quilzo theme check` says "+
			"which and by how much%s\n", bold, reset)
	}
	schemes := "both schemes"
	if sc := th.Scheme(); sc != "both" {
		schemes = "the " + sc + " scheme it is drawn in"
	}
	w.Human("\n  %squilzo theme check   the whole palette, %s%s\n",
		dim, schemes, reset)
	sayWhenReadersSeeIt()
	return nil
}

// sayWhenReadersSeeIt says when a change to the design reaches readers.
//
// The admin's preview reads templates/ again as soon as it changes, and the
// public site takes the design with its next publish, after the gate has
// checked it (designreload.go). A command that saved a palette and said
// nothing more left somebody refreshing the live site for a change that was
// waiting for them to publish, and the cure people reached for was the one
// that used to be needed: restarting the server.
func sayWhenReadersSeeIt() {
	w.Human("  %sthe admin's preview has it now; the site serves it from its next publish%s\n",
		dim, reset)
}

func themeUnset(root string, args []string) error {
	pos, flags := splitThemeArgs(args)
	fs, dir := dirFlag("unset", flags)
	all := fs.Bool("all", false, "remove every override, back to the shipped palette")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	existing, err := loadThemeFile(*dir)
	if err != nil {
		return err
	}
	if *all {
		if err := writeThemeFile(*dir, nil); err != nil {
			return err
		}
		w.Human("removed every override; the shipped palette is in effect\n")
		record(root, resolveCaller(root, "").auditRecord("theme.unset", "/",
			audit.Success, map[string]string{"removed": "all"}))
		sayWhenReadersSeeIt()
		return nil
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: quilzo theme unset TOKEN [TOKEN …] | --all")
	}
	for _, name := range pos {
		name = strings.TrimSpace(name)
		if _, present := existing[name]; !present {
			w.Human("  %s%s was not set%s\n", dim, name, reset)
			continue
		}
		delete(existing, name)
		w.Human("unset %s%s%s\n", bold, name, reset)
	}
	if err := writeThemeFile(*dir, existing); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("theme.unset", "/",
		audit.Success, map[string]string{"removed": strings.Join(pos, ",")}))
	sayWhenReadersSeeIt()
	return nil
}

// themeCheck is the contrast report, in both schemes.
//
// Both, always. A site checked in light and served in dark to half its readers
// is checked for half its readers, and dark is the palette that gets less
// looking at.
func themeCheck(args []string) error {
	fs, dir := dirFlag("check", args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := loadDesign(*dir)
	if err != nil {
		return err
	}
	findings := d.Theme.Check()
	// The layer's findings go with the palette's: a refused rule leaves the
	// whole layer out, which is a thing this site does not have until it is
	// fixed, and a script reading the answer needs to see it.
	layerRefused := theme.Blocks(d.LayerFindings) && !d.OwnStylesheet
	// So do the veil's, which the prose reports and the document left out.
	// They refuse only a page with a backdrop, which this command cannot
	// see, so they are advisories here, as the exit status treats them.
	doc := append(append([]theme.Finding{}, findings...), d.LayerFindings...)
	for _, f := range d.Theme.CheckBackdrop() {
		if f.Blocking {
			f.Blocking = false
			doc = append(doc, f)
		}
	}
	if w.JSON(doc) {
		// The status says what the prose says: a pair below its ratio fails
		// the check, as a refused layer does. It exited 0 for the first and 1
		// for the second, so a script reading the status alone passed a
		// palette the publish gate refuses.
		if n := blockingCount(findings); n > 0 {
			return fmt.Errorf("%d text pair(s) below the ratio a reader needs", n)
		}
		if layerRefused {
			return fmt.Errorf("the style layer is refused and is not served")
		}
		return nil
	}
	if d.OwnStylesheet {
		w.Human("%s%s is served as written, so these values are not in "+
			"effect and this check does not cover what readers get.%s\n\n",
			dim, filepath.Join(*dir, "site.css"), reset)
	}

	blocking := 0
	for _, f := range findings {
		if f.Blocking {
			blocking++
		}
	}
	schemes := "in both schemes"
	if sc := d.Theme.Scheme(); sc != "both" {
		schemes = "in the " + sc + " scheme, the only one this site is drawn in"
	}
	if blocking == 0 {
		w.Human("%severy text pair meets its ratio, %s%s\n", bold, schemes, reset)
	} else {
		w.Human("%s%d contrast failure(s)%s\n\n", bold, blocking, reset)
		for _, f := range findings {
			if f.Blocking {
				w.Human("  [%s] %s\n\n", f.Scheme, wrapIndent(f.Detail, 70, 4))
			}
		}
	}
	reportAdvisories(findings)
	reportBackdrop(d.Theme)
	reportLayer(*dir, d)
	w.Human("\n  %swhat is not checked: whether the palette is any good, "+
		"anything a colour outside the theme does, and in a style layer, a "+
		"colour pair split across two rules, text faded by opacity, or a rule "+
		"that hides the veil over a backdrop%s\n", dim, reset)
	if blocking > 0 {
		return fmt.Errorf("%d text pair(s) below the ratio a reader needs", blocking)
	}
	if layerRefused {
		return fmt.Errorf("the style layer is refused and is not served")
	}
	return nil
}

// reportBackdrop says whether words over a backdrop are readable with this
// site's veil. Not an error here: it refuses only a page with a backdrop,
// and the publish gate is what knows which pages those are.
func reportBackdrop(th *theme.Theme) {
	over := th.CheckBackdrop()
	if !theme.Blocks(over) {
		w.Human("\n  %sover a backdrop picture or video: readable at worst, with the "+
			"veil at %s%s\n", dim, themeValue(th, "scrim-strength"), reset)
		return
	}
	w.Human("\n%sover a backdrop picture or video%s %s(a page with a backdrop will "+
		"not publish until this passes)%s\n", bold, reset, dim, reset)
	for _, f := range over {
		w.Human("  [%s] %s\n", f.Scheme, wrapIndent(f.Detail, 70, 4))
	}
}

// reportLayer says what the style layer is and whether it is served.
func reportLayer(dir string, d *Design) {
	if d.Layer == "" {
		return
	}
	path := filepath.Join(dir, theme.LayerFile)
	switch {
	case d.OwnStylesheet:
		w.Human("\n  %s%s is not served: site.css replaces everything it would sit on%s\n", dim, path, reset)
		return
	case d.LayerServed:
		w.Human("\n  %sstyle layer %s: %d bytes, every colour a token, served%s\n", dim, path, len(d.Layer), reset)
	default:
		w.Human("\n%sstyle layer %s is refused and not served%s\n", bold, path, reset)
	}
	for _, f := range d.LayerFindings {
		sev := "advisory"
		if f.Blocking {
			sev = "refused"
		}
		w.Human("  [%s] %s\n", sev, wrapIndent(f.Detail, 70, 4))
	}
}

// namedChoices is a list of choices with what each does, in their order.
func namedChoices(names []string, words map[string]string) []map[string]string {
	out := make([]map[string]string, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]string{"name": n, "words": words[n]})
	}
	return out
}

// layerDoc is what `theme layer --json` answers with: where the layer is,
// how big, whether it is served, and every finding, as a list even when there
// are none, so a script reads one shape.
func layerDoc(path string, size int, served bool, findings []theme.Finding) map[string]any {
	if findings == nil {
		findings = []theme.Finding{}
	}
	return map[string]any{"path": path, "bytes": size, "served": served,
		"refused": blockingCount(findings), "findings": findings}
}

// themeValue is one token's value as a site has it.
func themeValue(th *theme.Theme, name string) string {
	v, _ := th.Value(name, false)
	return v
}

// themeLayer shows, sets or takes away a site's style layer.
//
// The file is the state, as theme.json is: editing templates/style.css by
// hand is supported, and `theme check` says what is wrong with it. This is
// the way to put one in that refuses a layer the site would not serve,
// before it replaces the one that is there.
func themeLayer(root string, args []string) error {
	sub := "show"
	if len(args) > 0 && !reFlag.MatchString(args[0]) {
		sub, args = args[0], args[1:]
	}
	pos, flags := splitThemeArgs(args)
	fs, dir := dirFlag("layer", flags)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	// Words after the flags are a command written flags first, as
	// `theme layer --dir DIR set FILE`. That used to show the layer that was
	// there, so somebody who asked to set one read a report of the old one
	// and the file they meant was never checked or saved.
	if fs.NArg() > 0 {
		return fmt.Errorf("%q comes after the flags; write it first: "+
			"quilzo theme layer [set FILE | unset] [--dir DIR]", strings.Join(fs.Args(), " "))
	}
	path := filepath.Join(*dir, theme.LayerFile)
	// A style layer is CSS served on every page at once, including pages the
	// person changing it may not edit, so changing one takes the authority
	// installing a design takes — here as on the Design screen. Asked here
	// rather than in the privilege table, where a subcommand may only narrow
	// what its command needs; reading the layer is the theme's own.
	if sub == "set" || sub == "unset" {
		if err := authorise(root, resolveCaller(root, flagToken), auth.ActPublish, "/"); err != nil {
			return fmt.Errorf("a style layer is served on every page, which needs whoever may publish: %w", err)
		}
	}
	switch sub {
	case "show":
		d, err := loadDesign(*dir)
		if err != nil {
			return err
		}
		if w.JSON(layerDoc(path, len(d.Layer), d.LayerServed, d.LayerFindings)) {
			return nil
		}
		if d.Layer == "" {
			w.Human("%sno style layer%s\n\n", bold, reset)
			w.Human("  %sCSS of this site's own, served after the generated stylesheet and held to%s\n", dim, reset)
			w.Human("  %sthe rule the shipped styles keep: every colour a token, as var(--primary)%s\n", dim, reset)
			w.Human("  %sor color-mix() of tokens; url() only to /media/ and /fonts/; no @import,%s\n", dim, reset)
			w.Human("  %sno !important, no redefining a token, no removing the focus outline.%s\n\n", dim, reset)
			w.Human("  %squilzo theme layer set FILE   check one and put it in %s%s\n", dim, path, reset)
			return nil
		}
		reportLayer(*dir, d)
		return nil
	case "set":
		if len(pos) != 1 {
			return fmt.Errorf("usage: quilzo theme layer set FILE [--dir DIR]")
		}
		info, err := os.Stat(pos[0])
		if err != nil {
			return err
		}
		if info.Size() > theme.MaxLayer {
			return fmt.Errorf("%s is %d bytes, and a style layer may be at most %d",
				pos[0], info.Size(), theme.MaxLayer)
		}
		b, err := os.ReadFile(pos[0])
		if err != nil {
			return err
		}
		d, err := loadDesign(*dir)
		if err != nil {
			return err
		}
		findings := theme.CheckLayer(string(b), d.Theme)
		if theme.Blocks(findings) {
			// The refused rules are the answer a script needs, so they are the
			// document on stdout and the refusal is the error, as `theme
			// check --json` does: an error alone said how many and not which.
			w.JSON(layerDoc(path, len(b), false, findings))
			w.Human("%snot saved%s %s(it would not be served)%s\n\n", bold, reset, dim, reset)
			for _, f := range findings {
				if f.Blocking {
					w.Human("  %s\n\n", wrapIndent(f.Detail, 72, 4))
				}
			}
			return fmt.Errorf("%d rule(s) in %s are refused", blockingCount(findings), pos[0])
		}
		// Atomically, as the browser and a site package write it: a server
		// starting while this writes reads the old layer or the new one.
		if err := atomicfile.Write(path, b, 0o600); err != nil {
			return err
		}
		record(root, resolveCaller(root, "").auditRecord("theme.layer.set", "/",
			audit.Success, map[string]string{"bytes": fmt.Sprint(len(b))}))
		doc := layerDoc(path, len(b), !d.OwnStylesheet, findings)
		doc["saved"] = true
		if w.JSON(doc) {
			return nil
		}
		w.Human("%sstyle layer saved%s %s(%s, %d bytes)%s\n", bold, reset, dim, path, len(b), reset)
		for _, f := range findings {
			w.Human("  %s%s%s\n", dim, wrapIndent(f.Detail, 70, 4), reset)
		}
		if d.OwnStylesheet {
			w.Human("  %sit is not served while %s exists: that file replaces everything a layer sits on%s\n",
				dim, filepath.Join(*dir, "site.css"), reset)
			return nil
		}
		// When, as every change to the design says it: the site reads the
		// layer with the rest of templates/, with its next publish.
		sayWhenReadersSeeIt()
		return nil
	case "unset":
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				if w.JSON(map[string]any{"path": path, "removed": false}) {
					return nil
				}
				w.Human("  %sthere is no style layer%s\n", dim, reset)
				return nil
			}
			return err
		}
		record(root, resolveCaller(root, "").auditRecord("theme.layer.unset", "/",
			audit.Success, map[string]string{"layer": theme.LayerFile}))
		if w.JSON(map[string]any{"path": path, "removed": true}) {
			return nil
		}
		// When, as setting one says: the running site serves the layer it
		// read with the last publish until the next one.
		w.Human("took the style layer away; the generated stylesheet is served alone\n")
		sayWhenReadersSeeIt()
		return nil
	}
	return fmt.Errorf("unknown theme layer command %q; try show, set FILE or unset", sub)
}

// themeFonts lists the faces this site serves and how to add one.
func themeFonts(args []string) error {
	fs, dir := dirFlag("fonts", args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	set, err := loadFontSet(*dir)
	if err != nil {
		return err
	}
	faces := set.Faces()
	if w.JSON(faces) {
		return nil
	}
	fontsDir := filepath.Join(*dir, "fonts")
	if len(faces) == 0 {
		w.Human("%sno fonts of your own%s\n\n", bold, reset)
		// What is in the directory and not served comes first: it is the
		// answer to "why is my font not there", which is why somebody runs
		// this with a file in the directory. It came only after a list of
		// faces, so a directory whose one file was refused said nothing.
		for _, note := range set.Warnings {
			w.Human("  %s%s%s\n", yellow, wrapIndent(note, 70, 2), reset)
		}
		if len(set.Warnings) > 0 {
			w.Human("\n")
		}
		w.Human("  %sPut a .woff2 or .woff in %s and it is served from this origin at%s\n",
			dim, fontsDir, reset)
		w.Human("  %s/fonts/NAME.woff2 (or .woff), then:  quilzo theme set font-display NAME%s\n",
			dim, reset)
		w.Human("  %sA .ttf or .otf is made into a WOFF and checked by:%s\n", dim, reset)
		w.Human("  %s  quilzo theme font add FILE [--name Satoshi-400-700]%s\n\n", dim, reset)
		w.Human("  %sThe filename is the contract:%s\n", dim, reset)
		w.Human("    %sSatoshi.woff2            the family, full variable range%s\n", dim, reset)
		w.Human("    %sSatoshi-600.woff2        one weight%s\n", dim, reset)
		w.Human("    %sSatoshi-400-700.woff2    a range (Satoshi-400..700.woff2 too)%s\n", dim, reset)
		w.Human("    %sSatoshi-italic.woff2     the italic%s\n\n", dim, reset)
		w.Human("  %sThere is no way to name a font on another host. A page that%s\n", dim, reset)
		w.Human("  %sfetches one has handed that host a request per visit and the%s\n", dim, reset)
		w.Human("  %sability to stall the render — and the policy cannot help,%s\n", dim, reset)
		w.Human("  %sbecause the page asked for it.%s\n", dim, reset)
		w.Human("\n  %sBuilt-in stacks, already on the reader's device: %s%s\n",
			dim, strings.Join(theme.StackNames(), ", "), reset)
		return nil
	}
	w.Human("%sfonts served from this origin%s %s(%s)%s\n\n", bold, reset, dim, fontsDir, reset)
	for _, f := range faces {
		w.Human("  %s%-22s%s %s%-12s %-8s %6d KiB  /fonts/%s%s\n",
			bold, f.Family, reset, dim, f.Weight, f.Style,
			len(f.Bytes)/1024, f.File, reset)
	}
	w.Human("\n  %squilzo theme set font-body %s%s\n", dim, faces[0].Family, reset)
	w.Human("  %squilzo theme font add FILE   another, from a .ttf, .otf, .woff or .woff2%s\n", dim, reset)
	// As above, and as loud: a file somebody put here and is not served is
	// the same news whether or not another face is. It was printed dim and
	// on one line under the list, the colour of a hint, and a sentence with
	// a path and a command in it ran far past the edge of the terminal.
	if len(set.Warnings) > 0 {
		w.Human("\n")
	}
	for _, note := range set.Warnings {
		w.Human("  %s%s%s\n", yellow, wrapIndent(note, 70, 2), reset)
	}
	return nil
}

// themeCSS prints the stylesheet a site is served, so it can be diffed.
func themeCSS(args []string) error {
	fs, dir := dirFlag("css", args)
	tokensOnly := fs.Bool("tokens", false, "just the generated token block")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := loadDesign(*dir)
	if err != nil {
		return err
	}
	if *tokensOnly {
		w.Human("%s", d.Theme.CSS())
		return nil
	}
	w.Human("%s", d.Stylesheet)
	return nil
}

// themeApply takes a shipped starter's palette without its layout.
//
// The design and the markup are separable now, and this is what makes that
// visible: a site can keep the layout it has written and take the editorial
// theme, or take the dashboard's density and none of its sections.
func themeApply(root string, args []string) error {
	pos, flags := splitThemeArgs(args)
	fs, dir := dirFlag("apply", flags)
	force := fs.Bool("force", false, "replace the theme that is there")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo theme apply <starter> — one of: %s",
			strings.Join(starter.Names(), ", "))
	}
	st, ok := starter.Get(pos[0])
	if !ok {
		return fmt.Errorf("no starter %q; try: %s",
			pos[0], strings.Join(starter.Names(), ", "))
	}
	if len(st.Tokens) == 0 {
		return fmt.Errorf(
			"the %s starter uses the shipped palette, so there is nothing to "+
				"apply. `quilzo theme unset --all` is the same result", st.Name)
	}
	existing, err := loadThemeFile(*dir)
	if err != nil {
		return err
	}
	if len(existing) > 0 && !*force {
		return fmt.Errorf(
			"this site already sets %d token(s). Applying a starter's theme "+
				"replaces all of them, so it is refused unless asked for: pass "+
				"--force", len(existing))
	}
	if err := writeThemeFile(*dir, st.Tokens); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("theme.apply", "/",
		audit.Success, map[string]string{"starter": st.Name}))
	w.Human("applied the %s%s%s theme: %s\n", bold, st.Name, reset, st.Look)
	w.Human("  %s%d token(s) written to %s%s\n", dim, len(st.Tokens),
		filepath.Join(*dir, themeFile), reset)
	sayWhenReadersSeeIt()
	return nil
}

func reportAdvisories(findings []theme.Finding) {
	var advisory []theme.Finding
	for _, f := range findings {
		if !f.Blocking {
			advisory = append(advisory, f)
		}
	}
	if len(advisory) == 0 {
		return
	}
	w.Human("\n%s%d thing(s) worth knowing%s\n", dim, len(advisory), reset)
	for _, f := range advisory {
		w.Human("  %s%s%s\n", dim, wrapIndent(f.Detail, 70, 4), reset)
	}
}

// splitThemeArgs separates positional arguments from flags, so
// `theme set primary '#123456' --dir x` works in either order.
// splitThemeArgs separates TOKEN VALUE pairs from the flags after them.
//
// A leading "-" is not enough to make an argument a flag. tracking-display is
// a letter spacing and its documentation says negative tightens, so
// `theme set tracking-display -0.02em` is the ordinary way to use it — and this
// used to hand -0.02em to the flag package, which answered "flag provided but
// not defined". The one token whose useful values are negative was the one
// token that could not be set.
//
// A flag is a dash followed by a letter. A value is anything else, and no token
// name starts with a dash.
func splitThemeArgs(args []string) (pos, flags []string) {
	for i, a := range args {
		if reFlag.MatchString(a) {
			return args[:i], args[i:]
		}
	}
	return args, nil
}

var reFlag = regexp.MustCompile(`^--?[A-Za-z]`)

func loadFontsFor(dir string) ([]theme.Family, error) {
	set, err := loadFontSet(dir)
	if err != nil {
		return nil, err
	}
	return set.Families(), nil
}

func schemeName(dark bool) string {
	if dark {
		return "dark"
	}
	return "light"
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// themeGenerate builds a whole palette from one colour.
//
// The thing it replaces is somebody with a brand colour, thirty tokens, and
// seventeen contrast requirements, doing constrained optimisation in a colour
// picker until the publish gate stops refusing them. That process ends in one
// of two places: a theme nobody likes, or the gate switched off. Neither is
// what the gate is for.
//
// The generated values are ordinary overrides and every one can be changed
// afterwards. This produces a defensible starting point, not a finished
// design.
func themeGenerate(root string, args []string) error {
	pos, flags := splitThemeArgs(args)
	fs, dir := dirFlag("generate", flags)
	replace := fs.Bool("replace", false,
		"discard the current colours rather than refusing")
	scheme := fs.String("scheme", "tonal",
		"how colourful: tonal, vibrant, expressive, neutral or monochrome")
	contrast := fs.String("contrast", "standard",
		"standard (WCAG AA), medium (6:1 text) or high (7:1 text, AAA)")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo theme generate <colour> [--scheme S] [--contrast C] [--replace]")
	}

	generated, err := theme.GenerateWith(pos[0], theme.Options{Scheme: *scheme, Contrast: *contrast})
	if err != nil {
		return err
	}

	existing, err := loadThemeFile(*dir)
	if err != nil {
		return err
	}
	// Somebody's own colours are not overwritten by accident. A generator that
	// silently replaced a hand-tuned palette would be a command nobody could
	// run twice.
	// By scope rather than by key: "primary" and "primary.light" are
	// different strings and the same setting for the light scheme, so a key
	// comparison finds nothing, generates over it, and leaves the hand-tuned
	// value quietly in charge of the scheme it still names.
	clash := theme.Colliding(existing, generated)
	if len(clash) > 0 && !*replace {
		return fmt.Errorf(
			"this theme already sets %d colour(s), starting with %s.\n"+
				"  Generating would discard them. Say so if that is what you "+
				"mean:\n    quilzo theme generate %s --replace",
			len(clash), clash[0], pos[0])
	}

	next := map[string]string{}
	for k, v := range existing {
		next[k] = v
	}
	for _, k := range clash {
		delete(next, k)
	}
	for k, v := range generated {
		next[k] = v
	}

	fonts, ferr := loadFontsFor(*dir)
	if ferr != nil {
		return ferr
	}
	th, problems := theme.New(next, fonts)
	for _, p := range problems {
		if p.Blocking {
			return fmt.Errorf("%s", p.Detail)
		}
	}
	// Checked, not assumed. The generator chooses values with the same
	// function this check uses, so a failure here means the two have drifted
	// -- and that is worth finding at generation time rather than at publish.
	findings := th.Check()
	for _, f := range findings {
		if f.Blocking {
			return fmt.Errorf(
				"the generated palette fails its own contrast check: %s — %s\n"+
					"  This is a bug in the generator, not in the colour you "+
					"chose", f.Token, f.Detail)
		}
	}

	if err := writeThemeFile(*dir, next); err != nil {
		return err
	}

	if w.JSON(map[string]any{"seed": pos[0], "tokens": len(generated)}) {
		return nil
	}
	w.Human("%s%d colour(s) generated from %s%s\n",
		bold, len(generated), pos[0], reset)
	w.Human("  %slight and dark, and every contrast pair checked%s\n", dim, reset)
	w.Human("\n  %ssee it:      quilzo theme show%s\n", dim, reset)
	w.Human("  %schange one:  quilzo theme set primary '#3b6ea5'%s\n", dim, reset)
	sayWhenReadersSeeIt()
	return nil
}
