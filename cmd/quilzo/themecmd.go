package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
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
		args = []string{"show"}
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
	case "css":
		return themeCSS(args[1:])
	case "apply":
		return themeApply(root, args[1:])
	default:
		return fmt.Errorf("unknown theme command %q; try show, tokens, set, "+
			"unset, check, fonts, css or apply", args[0])
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
	w.Human("\n  %squilzo theme check   the whole palette, both schemes%s\n",
		dim, reset)
	return nil
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
	if w.JSON(findings) {
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
	if blocking == 0 {
		w.Human("%severy text pair meets its ratio, in both schemes%s\n", bold, reset)
	} else {
		w.Human("%s%d contrast failure(s)%s\n\n", bold, blocking, reset)
		for _, f := range findings {
			if f.Blocking {
				w.Human("  [%s] %s\n\n", f.Scheme, wrapIndent(f.Detail, 70, 4))
			}
		}
	}
	reportAdvisories(findings)
	w.Human("\n  %swhat is not checked: whether the palette is any good, and "+
		"anything a colour outside the theme does%s\n", dim, reset)
	if blocking > 0 {
		return fmt.Errorf("%d text pair(s) below the ratio a reader needs", blocking)
	}
	return nil
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
		w.Human("  %sPut a .woff2 in %s and it is served from this origin at%s\n",
			dim, fontsDir, reset)
		w.Human("  %s/fonts/NAME.woff2, then:  quilzo theme set font-display NAME%s\n\n",
			dim, reset)
		w.Human("  %sThe filename is the contract:%s\n", dim, reset)
		w.Human("    %sSatoshi.woff2            the family, full variable range%s\n", dim, reset)
		w.Human("    %sSatoshi-600.woff2        one weight%s\n", dim, reset)
		w.Human("    %sSatoshi-400..700.woff2   a range%s\n", dim, reset)
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
	for _, note := range set.Warnings {
		w.Human("  %s%s%s\n", dim, note, reset)
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
