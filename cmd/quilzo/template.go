package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/foreign"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/starter"
)

func cmdTemplate(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return templateList()
	case "show":
		return templateShow(args[1:])
	case "use":
		return templateUse(root, args[1:])
	case "layouts":
		return templateLayouts(args[1:])
	case "adopt":
		return templateAdopt(root, args[1:])
	default:
		return fmt.Errorf("unknown template command %q; try list, show, use, "+
			"layouts or adopt", args[0])
	}
}

func templateList() error {
	all := starter.All()
	if w.JSON(all) {
		return nil
	}
	for _, t := range all {
		w.Human("%s%-11s%s %s\n", bold, t.Name, reset, wrapIndent(t.Summary, 62, 12))
		if t.Look != "" {
			w.Human("            %s%s%s\n", dim, wrapIndent(t.Look, 62, 12), reset)
		}
		w.Human("  %s%d fields · layout %s · quilzo template show %s%s\n\n",
			dim, len(t.Fields), t.LayoutName(), t.Name, reset)
	}
	w.Human("%squilzo template use NAME   writes the layout, a theme and sample%s\n",
		dim, reset)
	w.Human("%s                            content you can edit%s\n", dim, reset)
	w.Human("%squilzo template adopt FILE  converts a template from somewhere else%s\n",
		dim, reset)
	return nil
}

func templateShow(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo template show <name>")
	}
	t, ok := starter.Get(args[0])
	if !ok {
		return fmt.Errorf("no starter template %q; try: %s",
			args[0], strings.Join(starter.Names(), ", "))
	}
	if w.JSON(t) {
		return nil
	}
	w.Human("%s%s%s\n", bold, t.Name, reset)
	w.Human("%s\n\n", wrapIndent(t.Summary, 74, 0))
	if t.Look != "" {
		w.Human("%slooks like%s %s\n\n", bold, reset, wrapIndent(t.Look, 74, 0))
	}
	w.Human("%slayout%s     %s.html\n\n", bold, reset, t.LayoutName())

	w.Human("%sfields%s\n", bold, reset)
	fields := append([]string{}, t.Fields...)
	sort.Strings(fields)
	for _, f := range fields {
		kind := "text"
		switch v := t.Sample[f].(type) {
		case []any:
			kind = fmt.Sprintf("list of %d", len(v))
		case map[string]any:
			kind = "object"
		case nil:
			kind = "optional"
		}
		w.Human("  %-18s %s%s%s\n", f, dim, kind, reset)
	}

	if len(t.Tokens) > 0 {
		w.Human("\n%stheme%s %s(%d token(s); `quilzo theme` after using it)%s\n",
			bold, reset, dim, len(t.Tokens), reset)
		keys := make([]string, 0, len(t.Tokens))
		for k := range t.Tokens {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			w.Human("  %-28s %s%s%s\n", k, dim, t.Tokens[k], reset)
		}
	}
	return nil
}

// templateLayouts lists the layouts that ship, which is what a page's "layout"
// field may name once they are written out.
func templateLayouts(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: quilzo template layouts")
	}
	names := starter.LayoutNames()
	if w.JSON(names) {
		return nil
	}
	w.Human("%slayouts that ship%s\n\n", bold, reset)
	for _, n := range names {
		note := ""
		if n == render.DefaultLayout {
			note = " — the default: what a page renders through when it names none"
		}
		w.Human("  %s%-11s%s%s%s%s\n", bold, n, reset, dim, note, reset)
	}
	w.Human("\n  %sa page chooses one with a \"layout\" field:%s\n", dim, reset)
	w.Human("    %s{ \"layout\": \"catalogue\", \"title\": \"Shop\" }%s\n", dim, reset)
	w.Human("\n  %squilzo template use NAME --all-layouts  writes all of them%s\n",
		dim, reset)
	return nil
}

func templateUse(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("use", flag.ContinueOnError)
	dir := fs.String("dir", "templates", "where to write the layout and the theme")
	page := fs.String("page", "index", "page name for the sample content")
	force := fs.Bool("force", false, "overwrite files that already exist")
	noContent := fs.Bool("no-content", false, "write the template but not the sample")
	noTheme := fs.Bool("no-theme", false,
		"skip the theme, so the site keeps the palette it has")
	allLayouts := fs.Bool("all-layouts", false,
		"write every layout that ships, so any page can name any of them")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo template use <name> [--dir templates]")
	}
	t, ok := starter.Get(pos[0])
	if !ok {
		return fmt.Errorf("no starter template %q; try: %s",
			pos[0], strings.Join(starter.Names(), ", "))
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}

	// What gets written. The stylesheet is not in here any more: it is
	// generated from the theme and the shared components, so a copy on disk
	// would be a fourth thing to keep in step with the other three.
	targets := map[string]string{}
	if *allLayouts {
		layouts, lerr := starter.Layouts()
		if lerr != nil {
			return lerr
		}
		for name, src := range layouts {
			targets[filepath.Join(*dir, name+".html")] = src
		}
	} else {
		html, herr := t.HTML()
		if herr != nil {
			return herr
		}
		targets[filepath.Join(*dir, t.LayoutName()+".html")] = html
		if t.LayoutName() != render.DefaultLayout {
			// Every site needs the default layout, because it is what a page
			// that names no layout renders through — which is every page
			// written before layouts existed. Writing only `article.html`
			// would produce a directory that cannot serve an ordinary page.
			def, derr := starter.Layouts()
			if derr != nil {
				return derr
			}
			if src, found := def[render.DefaultLayout]; found {
				targets[filepath.Join(*dir, render.DefaultLayout+".html")] = src
			}
		}
	}

	// Refuse to clobber by default. A template directory is somebody's work,
	// and "use" reading as "replace what I spent a week on" is the kind of
	// surprise a tool gets one chance at.
	if !*force {
		for path := range targets {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("%s already exists; pass --force to replace it",
					path)
			}
		}
	}
	paths := make([]string, 0, len(targets))
	for path := range targets {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if err := os.WriteFile(path, []byte(targets[path]), 0o600); err != nil {
			return err
		}
	}

	// A template is what renders every page, so writing one is a change to
	// what the public sees the moment the server restarts.
	record(root, resolveCaller(root, "").auditRecord("template.use", "/",
		audit.Success, map[string]string{"starter": t.Name, "dir": *dir}))
	for _, path := range paths {
		w.Human("wrote %s%s%s\n", bold, path, reset)
	}

	if !*noTheme && len(t.Tokens) > 0 {
		themePath := filepath.Join(*dir, themeFile)
		if _, err := os.Stat(themePath); err == nil && !*force {
			w.Human("  %s%s already exists, left alone — the layout will use "+
				"the theme you have%s\n", dim, themePath, reset)
		} else if err := writeThemeFile(*dir, t.Tokens); err != nil {
			return err
		} else {
			w.Human("wrote %s%s%s %s(%d token(s); `quilzo theme show`)%s\n",
				bold, themePath, reset, dim, len(t.Tokens), reset)
		}
	}

	// An existing site.css wins over the generated stylesheet, so a site that
	// has one would take the new layout and none of its design. Said here
	// rather than discovered by looking at the page.
	if _, err := os.Stat(filepath.Join(*dir, "site.css")); err == nil {
		w.Human("\n  %s%s exists, so it is what gets served and this theme is "+
			"not in effect.%s\n", dim, filepath.Join(*dir, "site.css"), reset)
		w.Human("  %sDelete it to use the generated stylesheet, or keep it and "+
			"edit it by hand.%s\n", dim, reset)
	}

	if *noContent {
		return nil
	}
	// Sample content, so the first render shows a finished page rather than a
	// skeleton with every field empty. It is also the fixture the test suite
	// renders, which is why it is guaranteed to fill the template.
	sample := filepath.Join(*dir, t.Name+".json")
	body := t.Sample
	if t.LayoutName() != render.DefaultLayout {
		// The sample has to say which layout it is for, or it renders through
		// the default and looks nothing like the starter somebody chose.
		body = withLayout(t.Sample, t.LayoutName())
	}
	encoded, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}
	if _, err := os.Stat(sample); err == nil && !*force {
		w.Human("  %s%s already exists, left alone%s\n", dim, sample, reset)
	} else if err := os.WriteFile(sample, encoded, 0o600); err != nil {
		return err
	} else {
		w.Human("wrote %s%s%s\n", bold, sample, reset)
	}

	w.Human("\n  %snext:%s\n", dim, reset)
	w.Human("    quilzo add %s=%s\n", *page, sample)
	w.Human("    quilzo publish\n")
	w.Human("    quilzo site --open\n")
	w.Human("\n  %sthe stylesheet is generated from the theme and served at "+
		"/site.css%s\n", dim, reset)
	return nil
}

// withLayout returns a copy of a sample carrying its layout declaration.
func withLayout(sample map[string]any, layout string) map[string]any {
	out := make(map[string]any, len(sample)+1)
	for k, v := range sample {
		out[k] = v
	}
	out["layout"] = layout
	return out
}

// templateAdopt converts a template written for another system.
func templateAdopt(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("adopt", flag.ContinueOnError)
	dir := fs.String("dir", "templates", "where to write the converted layout")
	name := fs.String("as", "",
		"layout name to write; the file's own name by default")
	dry := fs.Bool("dry-run", false, "report what would change and write nothing")
	force := fs.Bool("force", false, "overwrite a layout that already exists")
	accept := fs.Bool("accept-unsupported", false,
		"write the layout even where constructs could not be converted")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf(
			"usage: quilzo template adopt <file.html> [--as name] [--dry-run]")
	}

	src, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	layoutName := strings.TrimSpace(*name)
	if layoutName == "" {
		layoutName = foreign.LayoutNameFor(pos[0])
	}
	if !render.ValidLayoutName(layoutName) {
		return fmt.Errorf(
			"%q is not a usable layout name. Lowercase letters, digits and "+
				"hyphens — pass --as to choose one", layoutName)
	}

	result := foreign.Adopt(string(src))
	if w.JSON(result) {
		return nil
	}

	w.Human("%s%s%s → %s%s.html%s  (%s)\n\n",
		bold, pos[0], reset, bold, layoutName, reset, result.Dialect)

	report(result.Changes, "changed", dim)
	report(result.Removed, "removed", dim)
	report(result.Unsupported, "not converted", bold)

	if len(result.Fields) > 0 {
		w.Human("\n%sfields this layout reads%s\n", bold, reset)
		w.Human("  %s%s%s\n", dim, wrapIndent(strings.Join(result.Fields, ", "), 70, 2), reset)
	}

	if len(result.Unsupported) > 0 && !*accept {
		return fmt.Errorf(
			"%d construct(s) could not be converted, so this layout would "+
				"render differently from the one it came from.\n"+
				"  Fix them in the source and adopt it again, or pass "+
				"--accept-unsupported to write it as it stands and finish it "+
				"by hand", len(result.Unsupported))
	}
	if *dry {
		w.Human("\n  %snothing written (--dry-run)%s\n", dim, reset)
		return nil
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(*dir, layoutName+".html")
	if _, serr := os.Stat(path); serr == nil && !*force {
		return fmt.Errorf("%s already exists; pass --force to replace it", path)
	}
	if err := os.WriteFile(path, []byte(result.Template), 0o600); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("template.adopt", "/",
		audit.Success, map[string]string{
			"from": pos[0], "layout": layoutName, "dialect": result.Dialect,
		}))
	w.Human("\nwrote %s%s%s\n", bold, path, reset)
	if layoutName != render.DefaultLayout {
		w.Human("  %sa page renders through it with \"layout\": %q%s\n",
			dim, layoutName, reset)
	}
	w.Human("  %squilzo audit %s  checks it before anything is published%s\n",
		dim, path, reset)
	return nil
}

func report(lines []string, label, emphasis string) {
	if len(lines) == 0 {
		return
	}
	w.Human("%s%d %s%s\n", emphasis, len(lines), label, reset)
	for _, l := range lines {
		w.Human("  %s\n", wrapIndent(l, 70, 4))
	}
	w.Human("\n")
}

// wrapIndent wraps text to a width, indenting continuation lines.
func wrapIndent(s string, width, indent int) string {
	words := strings.Fields(s)
	var b strings.Builder
	col := 0
	for i, word := range words {
		if col+len(word) > width && i > 0 {
			b.WriteString("\n" + strings.Repeat(" ", indent))
			col = indent
		} else if i > 0 {
			b.WriteString(" ")
			col++
		}
		b.WriteString(word)
		col += len(word)
	}
	return b.String()
}
