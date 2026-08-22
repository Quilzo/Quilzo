package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/starter"
	"github.com/quilzo/quilzo/internal/theme"
	"github.com/quilzo/quilzo/internal/webfont"
)

// A site's design, loaded from one directory, in one place.
//
// # Why this is one function and not four
//
// The design is four things — the layouts, the theme, the fonts and the
// stylesheet that falls out of the last two — and five programs need all of
// them: the public server, the admin (for the preview), the publish gate, the
// static export and `template use`. Every one of them used to read
// templates/page.html and templates/site.css for itself, which is how the gate
// ended up judging a document with no navigation in it.
//
// The rule this file exists to hold is that a page is rendered through the same
// layout, against the same stylesheet, whoever is doing the rendering. That
// cannot be true if the loading is written five times.
//
// # The directory
//
//	templates/
//	  page.html        the default layout; required
//	  *.html           any other layout, named by a page's "layout" field
//	  theme.json       the tokens this site overrides; optional
//	  site.css         an operator's own stylesheet; optional, and wins
//	  fonts/*.woff2    typefaces served from this origin; optional
//
// # Why site.css still wins when it is there
//
// The stylesheet is generated from the theme now. A site that was built before
// that has a real site.css in this directory, written or edited by hand, and
// silently replacing it with a generated one would change how somebody's site
// looks because they upgraded. So a site.css that exists is served as-is, and
// the theme is what a site gets when there is no file to respect.

// themeFile is the tokens a site overrides, beside its layouts.
const themeFile = "theme.json"

// Design is everything needed to render a page the way readers see it.
type Design struct {
	Layouts render.Layouts
	Theme   *theme.Theme
	Fonts   *webfont.Set
	// Stylesheet is what /site.css serves: either the operator's own file or
	// the theme's tokens followed by the shared components.
	Stylesheet string
	// OwnStylesheet is true when the operator's site.css was used, so a
	// command can say that the theme is not in effect rather than leaving
	// somebody wondering why `theme set` changed nothing.
	OwnStylesheet bool
	// Notes are non-fatal things worth telling the operator: a font that was
	// refused, a theme value that is not usable. A design that quietly loses
	// half of itself is worse than one that complains.
	Notes []string
}

// loadDesign reads a template directory.
//
// The default layout is required, because a directory with no page.html cannot
// render a page that does not name a layout — which is every page written before
// layouts existed.
func loadDesign(dir string) (*Design, error) {
	layouts, err := loadLayouts(dir)
	if err != nil {
		return nil, err
	}

	d := &Design{Layouts: layouts}

	fonts, ferr := webfont.Load(filepath.Join(dir, "fonts"))
	if ferr != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath.Join(dir, "fonts"), ferr)
	}
	d.Fonts = fonts
	d.Notes = append(d.Notes, fonts.Warnings...)

	overrides, terr := loadThemeFile(dir)
	if terr != nil {
		return nil, terr
	}
	th, problems := theme.New(overrides, fonts.Families())
	for _, p := range problems {
		// A bad token is reported and skipped rather than fatal. A site whose
		// server refuses to start because one colour is malformed is a site
		// that is down for a typo; the value is ignored, the default applies,
		// and the message says which.
		d.Notes = append(d.Notes, p.String())
	}
	d.Theme = th

	if own, oerr := os.ReadFile(filepath.Join(dir, "site.css")); oerr == nil {
		d.Stylesheet = string(own)
		d.OwnStylesheet = true
	} else {
		d.Stylesheet = starter.Stylesheet(th)
	}
	return d, nil
}

// loadLayouts reads every .html in the directory as a layout.
func loadLayouts(dir string) (render.Layouts, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return render.Layouts{}, fmt.Errorf(
			"no template directory at %s: %w", dir, err)
	}
	sources := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name, isHTML := strings.CutSuffix(e.Name(), ".html")
		if !isHTML {
			continue
		}
		if !render.ValidLayoutName(name) {
			// Skipped rather than refused: a directory may hold a file somebody
			// left there, and refusing to start over its name would be a
			// server that will not run because of an editor backup.
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			return render.Layouts{}, rerr
		}
		sources[name] = string(b)
	}
	if len(sources) == 0 {
		return render.Layouts{}, fmt.Errorf(
			"no layout in %s. There has to be a %s.html — every page that does "+
				"not name a layout renders through it. `quilzo template use "+
				"sections` writes one",
			dir, render.DefaultLayout)
	}
	return render.NewLayouts(sources)
}

// loadThemeFile reads templates/theme.json.
//
// Absent is normal and means the shipped palette. Malformed is an error, because
// a theme file that cannot be parsed is a design somebody wrote and is not
// getting, and starting anyway would hide that behind a site that looks wrong.
func loadThemeFile(dir string) (map[string]string, error) {
	path := filepath.Join(dir, themeFile)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var raw map[string]any
	if uerr := json.Unmarshal(b, &raw); uerr != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, uerr)
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64:
			out[k] = trimFloat(t)
		default:
			return nil, fmt.Errorf(
				"%s: %s is %T. Every theme value is a string or a number", path, k, v)
		}
	}
	return out, nil
}

func trimFloat(f float64) string {
	s := fmt.Sprintf("%g", f)
	return s
}

// writeThemeFile saves a token set, sorted so a diff is readable.
func writeThemeFile(dir string, values map[string]string) error {
	if len(values) == 0 {
		// An empty theme is the shipped palette, and the honest way to say that
		// is no file rather than an empty object somebody has to interpret.
		err := os.Remove(filepath.Join(dir, themeFile))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("{\n")
	for i, k := range keys {
		key, _ := json.Marshal(k)
		value, _ := json.Marshal(values[k])
		fmt.Fprintf(&b, "  %s: %s", key, value)
		if i < len(keys)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return os.WriteFile(filepath.Join(dir, themeFile), []byte(b.String()), 0o600)
}

// loadFontSet reads just the fonts, for the commands that only need those.
func loadFontSet(dir string) (*webfont.Set, error) {
	return webfont.Load(filepath.Join(dir, "fonts"))
}

// installStarter writes a shipped design's markup and palette into a directory.
//
// Shared by `template use` and the admin's design screen, because they are the
// same operation and the browser's version used to be a different, smaller one:
// it wrote the sample content and left the markup alone, so somebody who never
// opened a terminal got the fields of a design they were not being served.
//
// The default layout is always written alongside a named one. A directory
// holding only article.html cannot serve a page that names no layout, which is
// every page written before layouts existed.
func installStarter(dir, name string) ([]string, error) {
	st, ok := starter.Get(name)
	if !ok {
		return nil, fmt.Errorf("there is no starter called %q", name)
	}
	shipped, err := starter.Layouts()
	if err != nil {
		return nil, err
	}
	wanted := map[string]string{}
	src, ok := shipped[st.LayoutName()]
	if !ok {
		return nil, fmt.Errorf("the %s starter names a layout that does not ship", name)
	}
	wanted[st.LayoutName()] = src
	if def, found := shipped[render.DefaultLayout]; found {
		wanted[render.DefaultLayout] = def
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var written []string
	for layout, body := range wanted {
		path := filepath.Join(dir, layout+".html")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return nil, err
		}
		written = append(written, layout+".html")
	}
	if len(st.Tokens) > 0 {
		if err := writeThemeFile(dir, st.Tokens); err != nil {
			return nil, err
		}
		written = append(written, themeFile)
	}
	sort.Strings(written)
	return written, nil
}
