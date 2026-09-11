// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/find"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

// Looking for one thing, without knowing what kind of thing it is.
//
// The published site has had search since there was a site. The interface that
// makes it had none, and neither did the command line: to find a page you
// listed pages, to find a setting among seventy you guessed at `config list`
// and read.
//
// # Why the settings a person may see are filtered before the search
//
// A configuration key's summary says what it is for, which is exactly the text
// worth searching and also a description of a control. Reading it is gated on
// ActGrant in the interface for that reason, and the finder is handed only what
// the caller may see rather than filtering afterwards — a count of hits over a
// list somebody cannot read still tells them what is in it.
func cmdFind(root string, args []string) error {
	fs := flag.NewFlagSet("find", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "how many results at most")
	ref := fs.String("ref", site.RefDraft,
		"which pages to search: draft or live")
	rest, flags := leadingArgs(args, len(args))
	if err := fs.Parse(flags); err != nil {
		return err
	}
	query := strings.TrimSpace(strings.Join(rest, " "))
	if query == "" {
		return fmt.Errorf("usage: quilzo find WORDS [--ref live] [--limit N]\n" +
			"  words, not a query: there is no syntax here and a colon or a " +
			"quote is a character in a word")
	}

	src, err := findSources(root, *ref, query)
	if err != nil {
		return err
	}
	hits := find.Search(query, src, *limit)

	if w.JSON(map[string]any{"query": query, "results": hits}) {
		return nil
	}
	if len(hits) == 0 {
		w.Human("  %snothing matched %q%s\n", dim, query, reset)
		return nil
	}
	// Grouped under a heading per kind, because the kinds are not comparable
	// and a flat list invites reading the order as a ranking across them.
	last := find.Kind("")
	for _, h := range hits {
		if h.Kind != last {
			w.Human("\n%s%s%s\n", bold, kindHeading(h.Kind), reset)
			last = h.Kind
		}
		w.Human("  %-34s %s%s%s\n", h.Title, dim, h.Why, reset)
		if h.Path != "" {
			w.Human("  %s%s%s\n", dim, h.Path, reset)
		}
	}
	w.Human("\n")
	return nil
}

func kindHeading(k find.Kind) string {
	switch k {
	case find.Screen:
		return "screens"
	case find.Setting:
		return "settings"
	case find.Page:
		return "pages"
	case find.Media:
		return "media"
	case find.Type:
		return "content types"
	default:
		return string(k)
	}
}

// findSources gathers what this caller may search.
//
// Each source is optional and a failure to open one is not a failure to
// search: a store with no media library should still find a page, and a
// finder that refuses everything because one directory is missing is a finder
// nobody reaches for.
func findSources(root, ref, query string) (find.Sources, error) {
	s, err := open(root)
	if err != nil {
		return find.Sources{}, err
	}
	if ref != site.RefDraft && ref != site.RefLive {
		return find.Sources{}, fmt.Errorf(
			"--ref is draft or live, not %q", ref)
	}

	src := find.Sources{
		Commit:  s.GetRef(ref),
		Screens: admin.Screens(),
	}
	if pages, perr := site.PagesAt(s, ref); perr == nil {
		src.Pages = pages
	}

	// The settings, when this caller may read them. Everything else here is
	// content or an address; these are the descriptions of controls.
	caller := resolveCaller(root, "")
	if authorise(root, caller, auth.ActGrant, "/") == nil {
		for _, o := range config.All() {
			src.Settings = append(src.Settings,
				find.Option{Key: o.Key, Summary: o.Summary})
		}
	}

	if lib, lerr := openMedia(root); lerr == nil {
		if files, ferr := lib.List(); ferr == nil {
			for _, f := range files {
				src.Media = append(src.Media, find.File{ID: f.ID, Alt: f.Alt})
			}
		}
	}

	if st, rerr := schema.Load(root); rerr == nil && st != nil && st.Registry != nil {
		for _, t := range st.Registry.Types {
			src.Types = append(src.Types, find.ContentType{
				Name: t.Name, Fields: fieldNames(t),
			})
		}
	}
	return src, nil
}

func fieldNames(t schema.Type) []string {
	out := make([]string, 0, len(t.Fields))
	for _, f := range t.Fields {
		out = append(out, f.Name)
	}
	return out
}
