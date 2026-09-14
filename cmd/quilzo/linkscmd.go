// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"

	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

// What points at what.
//
// The walk that refuses a publish over a dangling reference has always known
// both directions and reported one. Asked here in either: `links PAGE` for
// what names it, `links --from PAGE` for what it names, and `links` for the
// whole map.
//
// Of a ref, not of the store. A rename is safe or not against a particular
// set of pages, and "safe in the draft" and "safe in what is live" are
// different questions with different answers — which is exactly the moment
// somebody asks.

func cmdLinks(root string, args []string) error {
	fs := flag.NewFlagSet("links", flag.ContinueOnError)
	ref := fs.String("ref", site.RefDraft, "which version to read: draft or live")
	from := fs.Bool("from", false,
		"what the page names, instead of what names it")
	broken := fs.Bool("broken", false, "only the ones pointing at nothing")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	// `links --broken PAGE` puts the flag first, and leadingArgs stops at the
	// first thing beginning with a dash — so the page would be invisible and
	// the command would answer about the whole site instead of saying it did
	// not understand. Whatever the flag set did not consume is the page.
	if len(rest) == 0 {
		rest = fs.Args()
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	pages, err := site.PagesAt(s, *ref)
	if err != nil {
		return err
	}
	st, err := schema.Load(root)
	if err != nil {
		return err
	}

	all := st.Links(pages)
	var show []schema.Link
	switch {
	case len(rest) == 0:
		show = all
	case *from:
		for _, l := range all {
			if l.From == rest[0] {
				show = append(show, l)
			}
		}
	default:
		show = st.LinksTo(pages, rest[0])
	}
	if *broken {
		var only []schema.Link
		for _, l := range show {
			if !l.Resolves {
				only = append(only, l)
			}
		}
		show = only
	}

	if w.JSON(map[string]any{"links": show, "total": len(show)}) {
		return nil
	}
	if len(show) == 0 {
		switch {
		case len(rest) == 0:
			w.Human("no references in %s\n", *ref)
			w.Human("  %sa reference is a field of kind `reference`; "+
				"`quilzo type show TYPE` lists a type's fields%s\n", dim, reset)
		case *from:
			w.Human("%s names nothing\n", rest[0])
		default:
			w.Human("nothing points at %s\n", rest[0])
		}
		return nil
	}

	for _, l := range show {
		mark, colour := "", dim
		if !l.Resolves {
			mark, colour = "  ← points at nothing", yellow
		}
		w.Human("  %-24s %s%s%s → %s%s%s\n",
			l.From, dim, l.Field, reset, l.To, colour, mark)
	}
	// The count says which question was answered, because "3 references" and
	// "3 pages point at this" are different facts and the rows look the same.
	switch {
	case len(rest) == 0:
		w.Human("\n%s\n", count(len(show), "reference"))
	case *from:
		w.Human("\n%s names %s\n", rest[0], count(len(show), "page"))
	default:
		// "1 page points at" and "2 pages point at": count gets the noun
		// right and the verb is this sentence's own business.
		verb := "point"
		if len(show) == 1 {
			verb = "points"
		}
		w.Human("\n%s %s at %s\n", count(len(show), "page"), verb, rest[0])
	}
	return nil
}
