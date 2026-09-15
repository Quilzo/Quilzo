// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/store"
)

// What a template may see, built once for every command that renders one.
//
// The accessibility check and the IPFS export each built their own context
// holding the page and nothing else, so both worked on a document with no
// navigation and no listings in it. For the check that means judging a page
// nobody is served — a link wrapping the site name looked empty and blocked
// the publish, and a real failure inside a menu would have been invisible. For
// the export it means shipping a static site with no navigation on any page.
func sourcesFor(root string, s *store.Store, commit, siteName string,
	pages map[string]any) render.Sources {

	src := render.Sources{Name: siteName, Pages: pages}

	// What the asset library can be asked, wired here too.
	//
	// This mattered the moment captions existed. The accessibility gate
	// renders pages through this builder and then refuses a <video> with no
	// <track> — and the track is a companion the decorator asks the library
	// for. Without these, the gate would have judged every captioned video as
	// uncaptioned and refused a publish nobody could fix: the file had the
	// captions and the document the gate read did not.
	//
	// The srcset goes with it for the reason this function exists at all. Its
	// own comment says pages are "rendered the way the site serves them", and
	// without this the pictures in the judged document carried no narrower
	// copies while the served ones did.
	if lib, lerr := openMedia(root); lerr == nil {
		src.SrcSet = func(id string) string {
			f, err := lib.Stat(id)
			if err != nil {
				return ""
			}
			return f.SrcSet("/media")
		}
		src.Tracks = func(id string) []any {
			f, err := lib.Stat(id)
			if err != nil || len(f.Tracks) == 0 {
				return nil
			}
			out := make([]any, 0, len(f.Tracks))
			for _, t := range f.Tracks {
				out = append(out, map[string]any{
					"src": "/media/" + t.ID, "lang": t.Lang,
					"label": t.Label, "kind": t.Kind, "default": t.Default,
				})
			}
			return out
		}
	}
	if set, err := loadMenus(root); err == nil {
		src.Menus = set
	}
	if set, err := loadListings(root); err == nil {
		tree := ""
		if commit != "" {
			if c, cerr := s.GetCommit(commit); cerr == nil {
				tree = c.Tree
			}
		}
		src.Listings = &listing.Resolver{
			Store: s, Index: collection.NewCache(), Tree: tree, Set: set}
	}
	return src
}

// siteName is what this site calls itself.
//
// Configuration rather than a flag, so that the gate, the preview and the
// exports agree with the server. `quilzo site --name` still overrides it for
// one run, which is how a staging copy gets a different title without editing
// anything.
func siteName(root string) string {
	cfg, err := loadConfig(root)
	if err != nil {
		return ""
	}
	return cfg.Raw("site.name")
}
