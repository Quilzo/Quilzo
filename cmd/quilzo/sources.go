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
