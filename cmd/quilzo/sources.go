// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/public"
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
//
// And then this was a builder of its own beside the public site's and the
// admin's: it had no forms, boards, bookings, newsletter, events or posts, so
// `quilzo render` and the gate in `quilzo publish` drew a page naming a form
// without it. The context is the public site's now (public.(*Site).Sources),
// of a site wired here as the server wires it; the admin's preview and its
// gate are handed the same (renderContext).
func sourcesFor(root string, s *store.Store, commit, siteName string,
	pages map[string]any) render.Sources {
	return renderSiteFor(root, s, commit, siteName).Sources(pages)
}

// renderSiteFor is the site as its pages are drawn at commit, for whatever
// renders one outside the server: what a page's context reads, wired from
// the store with the helpers the server's site is wired with (siteFor), and
// every listing, and so every post and event, read at commit's tree. Nothing
// a visitor sends is taken here, so no limiter, notice or audit is wired.
func renderSiteFor(root string, s *store.Store, commit, siteName string) *public.Site {
	st := public.New(s, render.Layouts{})
	st.Name = siteName
	cfg, cerr := loadConfig(root)
	if cerr == nil {
		// The newsletter's form is open only on a site with an address.
		st.BaseURL = config.SiteBase(strings.TrimSpace(cfg.Raw("site.base_url")))
	}

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
	// copies while the served ones did. The icon is one of the library's
	// pictures too.
	if lib, lerr := openMedia(root); lerr == nil {
		st.Media = lib.Get
		st.MediaStat = lib.Stat
	}
	st.Menus = func() (*menu.Set, error) { return loadMenus(root) }
	if set, err := loadListings(root); err == nil {
		tree := ""
		if commit != "" {
			if c, cerr := s.GetCommit(commit); cerr == nil {
				tree = c.Tree
			}
		}
		st.Listings = &listing.Resolver{
			Store: s, Index: collection.NewCache(), Tree: tree, Set: set}
	}
	// The forms a page names, read from the set the site's submit handler
	// validates against, so what is drawn is what is accepted.
	st.Forms = &public.Forms{Set: func() (*form.Set, error) { return loadForms(root) }}
	st.Boards = siteBoards(root)
	st.Bookings = publicBookings(root)
	st.Newsletter = publicNewsletter(root)
	// Buy buttons as the site shows them, so a preview and the gate see the
	// page a visitor gets.
	st.Buy = (&payReader{root: root}).Buy
	if cerr == nil {
		st.Icon = strings.TrimSpace(cfg.Raw("site.icon"))
		st.IconInitial = cfg.Bool("site.icon_initial")
		st.Events = strings.TrimSpace(cfg.Raw("site.events"))
		st.Blog = strings.TrimSpace(cfg.Raw("site.blog"))
		// Whether visitors have accounts, for the links a layout shows them.
		// The site's own carries its passkey party and limits, which drawing
		// a page needs none of.
		if mode := membersMode(cfg); mode != "off" {
			if ms, merr := openMembers(root); merr == nil {
				st.Members = &public.Members{Store: ms, Mode: mode}
			}
		}
	}
	return st
}

// renderContext is the admin's Sources hook: the one context, so the
// preview and the browser's publish gate draw the page the site serves.
func renderContext(root string, s *store.Store) func(commit string, pages map[string]any) render.Sources {
	return func(commit string, pages map[string]any) render.Sources {
		return sourcesFor(root, s, commit, siteName(root), pages)
	}
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

// mediaSound answers the accessibility gate's question about a recording:
// whether the library recorded it as having sound, and whether it recorded
// anything. An address that is not one of the library's files is unknown,
// which the gate treats as sound.
func mediaSound(root string) func(src string) (bool, bool) {
	lib, err := openMedia(root)
	if err != nil {
		return nil
	}
	return func(src string) (bool, bool) {
		id := strings.TrimPrefix(strings.TrimSpace(src), "/media/")
		if medialib.ValidID(id) != nil {
			return false, false
		}
		f, err := lib.Stat(id)
		if err != nil {
			return false, false
		}
		return f.SoundKnown()
	}
}
