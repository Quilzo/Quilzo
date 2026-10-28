// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/booking"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/webimport"
)

// The site crew, for an agent. An agent can build a whole site from a
// description, bring one in by its address, or write any feature as a
// package, and each waits as a proposal for a person to read and install:
// an agent may draft a package and may not install one. Once installed, it
// can fill in the blanks with facts the person gave it, and those pages are
// marked as an agent's words.

// mcpSiteImportPages bounds a read started over MCP, whose clients give up
// on a tool that takes minutes.
const mcpSiteImportPages = 30

func registerSiteOps(srv *mcp.Server, root string, caller *Caller) {
	refuse := func(err error) (any, error) { return nil, &mcp.Refusal{Reason: err.Error()} }
	str := func(a map[string]any, k string) string { v, _ := a[k].(string); return strings.TrimSpace(v) }
	_, agent := proposingAgent(caller)
	// proposed is what an agent is told about a proposal: enough to tell
	// the person what to read, and what happens next.
	proposed := func(pr proposal, p *feature.Package, extra map[string]any) (any, error) {
		card := p.MakeCard()
		out := map[string]any{
			"proposal": pr.ID, "package": pr.Name, "version": pr.Version, "title": card.Title,
			"risk": card.Risk, "approvers": card.Approvers, "card": card, "notes": pr.Notes,
			"next": "A person reads it and installs it on the Make screen (Proposed for you), or with " +
				"`quilzo feature proposals`. It is not installed until they do.",
		}
		for k, v := range extra {
			out[k] = v
		}
		b, err := json.Marshal(out)
		return string(b), err
	}

	srv.Register(mcp.Operation{
		Name: "site_build", NeedsRole: "author", Writes: true,
		Summary: "build a whole website from a description, as a proposal for a person to install",
		Detail: "Pages, menus, a contact form, a question box, a privacy page written from what the forms " +
			"collect, and a look. A fact the description does not give (a price, an address, opening hours) is " +
			"left as a [[blank]] rather than made up. Kinds: business, product, restaurant, portfolio, community, " +
			"event; read from the description when not given. Nothing is installed: a person reads the " +
			"proposal and decides.",
		Args: map[string]string{
			"description": "what the site is for, in a sentence or two",
			"name":        "what the site is called",
			"kind":        "optional: business, product, restaurant, portfolio, community or event",
			"style":       "optional: classic, expressive, glass, editorial, bold, soft or business",
			"colour":      "optional main colour, as #rrggbb",
		},
		Keywords: []string{"website", "site", "build", "create", "new site", "landing", "homepage", "make"},
	}, func(a map[string]any) (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), featureDraftTimeout)
		defer cancel()
		built, err := buildSite(ctx, root, feature.SiteBrief{Description: str(a, "description"), Name: str(a, "name"),
			Kind: str(a, "kind"), Style: str(a, "style"), Colour: str(a, "colour")}, false, agent)
		if err != nil {
			return refuse(err)
		}
		pr, p, err := proposeFeature(root, built.Body, "a site built from a description", built.Notes, caller)
		if err != nil {
			return refuse(err)
		}
		return proposed(pr, p, map[string]any{"to_fill": built.Fill})
	})

	srv.Register(mcp.Operation{
		Name: "site_import", NeedsRole: "author", Writes: true,
		Summary: "bring a live website in by its address, as a proposal for a person to install",
		Detail: "Reads the site politely (robots.txt obeyed, that host only, private addresses refused): its " +
			"pages as a hero and sections, its menus, its name and colour, and redirects so its old addresses " +
			"keep working. Scripts and forms are left behind and named in the notes. Pictures stay behind too: " +
			"nothing an agent brings is kept before a person decides, and a person keeps them by bringing the " +
			"site in from the Make screen. Reads at most 30 pages here; `quilzo site import` reads more.",
		Args: map[string]string{
			"address": "the site's home page, https://…",
			"name":    "optional: what the site is called, when not what it calls itself",
			"pages":   "optional: how many pages to read, at most 30",
		},
		Keywords: []string{"import", "migrate", "move", "bring", "wix", "squarespace", "wordpress", "website"},
	}, func(a map[string]any) (any, error) {
		pages := mcpSiteImportPages
		if n, ok := a["pages"].(float64); ok && n >= 1 && n < float64(pages) {
			pages = int(n)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		// No pictures: they would be in the media library, which the public
		// site serves by their hash, before anybody decided to keep them.
		b, s, err := importSite(ctx, root, str(a, "address"), str(a, "name"), pages, false, agent)
		if err != nil {
			return refuse(err)
		}
		for i, n := range b.Notes {
			if n == webimport.NotePicturesLeftOut {
				b.Notes[i] = "pictures stay behind when an agent brings a site in, since nothing it brings is kept " +
					"before a person decides; bring the site in from Make › Bring your site, or with quilzo site " +
					"import, to keep the ones it describes"
			}
		}
		body, err := json.MarshalIndent(b.Package, "", "  ")
		if err != nil {
			return nil, err
		}
		pr, p, err := proposeFeature(root, body, "a site brought from "+s.Home.Host, b.Notes, caller)
		if err != nil {
			return refuse(err)
		}
		return proposed(pr, p, map[string]any{"read": len(s.Pages), "redirects": len(b.Redirects)})
	})

	srv.Register(mcp.Operation{
		Name: "propose_feature", NeedsRole: "author", Writes: true,
		Summary: "propose a feature package you wrote (types, forms, pages, menus, chatbots…) for a person to install",
		Detail: "The package is checked as an install would check it, and kept for a person to read on the Make " +
			"screen. Its pages are marked as a model's words when installed. `quilzo feature example` shows " +
			"the format; a bookings block (as `quilzo booking example` prints) sets how the site takes " +
			"appointments, for pages with a booking section.",
		Args:     map[string]string{"package": "the package, as a JSON object"},
		Keywords: []string{"feature", "package", "propose", "form", "booking", "directory", "install"},
	}, func(a map[string]any) (any, error) {
		raw, ok := a["package"]
		if !ok {
			return refuse(errNoPackage)
		}
		body, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}
		p, _, err := readFeatureBytes(root, body, "")
		if err != nil {
			return refuse(err)
		}
		// Written by a model, so its pages say so once installed.
		by, _ := proposingAgent(caller)
		if err := rememberBuilt(root, p, by); err != nil {
			return nil, err
		}
		pr, p, err := proposeFeature(root, body, "a feature an agent wrote", nil, caller)
		if err != nil {
			return refuse(err)
		}
		return proposed(pr, p, nil)
	})

	srv.Register(mcp.Operation{
		Name: "booking_times", NeedsRole: "reader",
		Summary: "the site's bookable services and their free times, as visitors see them",
		Detail: "What the public booking pages offer: each service with its length and price, and the free times " +
			"in the site's time zone. Who booked is not here; a person reads that on the Bookings screen. To change " +
			"the hours or services, propose a package with a bookings block (propose_feature).",
		Args:     map[string]string{"days": "optional: how many days ahead, at most 31; 7 by default"},
		Keywords: []string{"booking", "appointment", "availability", "free", "times", "calendar", "slots"},
	}, func(a map[string]any) (any, error) {
		setup, err := loadBookingSetup(root)
		if err != nil {
			return refuse(err)
		}
		if setup == nil {
			return `{"bookings":false,"note":"this site takes no bookings"}`, nil
		}
		days := 7
		if n, ok := a["days"].(float64); ok && n >= 1 && n <= 31 {
			days = int(n)
		}
		book, err := openBookings(root)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		busy, err := book.Window(setup, now)
		if err != nil {
			return nil, err
		}
		type day struct {
			Date  string   `json:"date"`
			Times []string `json:"times"`
		}
		type service struct {
			Name    string `json:"name"`
			Title   string `json:"title"`
			Minutes int    `json:"minutes"`
			Price   string `json:"price,omitempty"`
			Free    []day  `json:"free"`
		}
		var out []service
		horizon := now.AddDate(0, 0, days).Format("2006-01-02")
		for _, sv := range setup.Services {
			free, err := booking.Free(setup, sv, busy, now)
			if err != nil {
				return refuse(err)
			}
			entry := service{Name: sv.Name, Title: sv.Title, Minutes: sv.Minutes, Price: sv.Price}
			for _, d := range free {
				if d.Date > horizon {
					break
				}
				var times []string
				for _, sl := range d.Slots {
					times = append(times, sl.Label)
				}
				entry.Free = append(entry.Free, day{Date: d.Date, Times: times})
			}
			out = append(out, entry)
		}
		b, err := json.Marshal(map[string]any{"bookings": true, "zone": setup.Zone, "paused": setup.Paused,
			"services": out})
		return string(b), err
	})

	srv.Register(mcp.Operation{
		Name: "site_blanks", NeedsRole: "reader",
		Summary: "what the draft's pages still need filled in, and the pages each is on",
		Detail: "The facts a site package left blank rather than made up. A page holding one is not " +
			"published until it is filled in.",
		Keywords: []string{"blanks", "fill", "missing", "site", "facts", "todo"},
	}, func(map[string]any) (any, error) {
		known, err := builderBlanks(root)
		if err != nil {
			return nil, err
		}
		pages, err := draftPages(root)
		if err != nil {
			return nil, err
		}
		whats, on := siteBlanks(pages, known)
		b, err := json.Marshal(map[string]any{"blanks": whats, "on": on})
		return string(b), err
	})

	srv.Register(mcp.Operation{
		Name: "site_fill", NeedsRole: "author", Writes: true,
		Summary: "fill in blanks with facts the person gave you",
		Detail: "Each value goes into every page that blank is on. Only facts the person told you or that you " +
			"read from a source they pointed you to; a blank you cannot fill stays a blank, which keeps its " +
			"page from being published. Filled pages are marked as an agent's words.",
		Args:     map[string]string{"values": "object of blank (as site_blanks names it) to value"},
		Keywords: []string{"fill", "blanks", "address", "hours", "price", "site"},
	}, func(a map[string]any) (any, error) {
		raw, _ := a["values"].(map[string]any)
		values := map[string]string{}
		for k, v := range raw {
			s, ok := v.(string)
			if !ok || strings.TrimSpace(s) == "" {
				continue
			}
			values[k] = s
		}
		if len(values) == 0 {
			return refuse(errNoValues)
		}
		n, changed, err := fillSite(root, values, agent)
		if err != nil {
			return refuse(err)
		}
		b, err := json.Marshal(map[string]any{"filled": n, "pages": changed,
			"next": "The pages are in the draft, marked as an agent's words; a person publishes them."})
		return string(b), err
	})
}

var (
	errNoPackage = errors.New("no package given")
	errNoValues  = errors.New("no values given; site_blanks lists what there is to fill in")
)
