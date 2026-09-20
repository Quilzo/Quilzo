// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"sort"
	"time"

	"github.com/quilzo/quilzo/internal/gate"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The checks about the content, built once and handed to every surface.
//
// See internal/gate for what was wrong and why this is a list rather than a
// call in each place. This is where the list is filled in, because this is the
// one package that can reach every store the checks need — the media library,
// the type registry, the claim rules, the menus — and the browser, the agent
// interface and the chat surfaces are all wired from here.
//
// # What is not in it
//
// Accessibility, provenance and dual authorisation are not, and each for a
// reason of its own rather than by oversight.
//
// Accessibility and provenance carry an override: --force-inaccessible and
// --force-unmarked on the command line, a written reason in the browser. A
// gate that can be waived needs the waiver recorded against it, and that is a
// per-surface conversation — a flag here, a text box there — rather than a
// yes or no. They are run by every surface already.
//
// Dual authorisation is about people rather than about content, and it is
// asked last everywhere for the reason cmdPublish gives: asking two colleagues
// to approve something the tool is going to refuse anyway wastes their time
// and teaches them the approval is a formality.
//
// Nothing in here is waivable. That is the property that makes one list
// possible: every gate below either passes or refuses, on every surface, with
// no per-surface question about what an override means.

// contentGates is every check about the bytes being published.
//
// ref names what would go live. Empty means the draft, which is what every
// caller but `quilzo publish TARGET` means.
func contentGates(root string, s *store.Store, ref string) gate.Set {
	at := func() string {
		if ref != "" {
			return ref
		}
		return s.GetRef(site.RefDraft)
	}
	pagesAt := func() (map[string]any, error) { return site.PagesAt(s, at()) }

	return gate.Set{
		// Spillage first, and with no way to skip it. A page marked above what
		// the deployment is accredited for must not reach it, and unlike the
		// accessibility gate there is no legitimate reason to turn this off —
		// a deployment that does not mark is unaffected, because the check is
		// a no-op when no scheme is configured.
		{
			Name: "classification",
			Refusal: func(int) string {
				return "content is marked above what this deployment may publish"
			},
			Run: func() (blocking, advisory []gate.Finding, err error) {
				if err := checkMarking(root, s, ref); err != nil {
					return []gate.Finding{{Detail: err.Error()}}, nil, nil
				}
				return nil, nil, nil
			},
		},

		// Image rights. Only an expiry that has passed blocks; lapsing and
		// undeclared are advisory, because a gate that refuses three different
		// things is a gate people switch off — and the lapsing report is the
		// half worth having, since an expired licence cannot be fixed
		// retroactively and one expiring in six weeks can.
		{
			Name: "image rights",
			Refusal: func(n int) string {
				return fmt.Sprintf("%d image(s) would be published under "+
					"permission that has ended.\n  Renew the licence and "+
					"record the new date, or take the image off the page", n)
			},
			Run: func() (blocking, advisory []gate.Finding, err error) {
				lib, lerr := openMedia(root)
				if lerr != nil {
					// No library is not a failed check. A store with no media
					// has no image rights to examine.
					return nil, nil, nil
				}
				now := time.Now()
				rep, rerr := checkRights(s, lib, at(), now)
				if rerr != nil {
					return nil, nil, rerr
				}
				for _, u := range rep.Expired {
					blocking = append(blocking, gate.Finding{
						Page:   u.File.Name,
						Detail: "the permission to use this ended",
					})
				}
				for _, u := range rep.Lapsing {
					advisory = append(advisory, gate.Finding{
						Page:   u.File.Name,
						Detail: "the permission to use this is running out",
					})
				}
				return blocking, advisory, nil
			},
		},

		// The "references" gate is on main and not here.
		//
		// It refuses a page whose field names another page that is not being
		// published, and it is built on schema.Store.Unresolved, which arrived
		// with the `page` field kind after v0.2.1. There is no such field kind
		// in this release, so there is nothing for the gate to check — and a
		// gate that cannot fire is worse than an absent one, because the table
		// below says it ran.

		// A section whose kind this build does not know renders as nothing at
		// all: a page carrying "gallry" is a page with a gallery missing, no
		// message anywhere, and a publish that reported success. The kinds are
		// a closed list, so this is a check the tool can make and the author
		// cannot. Blocking for the kind, advisory for the fields inside it.
		{
			Name: "arrangement",
			Refusal: func(n int) string {
				return fmt.Sprintf("%d section(s) would render as nothing. A "+
					"kind this build does not know is not a section; `quilzo "+
					"section kinds` lists the ones there are", n)
			},
			Run: func() (blocking, advisory []gate.Finding, err error) {
				pages, perr := pagesAt()
				if perr != nil {
					return nil, nil, perr
				}
				for _, name := range sortedNames(pages) {
					bad, advice := section.Validate(pages[name])
					for _, p := range bad {
						blocking = append(blocking,
							gate.Finding{Page: name, Detail: p.String()})
					}
					for _, p := range advice {
						advisory = append(advisory,
							gate.Finding{Page: name, Detail: p.String()})
					}
				}
				return blocking, advisory, nil
			},
		},

		// Claims. The rules live in a file that may not exist, which is the
		// ordinary state and not a failure. A file that exists and does not
		// parse IS a failure, because treating a broken rules file as "no
		// rules" would make corrupting it the way to publish anything.
		{
			Name: "claims",
			Refusal: func(n int) string {
				return fmt.Sprintf("%d claim(s) this business would have to "+
					"stand behind and nothing here substantiates.\n  Add the "+
					"field each one names, or say something else", n)
			},
			Run: func() (blocking, advisory []gate.Finding, err error) {
				rules, berr := loadBrand(root)
				if berr != nil {
					return nil, nil, berr
				}
				if len(rules.Terms) == 0 {
					return nil, nil, nil
				}
				findings, _, ferr := brandFindings(s, rules, at())
				if ferr != nil {
					return nil, nil, ferr
				}
				for _, f := range findings {
					detail := fmt.Sprintf("%s: %q — %s", f.Field, f.Term, f.Why)
					if f.Needs != "" {
						detail += fmt.Sprintf("; say it and set %s, or say "+
							"something else", f.Needs)
					}
					blocking = append(blocking,
						gate.Finding{Page: f.Where, Detail: detail})
				}
				return blocking, nil, nil
			},
		},

		// A page already past the date it stops being public. Publishing would
		// put up content nobody can see, which is a release that looks like it
		// worked and did nothing.
		//
		// This one the browser had and the command line did not, so the
		// divergence ran both ways.
		{
			Name: "expiry",
			Refusal: func(n int) string {
				return fmt.Sprintf("%d page(s) are already past the date they "+
					"stop being public.\n  Publishing would put up content "+
					"nobody can see: move the date, or take the page out", n)
			},
			Run: func() (blocking, advisory []gate.Finding, err error) {
				pages, perr := pagesAt()
				if perr != nil {
					return nil, nil, perr
				}
				for _, stale := range site.AlreadyExpired(pages, time.Now()) {
					blocking = append(blocking, gate.Finding{Detail: stale})
				}
				return blocking, nil, nil
			},
		},

		// A menu entry pointing at nothing is "a 404 every reader finds before
		// anybody here does" — internal/menu's words. Also the browser's, and
		// also not the command line's until now.
		{
			Name: "navigation",
			Refusal: func(n int) string {
				return fmt.Sprintf("%d menu entr(y/ies) point at a page that "+
					"is not being published.\n  Publish it, or take the entry "+
					"out of the menu", n)
			},
			Run: func() (blocking, advisory []gate.Finding, err error) {
				set, merr := loadMenus(root)
				if merr != nil {
					return nil, nil, merr
				}
				if set == nil {
					return nil, nil, nil
				}
				pages, perr := pagesAt()
				if perr != nil {
					return nil, nil, perr
				}
				for _, p := range set.Broken(pages) {
					blocking = append(blocking, gate.Finding{Detail: p.String()})
				}
				return blocking, nil, nil
			},
		},
	}
}

func sortedNames(pages map[string]any) []string {
	out := make([]string, 0, len(pages))
	for name := range pages {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
