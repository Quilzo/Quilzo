// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/export"
	"github.com/quilzo/quilzo/internal/seo"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The one export of a whole site.
//
// `quilzo export`, MCP's export_site and the admin's Transfer screen each
// built an export of their own. Only the command line's carried the
// collections, the change dates and the redirects, and only it recorded
// that the site had been taken out: an agent backing the site up over MCP
// got the draft's pages and the banner, no products, no stockists and no
// record, and the screen's hint promised change dates and redirects its
// download did not carry. Every surface builds through exportSite and
// records through recordExport, so what one takes out the others take out.

// exportOptions says what an export is of and how it is described.
type exportOptions struct {
	Format export.Format
	// Ref is the ref or commit exported: live on the command line and over
	// MCP, unless they name another, and the draft on the Transfer screen.
	Ref string
	// Name and BaseURL describe the site, for the formats that carry them.
	Name, BaseURL string
	// Licence and Publisher are for an RO-Crate deposit, which needs a
	// licence.
	Licence, Publisher string
}

// exported is a whole site's export, built and not yet written anywhere.
type exported struct {
	Files                       []export.File
	Pages, Records, Collections int
	// Notes say what was left out, and why, when part of it could not be
	// read: the change dates, or the redirects `quilzo import` wrote.
	Notes []string
}

// exportSite builds the export of the site at opts.Ref for caller. It is
// refused when any page or collection in it is not the caller's to read:
// an export holds all of them, and one quietly left out is a copy somebody
// keeps believing it whole.
func exportSite(root string, caller *Caller, opts exportOptions) (*exported, error) {
	s, err := open(root)
	if err != nil {
		return nil, err
	}
	pages, err := site.PagesAt(s, opts.Ref)
	if err != nil {
		return nil, err
	}
	if err := everyPage(root, caller, pages); err != nil {
		return nil, err
	}
	head := s.GetRef(opts.Ref)
	if head == "" {
		head = opts.Ref
	}
	ex := &exported{Pages: len(pages)}

	// The collections too. Leaving these out was a silent data loss in every
	// format: the demo shop exported a catalogue page and none of its twelve
	// products, and nothing said so because the count printed was of pages.
	colls := map[string][]export.Record{}
	tree := ""
	if c, err := s.GetCommit(head); err != nil {
		return nil, err
	} else {
		tree = c.Tree
	}
	if tree != "" {
		names, err := collection.Names(s, tree)
		if err != nil {
			return nil, err
		}
		// Every collection is in the export, so every one must be the
		// caller's to read: access is given per collection, and a check on
		// "/" does not see a deny on one.
		for _, name := range names {
			if err := authorise(root, caller, auth.ActView, auth.DataResource(name)); err != nil {
				return nil, fmt.Errorf("the export holds every collection, and %s is not yours to read: %w", name, err)
			}
		}
		for _, name := range names {
			// Paged to the end, not one page of it. A listing has a maximum
			// limit, so taking a single page would export the first thousand
			// products of a larger catalogue and report success — the same
			// shape of failure as exporting none of them.
			for offset := 0; ; {
				rows, total, err := collection.List(s, tree, name,
					collection.Query{
						Limit: collection.MaxLimit, Offset: offset, Sort: "id"})
				if err != nil {
					return nil, err
				}
				for _, r := range rows {
					colls[name] = append(colls[name], export.Record{
						ID: r.ID, Fields: r.Fields,
						Created: r.Created, Updated: r.Updated,
					})
				}
				offset += len(rows)
				ex.Records += len(rows)
				if len(rows) == 0 || offset >= total {
					if offset != total {
						return nil, errBlocked{fmt.Errorf(
							"%s holds %d records but only %d could be read; "+
								"exporting now would drop the rest silently",
							name, total, offset)}
					}
					break
				}
			}
		}
	}
	ex.Collections = len(colls)
	changed, err := seo.LastChanged(s, head, 5000)
	if err != nil {
		// A missing history costs the dates, not the export. Refusing to
		// export because one derived field could not be computed would be the
		// wrong trade for the one command people run when they are leaving.
		changed = nil
		ex.Notes = append(ex.Notes, "could not read history, so change dates are omitted")
	}

	// The site's own redirect map, and the one `quilzo import` writes here,
	// so the addresses that moved keep moving wherever the site goes next.
	var redirects []export.Redirect
	held, err := siteRedirects(root, "redirects.json")
	if err != nil {
		ex.Notes = append(ex.Notes, fmt.Sprintf(
			"redirects.json could not be read, so only the site's own redirects are kept: %v", err))
		held, _ = siteRedirects(root)
	}
	for _, r := range held {
		redirects = append(redirects, export.Redirect{
			From: r.From, To: r.To, Permanent: r.Permanent, Note: r.Note})
	}

	// The deployment's marking, on every exported file. An export is the copy
	// that ends up on removable media or in somebody's home directory, and a
	// file with no marking does not look like one whose marking was lost.
	// Refused when the configuration cannot be read, which used to write the
	// export with no banner at all (deploymentMarking).
	banner, err := deploymentBanner(root)
	if err != nil {
		return nil, errBlocked{err}
	}

	ex.Files, err = export.Export(opts.Format, export.Site{
		Banner: banner,
		// The scheme's own port left out, as the site and site.base_url
		// leave it out: :443 in every link of the export, otherwise.
		Pages: pages, Name: opts.Name, BaseURL: config.SiteBase(opts.BaseURL),
		Changed: changed, Redirects: redirects, Collections: colls,
		Licence: opts.Licence, Publisher: opts.Publisher, Commit: head,
	}, time.Now())
	if err != nil {
		return nil, errBlocked{err}
	}
	return ex, nil
}

// recordExport records that the site was taken out: one "export" record,
// with the same detail from every surface, to naming where it went.
func recordExport(root string, caller *Caller, opts exportOptions, ex *exported, to string) {
	record(root, audit.Record{
		Action: "export", Resource: "/" + opts.Ref, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{
			"format": string(opts.Format), "pages": fmt.Sprintf("%d", ex.Pages),
			"records": fmt.Sprintf("%d", ex.Records),
			"files":   fmt.Sprintf("%d", len(ex.Files)), "to": to,
		},
	})
}

// transferExport is the Transfer screen's Export hook: the one export, for
// whoever is signed in, recorded as every surface's is. It is of the draft,
// as the screen's own was, or of what is published before there is a draft,
// and the site is named and placed from its settings, read at each export.
func transferExport(root string, signedIn func(admin.Actor) *Caller) func(export.Format, admin.Actor) ([]export.File, error) {
	return func(format export.Format, by admin.Actor) ([]export.File, error) {
		s, err := open(root)
		if err != nil {
			return nil, err
		}
		cfg, err := loadConfig(root)
		if err != nil {
			return nil, err
		}
		ref := site.RefDraft
		if s.GetRef(ref) == "" && s.GetRef(site.RefLive) != "" {
			ref = site.RefLive
		}
		caller := signedIn(by)
		opts := exportOptions{Format: format, Ref: ref,
			Name: cfg.Raw("site.name"), BaseURL: cfg.Raw("site.base_url")}
		ex, err := exportSite(root, caller, opts)
		if err != nil {
			return nil, err
		}
		recordExport(root, caller, opts, ex, "download")
		return ex.Files, nil
	}
}

// transferHooks is what the Transfer screen does with this store: its
// export, the one every surface builds, and its import's write.
func transferHooks(root string, s *store.Store, cfg *config.Config, signedIn func(admin.Actor) *Caller) *admin.Transfer {
	return &admin.Transfer{
		Pages: func() (map[string]any, error) { return draftPages(root) },
		// Its own Save rather than the shared one, so what it marks is what it
		// brought in. A transfer is content this program converted out of
		// somebody else's export — a thing it knows — where an ordinary edit
		// is a person writing, which it does not. Marking through the shared
		// path would assert the first about the second.
		Save: func(p map[string]any, msg, by, base string) error {
			if err := saveDraft(root, s, p, msg, by, base); err != nil {
				return err
			}
			markGeneratedQuietly(root, s, by, "brought in by transfer import")
			return nil
		},
		SiteName: cfg.Raw("site.name"), BaseURL: cfg.Raw("site.base_url"),
		// Read at each export, so a scheme changed while this runs is the
		// one an export carries.
		Banner: func() (string, error) { return deploymentBanner(root) },
		// The one export (exportsite.go), so the download carries what
		// `quilzo export` writes.
		Export: transferExport(root, signedIn),
	}
}
