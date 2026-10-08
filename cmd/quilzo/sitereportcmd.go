// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/sitereport"
	"github.com/quilzo/quilzo/internal/store"
)

// The site report: what the law asks of the published site and where it
// stands (internal/sitereport). Each part is read by the check that already
// owns it — the accessibility gate's renderer, the publish gate's personal
// data scan, posture's AI rules, the site's own handler for its headers —
// so this report and those checks cannot disagree.

// buildSiteReport reads the live site into a report.
func buildSiteReport(root, tplDir string, now time.Time) (sitereport.Report, error) {
	s, err := open(root)
	if err != nil {
		return sitereport.Report{}, err
	}
	live := s.GetRef(site.RefLive)
	if live == "" {
		return sitereport.Report{}, errors.New("nothing is published, so there is no site to report on; " +
			"`quilzo publish` puts the draft live")
	}
	in := sitereport.Input{Site: siteName(root), Organisation: organisationOf(root),
		Version: version, At: now, Live: live}
	cfg, cerr := loadConfig(root)
	if cerr == nil {
		in.Address = strings.TrimSpace(cfg.Raw("site.base_url"))
	}

	if reports, err := checkAccessibility(root, s, live, tplDir); err == nil {
		in.ACR = a11y.BuildACR(reports)
	} else {
		in.ACRUnread = err.Error()
	}

	if pages, err := site.PagesAt(s, live); err != nil {
		in.PIIUnread = err.Error()
	} else {
		in.StatementPage = statementPage(pages)
		blocking, advisory := personalDataIn(root, pages)
		for _, f := range blocking {
			in.PersonalData = append(in.PersonalData, sitereport.Item{Page: f.Page, Detail: f.Detail, Blocking: true})
		}
		for _, f := range advisory {
			in.PersonalData = append(in.PersonalData, sitereport.Item{Page: f.Page, Detail: f.Detail})
		}
	}

	if set, err := loadForms(root); err != nil {
		in.FormsUnread = err.Error()
	} else if set != nil {
		for _, f := range set.Forms {
			rf := sitereport.Form{Name: f.Name, Label: f.Label, Purpose: f.Purpose, Basis: f.Basis,
				RetentionDays: int(f.Retention().Hours() / 24), Closed: f.Closed, Lawful: f.Lawful()}
			for _, fl := range f.Fields {
				if fl.Sensitive {
					rf.Sensitive = append(rf.Sensitive, fl.Name)
				}
			}
			in.Forms = append(in.Forms, rf)
		}
	}

	if h, err := servedHeaders(root, tplDir); err != nil {
		in.HeadersUnread = err.Error()
	} else {
		how := sitereport.Served{Address: in.Address}
		if cerr == nil {
			how.Proxied = strings.TrimSpace(cfg.Raw("network.trusted_proxies")) != "" || cfg.Bool("site.trusted_proxy")
		}
		in.Headers = sitereport.GradeHeaders(h, how)
	}

	rules := posture.RuleIndex()
	events, _ := audit.Read(auditPath(root))
	ai := observeAI(root, tplDir, events)
	for _, c := range ai.Chatbots {
		if c.Public {
			in.Assistants++
		}
	}
	for _, f := range rules["ai.chatbot-undisclosed"].Check(posture.State{AI: ai}) {
		in.Undisclosed = append(in.Undisclosed, sitereport.Item{Page: f.Resource, Detail: f.Detail, Fix: f.Fix})
	}

	if content, err := provenanceFacts(root, s, live); err != nil {
		in.MarkingUnread = err.Error()
	} else {
		for _, id := range []string{"content.unmarked-ai", "content.stale-provenance"} {
			for _, f := range rules[id].Check(posture.State{Content: content}) {
				in.Unmarked = append(in.Unmarked, sitereport.Item{Detail: f.Detail, Fix: f.Fix})
			}
		}
	}
	return sitereport.Build(in), nil
}

// provenanceFacts is the half of observeContent the marking duty needs,
// without rendering every page a second time. A provenance file that is
// there and cannot be read is a check that did not run.
func provenanceFacts(root string, s *store.Store, live string) (posture.ContentFacts, error) {
	var c posture.ContentFacts
	tree, err := pageHashes(s, live)
	if err != nil {
		return c, err
	}
	idx, err := loadProvenance(root)
	if err != nil {
		return c, err
	}
	for page := range tree {
		c.LivePages = append(c.LivePages, page)
	}
	sort.Strings(c.LivePages)
	for _, p := range provenance.Check(idx, tree) {
		switch {
		case !p.Have:
			c.UnmarkedPages = append(c.UnmarkedPages, p.Page)
		case p.Stale:
			c.StalePages = append(c.StalePages, p.Page)
		}
	}
	return c, nil
}

// statementPage is the published page that is an accessibility statement:
// one named for it, or titled it.
func statementPage(pages map[string]any) string {
	for _, name := range []string{"accessibility", "accessibility-statement", "accessibility_statement"} {
		if _, ok := pages[name]; ok {
			return name
		}
	}
	for _, name := range sortedNames(pages) {
		p, _ := pages[name].(map[string]any)
		if title, _ := p["title"].(string); strings.Contains(strings.ToLower(title), "accessibility statement") {
			return name
		}
	}
	return ""
}

// servedHeaders asks the site, built exactly as `quilzo site` builds it, for
// its home page in this process, and returns the headers it sent. Graded
// from a response rather than from the configuration, so a header the
// configuration implies and the server does not send is a header missing.
// Nothing is counted: the counter is attached by `quilzo site`, not here.
func servedHeaders(root, tplDir string) (http.Header, error) {
	design, err := loadDesign(tplDir)
	if err != nil {
		return nil, err
	}
	st, err := siteFor(root, design, siteOpts{})
	if err != nil {
		return nil, err
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "quilzo-site-report")
	st.Handler().ServeHTTP(rec, req)
	return rec.Result().Header, nil
}

// complianceSite prints the site report, or with --statement only the draft
// accessibility statement, as text a page can be written from.
func complianceSite(root string, args []string) error {
	fs := flag.NewFlagSet("site", flag.ContinueOnError)
	tplDir := fs.String("templates", "templates", "where the layouts live")
	statement := fs.Bool("statement", false, "print only the draft accessibility statement, as Markdown")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rep, err := buildSiteReport(root, *tplDir, time.Now())
	if err != nil {
		return err
	}
	if *statement {
		if w.JSON(rep.Statement) {
			return nil
		}
		fmt.Print(rep.Statement.Markdown())
		if len(rep.Statement.ToFill) > 0 {
			w.Human("\n%sto fill in before publishing it:%s\n", yellow, reset)
			for _, f := range rep.Statement.ToFill {
				w.Human("  %s- %s%s\n", dim, f, reset)
			}
		}
		return nil
	}
	if w.JSON(rep) {
		return nil
	}
	name := rep.Site
	if name == "" {
		name = "this site"
	}
	w.Human("%sWhat the law asks of %s%s  %s\n\n", bold, name, reset, rep.At.Format("2 January 2006"))
	colour := map[sitereport.State]string{sitereport.Attention: red, sitereport.Review: yellow,
		sitereport.Unknown: yellow, sitereport.Clear: green}
	for _, d := range rep.Duties {
		w.Human("  %s%-9s%s %s%s%s\n", colour[d.State], d.State, reset, bold, d.Title, reset)
		w.Human("            %s%s%s\n", dim, d.Law, reset)
		w.Human("            %s\n", d.Says)
		if d.Fix != "" {
			w.Human("            %sfix:%s %s\n", dim, reset, d.Fix)
		}
		w.Human("\n")
	}
	if len(rep.Headers) > 0 {
		w.Human("  %sBrowser protections%s\n", bold, reset)
		for _, h := range rep.Headers {
			c := green
			switch h.Grade {
			case sitereport.Weak, sitereport.Elsewhere:
				c = yellow
			case sitereport.Unchecked:
				c = dim
			case sitereport.Missing:
				c = red
			}
			w.Human("    %s%-9s%s %-28s %s%s%s\n", c, h.Grade, reset, h.Name, dim, h.Why, reset)
		}
		w.Human("\n")
	}
	for _, it := range rep.PersonalData {
		mark := yellow + "look"
		if it.Blocking {
			mark = red + "remove"
		}
		w.Human("  %s%s %s: %s\n", mark, reset, it.Page, it.Detail)
	}
	w.Human("\n  %squilzo compliance site --statement   the draft accessibility statement%s\n", dim, reset)
	w.Human("  %squilzo compliance accessibility      the conformance report, criterion by criterion%s\n", dim, reset)
	w.Human("\n  %s%s%s\n", dim, rep.Caveat, reset)
	return nil
}
