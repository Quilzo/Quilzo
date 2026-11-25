// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Asking about each page, wherever pages are touched in bulk.
//
// A binding can be scoped to part of the site: a grant `--on /blog`, or a
// deny on /legal. Asked about "/", neither is seen. The grant does not
// cover "/", so the person it was given to could not use the machine
// interface at all; and the deny does not cover "/" either, so whoever it
// was meant to stop could read, list, search, export and write /legal over
// MCP, and publish a draft that changed it from anywhere, because every one
// of those asked about the whole site. privilege.go fixed this for the
// commands that name one page. These are the operations that touch many.

// pageCheck answers, for one caller and one action, whether a page may be
// touched: the policy is read once and every page asked about its own path,
// with the caller's credential capping each answer as authorise does.
func pageCheck(root string, c *Caller, action auth.Action) (func(page string) bool, error) {
	inUse, err := policyInUse(root)
	if err != nil {
		return nil, err
	}
	if !inUse {
		return func(string) bool { return true }, nil
	}
	if !c.Verified {
		return func(string) bool { return false }, nil
	}
	p, err := loadPolicy(root)
	if err != nil {
		return nil, err
	}
	limits := contentLimits(root, c)
	return func(page string) bool {
		res := pageResource(page)
		d := p.Evaluate(c.Name, action, res)
		return d.Allowed && auth.CheckGranted(d, c.Role, c.Scope, c.Limits, action, res) == nil &&
			limits(action, res) == ""
	}, nil
}

// contentLimits answers, for a caller whose credential is limited to some
// content types or languages, why a page is out of its reach: "" when it is
// not. The type is the one the page is bound to and the language the one
// its own fields give, in the draft or else on the live site, which is how
// the content API and an agent run read both.
//
// Asked by authorise and pageCheck because nothing else here asked it. A
// token issued `--types policy` wrote the product pages from a terminal and
// over /mcp, and one issued `--locales fr` the English ones, while the
// content API refused the same token the same pages. A resource that is not
// a page is not asked: a collection is asked by auth.CheckCredential, and the
// whole site and the areas are no one type or language.
func contentLimits(root string, c *Caller) func(action auth.Action, resource string) string {
	if c == nil || !c.Limits.LimitsContent() {
		return func(auth.Action, string) string { return "" }
	}
	var (
		loaded      bool
		bound       map[string]string
		draft, live map[string]any
	)
	return func(action auth.Action, resource string) string {
		if auth.IsArea(resource) || strings.Trim(resource, "/") == "" {
			return ""
		}
		if !loaded {
			loaded = true
			if st, err := schema.Load(root); err == nil && st != nil {
				bound = st.Bound
			}
			if s, err := open(root); err == nil {
				draft, _ = site.PagesAt(s, site.RefDraft)
				live, _ = site.PagesAt(s, site.RefLive)
			}
		}
		page := strings.Trim(resource, "/")
		fields, ok := draft[page]
		if !ok {
			fields = live[page]
		}
		return c.Limits.Why(action, bound[page], auth.PageLocale(fields))
	}
}

// writeLimits is contentLimits for a page as a command is about to write it:
// why a caller whose credential is limited to some content types or
// languages may not store these fields under this name, or "" when it may.
// The type is the one the name is bound to and the language the one the new
// fields give, as the content API's PUT asks of its body.
//
// authorise asks about a page as it stands, before the command has read what
// it is to write, so a token issued `--locales fr` stored the French returns
// page as English, and started English pages, with `quilzo add`, `quilzo
// import` and write_page, while the content API refused the same token the
// same write.
func writeLimits(root string, c *Caller, page string, fields any) string {
	if c == nil || !c.Limits.LimitsContent() {
		return ""
	}
	typeName := ""
	if st, err := schema.Load(root); err == nil && st != nil {
		typeName = st.Bound[page]
	}
	return c.Limits.Why(auth.ActEditDraft, typeName, auth.PageLocale(fields))
}

// visiblePages keeps the pages a caller may read.
func visiblePages(root string, c *Caller, pages map[string]any) (map[string]any, error) {
	may, err := pageCheck(root, c, auth.ActView)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(pages))
	for name, body := range pages {
		if may(name) {
			out[name] = body
		}
	}
	return out, nil
}

// everyPage refuses an operation over the whole site, such as an export,
// when some of its pages are not the caller's to read. Refused rather than
// left out: an export that silently lacks a section is a copy somebody
// keeps believing is complete.
//
// The pages are counted and not named. list_pages, find and search leave a
// page the caller may not read out as though it were not there, and this
// refusal named them, so a reader denied /hr asking for an export was told
// "hr/salaries": the one thing the deny was for, since a page's name often
// says what it is about.
func everyPage(root string, c *Caller, pages map[string]any) error {
	may, err := pageCheck(root, c, auth.ActView)
	if err != nil {
		return err
	}
	hidden := 0
	for name := range pages {
		if !may(name) {
			hidden++
		}
	}
	if hidden == 0 {
		return nil
	}
	return fmt.Errorf("this reads every page, and %s not %s's to read; an administrator can say which",
		plural2(hidden, "one of them is", "of them are"), c.Name)
}

// readableOrCounted names the pages a caller may read among pages, and
// only counts the rest, for a refusal: a page out of the caller's reach is
// left out of everything they are shown, so a refusal is not where its
// name may reach them either (everyPage).
func readableOrCounted(pages []string, mayRead func(string) bool, who string) string {
	var named []string
	hidden := 0
	for _, p := range pages {
		if mayRead(p) {
			named = append(named, p)
		} else {
			hidden++
		}
	}
	if hidden == 0 {
		return nameSome(named)
	}
	rest := plural2(hidden, "one page that is", "pages that are") + " not " + who + "'s to read"
	if len(named) == 0 {
		return rest
	}
	return nameSome(named) + " and " + rest
}

// changesTo are the pages publishing a commit would change: the draft when
// to is empty, otherwise the ref or commit named.
func changesTo(s *store.Store, to string) ([]string, error) {
	if to == "" {
		to = site.RefDraft
	}
	if c := s.GetRef(to); c != "" {
		to = c
	}
	changes, err := site.Diff(s, s.GetRef(site.RefLive), to)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ch := range changes {
		id := ch.After
		if id == "" {
			id = ch.Before
		}
		if s.IsTree(id) {
			continue // records, which publishing checks as records
		}
		out = append(out, ch.Path)
	}
	return out, nil
}

// mayPublishChanges refuses a publish that would change a page the caller
// may not publish, which a check on "/" alone cannot see. to is what is
// being published: the draft when empty.
func mayPublishChanges(root string, s *store.Store, c *Caller, to string) error {
	may, err := pageCheck(root, c, auth.ActPublish)
	if err != nil {
		return err
	}
	mayRead, err := pageCheck(root, c, auth.ActView)
	if err != nil {
		return err
	}
	pages, err := changesTo(s, to)
	if err != nil {
		return err
	}
	var denied []string
	for _, p := range pages {
		if !may(p) {
			denied = append(denied, p)
		}
	}
	if len(denied) == 0 {
		return nil
	}
	return fmt.Errorf("publishing the draft would change %s, which %s may not publish",
		readableOrCounted(denied, mayRead, c.Name), c.Name)
}

// everyDraftPage is everyPage over the draft as it stands.
func everyDraftPage(root string, s *store.Store, c *Caller) error {
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		return err
	}
	return everyPage(root, c, pages)
}
