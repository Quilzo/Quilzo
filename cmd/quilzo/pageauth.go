// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"

	"github.com/quilzo/quilzo/internal/auth"
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
	return func(page string) bool {
		res := pageResource(page)
		d := p.Evaluate(c.Name, action, res)
		return d.Allowed && auth.CheckGranted(d, c.Role, c.Scope, c.Limits, action, res) == nil
	}, nil
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
func everyPage(root string, c *Caller, pages map[string]any) error {
	may, err := pageCheck(root, c, auth.ActView)
	if err != nil {
		return err
	}
	var hidden []string
	for name := range pages {
		if !may(name) {
			hidden = append(hidden, name)
		}
	}
	if len(hidden) == 0 {
		return nil
	}
	sort.Strings(hidden)
	return fmt.Errorf("this reads every page, and %d of them are not %s's to read (%s)",
		len(hidden), c.Name, nameSome(hidden))
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
		nameSome(denied), c.Name)
}

// everyDraftPage is everyPage over the draft as it stands.
func everyDraftPage(root string, s *store.Store, c *Caller) error {
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		return err
	}
	return everyPage(root, c, pages)
}
