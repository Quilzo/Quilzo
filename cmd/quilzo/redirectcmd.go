// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/seo"
)

// The site's own redirects: an old address sent to where its page is now.
//
//	quilzo redirect list
//	quilzo redirect add FROM TO [--temporary] [--note TEXT]
//	quilzo redirect remove FROM
//
// Kept in the store's redirects.json, which a site import writes too, and
// read again by the running site when it changes, so a redirect works
// without a restart. A redirect is served before any page and changes the
// live site at once, with no draft to review, so it takes what publishing
// takes.

// addSiteRedirect adds one, or replaces the one from the same address.
func addSiteRedirect(root string, r seo.Redirect) error {
	from, err := seo.Path(r.From)
	if err != nil {
		return err
	}
	r.From = from
	var f redirectFile
	if err := loadRedirectFile(storeRedirectsPath(root), &f); err != nil {
		return err
	}
	next := make([]seo.Redirect, 0, len(f.Redirects)+1)
	for _, x := range f.Redirects {
		if p, err := seo.Path(x.From); err == nil && p == from {
			continue
		}
		next = append(next, x)
	}
	next = append(next, r)
	if _, err := seo.NewMap(next); err != nil {
		return fmt.Errorf("that redirect would not hold together with the others: %w", err)
	}
	return saveJSON(storeRedirectsPath(root), redirectFile{Redirects: next})
}

// removeSiteRedirect takes one away.
func removeSiteRedirect(root, from string) error {
	from, err := seo.Path(from)
	if err != nil {
		return err
	}
	var f redirectFile
	if err := loadRedirectFile(storeRedirectsPath(root), &f); err != nil {
		return err
	}
	var next []seo.Redirect
	found := false
	for _, x := range f.Redirects {
		if p, err := seo.Path(x.From); err == nil && p == from {
			found = true
			continue
		}
		next = append(next, x)
	}
	if !found {
		return fmt.Errorf("no redirect from %s", from)
	}
	if len(next) == 0 {
		if err := os.Remove(storeRedirectsPath(root)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return saveJSON(storeRedirectsPath(root), redirectFile{Redirects: next})
}

// reloadingRedirects is the redirect map as the files say now: read again
// at most once a second, and rebuilt only when what they hold changed. A
// file that no longer holds together keeps the map that did, rather than
// dropping every redirect.
func reloadingRedirects(root, file string, start *seo.Map) func() *seo.Map {
	var (
		mu      sync.Mutex
		current = start
		sum     [32]byte
		checked time.Time
	)
	digest := func() [32]byte {
		h := sha256.New()
		for _, p := range []string{file, storeRedirectsPath(root)} {
			if p == "" {
				continue
			}
			b, _ := os.ReadFile(p)
			h.Write([]byte(p + "\x00"))
			h.Write(b)
			h.Write([]byte{0})
		}
		var out [32]byte
		copy(out[:], h.Sum(nil))
		return out
	}
	sum = digest()
	return func() *seo.Map {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(checked) < time.Second {
			return current
		}
		checked = time.Now()
		if d := digest(); d != sum {
			if m, err := servedRedirects(root, file); err == nil {
				current, sum = m, d
			}
		}
		return current
	}
}

func cmdRedirect(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	caller := resolveCaller(root, flagToken)
	switch args[0] {
	case "list":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		rs, err := siteRedirects(root)
		if err != nil {
			return err
		}
		if w.JSON(rs) {
			return nil
		}
		if len(rs) == 0 {
			w.Human("  %sno redirects; quilzo redirect add FROM TO makes one%s\n", dim, reset)
			return nil
		}
		for _, r := range rs {
			kind := "permanent"
			if !r.Permanent {
				kind = "temporary"
			}
			w.Human("%s%s%s -> %s  %s(%s)%s\n", bold, r.From, reset, r.To, dim, kind, reset)
		}
		return nil
	case "add":
		fs := flag.NewFlagSet("redirect add", flag.ContinueOnError)
		temporary := fs.Bool("temporary", false, "a temporary redirect (307) rather than a permanent one (308)")
		note := fs.String("note", "", "why it is there, for whoever finds it later")
		pos, flags := leadingArgs(args[1:], 2)
		if err := parseFlags(fs, flags, &pos, 2); err != nil {
			return err
		}
		if len(pos) != 2 {
			return errors.New("usage: quilzo redirect add FROM TO [--temporary] [--note TEXT]")
		}
		if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
			return err
		}
		r := seo.Redirect{From: pos[0], To: strings.TrimSpace(pos[1]), Permanent: !*temporary, Note: clip(*note, 200)}
		if err := addSiteRedirect(root, r); err != nil {
			return err
		}
		record(root, caller.auditRecord("redirect.added", r.From, audit.Success, map[string]string{"to": r.To}))
		w.Human("  %s%s now goes to %s%s\n", green, r.From, r.To, reset)
		return nil
	case "remove", "rm":
		if len(args) != 2 {
			return errors.New("usage: quilzo redirect remove FROM")
		}
		if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
			return err
		}
		if err := removeSiteRedirect(root, args[1]); err != nil {
			return err
		}
		record(root, caller.auditRecord("redirect.removed", args[1], audit.Success, nil))
		w.Human("  %sremoved%s\n", green, reset)
		return nil
	}
	return fmt.Errorf("unknown redirect command %q; try list, add or remove", args[0])
}
