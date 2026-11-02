// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// A draft shared for review with somebody who has no account: a client, a
// colleague elsewhere.
//
//	quilzo share PAGE [--days 7]      a link, to the page as the draft is now
//	quilzo share list
//	quilzo share revoke ID
//
// A link shows one page as it was when it was shared: later edits do not
// reach it, so a link sent last week cannot show somebody what was written
// since. It expires (thirty days at the most), can be revoked, is a random
// id nobody can guess, and is served by the public site at /shared/ID,
// marked not to be indexed, stored or referred onward.

// MaxShareDays is the longest a link lives.
const MaxShareDays = 30

func sharesPath(root string) string { return filepath.Join(root, "shares.json") }

// share is one link.
type share struct {
	ID      string    `json:"id"`
	Page    string    `json:"page"`
	Commit  string    `json:"commit"`
	By      string    `json:"by"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	Revoked time.Time `json:"revoked,omitempty"`
}

func (s share) live(now time.Time) bool { return s.Revoked.IsZero() && now.Before(s.Expires) }

type shares struct {
	Shares []share `json:"shares"`
}

var reShareID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func loadShares(root string) (shares, error) {
	var f shares
	b, err := os.ReadFile(sharesPath(root))
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	return f, json.Unmarshal(b, &f)
}

func changeShares(root string, change func(*shares) error) error {
	unlock, err := atomicfile.Lock(sharesPath(root) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	f, err := loadShares(root)
	if err != nil {
		return err
	}
	if err := change(&f); err != nil {
		return err
	}
	// Links long expired or revoked are let go after a while: the record
	// of them is in the audit log.
	kept := f.Shares[:0]
	for _, s := range f.Shares {
		if time.Since(s.Expires) < 90*24*time.Hour {
			kept = append(kept, s)
		}
	}
	f.Shares = kept
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(sharesPath(root), append(b, '\n'), 0o600)
}

// newShare shares a page of the draft as it is now.
func newShare(root string, s *store.Store, page, by string, days int, now time.Time) (share, error) {
	if days < 1 || days > MaxShareDays {
		return share{}, fmt.Errorf("a link lives 1 to %d days", MaxShareDays)
	}
	commit := s.GetRef(site.RefDraft)
	if commit == "" {
		return share{}, errors.New("there is no draft to share")
	}
	pages, err := site.PagesAt(s, commit)
	if err != nil {
		return share{}, err
	}
	if _, ok := pages[page]; !ok {
		return share{}, fmt.Errorf("the draft has no page called %s", page)
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return share{}, err
	}
	sh := share{ID: hex.EncodeToString(b[:]), Page: page, Commit: commit, By: by, Created: now.UTC(),
		Expires: now.Add(time.Duration(days) * 24 * time.Hour).UTC()}
	return sh, changeShares(root, func(f *shares) error {
		f.Shares = append(f.Shares, sh)
		return nil
	})
}

// revokeShare ends a link at once. page, when given, is the page it must
// be to.
func revokeShare(root, page, id string, now time.Time) (share, error) {
	var out share
	err := changeShares(root, func(f *shares) error {
		for i := range f.Shares {
			if f.Shares[i].ID == id && (page == "" || f.Shares[i].Page == page) {
				if f.Shares[i].Revoked.IsZero() {
					f.Shares[i].Revoked = now.UTC()
				}
				out = f.Shares[i]
				return nil
			}
		}
		return fmt.Errorf("no link %s", id)
	})
	return out, err
}

// shareURL is where a link is opened.
func shareURL(root, id string) string {
	base := strings.TrimRight(mustConfig(root).Raw("site.base_url"), "/")
	if base == "" {
		return "/shared/" + id
	}
	return base + "/shared/" + id
}

// renderShared renders a shared page as it was when it was shared, through
// the site's own layouts: what a reader would have got had it been
// published then. ok is false for a link that is not, or no longer, live.
func renderShared(root string, design *Design, id string, now time.Time) (string, bool) {
	if !reShareID.MatchString(id) {
		return "", false
	}
	f, err := loadShares(root)
	if err != nil {
		return "", false
	}
	var sh *share
	for i := range f.Shares {
		if f.Shares[i].ID == id {
			sh = &f.Shares[i]
		}
	}
	if sh == nil || !sh.live(now) {
		return "", false
	}
	s, err := store.Open(root)
	if err != nil {
		return "", false
	}
	pages, err := site.PagesAt(s, sh.Commit)
	if err != nil {
		return "", false
	}
	body, ok := pages[sh.Page]
	if !ok {
		return "", false
	}
	if design == nil {
		return "", false
	}
	src := sourcesFor(root, s, sh.Commit, siteName(root), pages)
	src.IconStyle = design.Theme.IconStyle()
	// The navigation around it is the published site's, so a link to one
	// draft page does not show the names of every other one in its menus;
	// the blocks the page reuses are the draft's it was shared with.
	src.Blocks = pages
	src.Pages = map[string]any{}
	if live, lerr := site.PagesAt(s, site.RefLive); lerr == nil {
		src.Pages = site.Visible(live, now)
	}
	ctx, err := src.For(sh.Page, body, nil)
	if err != nil {
		return "", false
	}
	_, layout, err := design.Layouts.For(body)
	if err != nil {
		return "", false
	}
	out, err := tmpl.Render(layout, ctx)
	if err != nil {
		return "", false
	}
	return out, true
}

// sharesCapability lets the editor make, list and revoke links; the
// handler has checked who may.
func sharesCapability(root string) *admin.Shares {
	link := func(sh share, now time.Time) admin.ShareLink {
		return admin.ShareLink{ID: sh.ID, URL: shareURL(root, sh.ID), By: sh.By, Expires: sh.Expires, Live: sh.live(now)}
	}
	return &admin.Shares{
		Create: func(page, by string, days int) (admin.ShareLink, error) {
			s, err := store.Open(root)
			if err != nil {
				return admin.ShareLink{}, err
			}
			now := time.Now()
			sh, err := newShare(root, s, page, by, days, now)
			if err != nil {
				return admin.ShareLink{}, err
			}
			return link(sh, now), nil
		},
		For: func(page string) ([]admin.ShareLink, error) {
			f, err := loadShares(root)
			if err != nil {
				return nil, err
			}
			now := time.Now()
			var out []admin.ShareLink
			for _, sh := range f.Shares {
				// Ended links are listed for a week, then only in the log.
				if sh.Page == page && (sh.live(now) || now.Sub(sh.endedAt()) < 7*24*time.Hour) {
					out = append(out, link(sh, now))
				}
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Expires.After(out[j].Expires) })
			return out, nil
		},
		Revoke: func(page, id, by string) error {
			if !reShareID.MatchString(id) {
				return errors.New("that is not a link")
			}
			_, err := revokeShare(root, page, id, time.Now())
			return err
		},
	}
}

func (s share) endedAt() time.Time {
	if !s.Revoked.IsZero() && s.Revoked.Before(s.Expires) {
		return s.Revoked
	}
	return s.Expires
}

func cmdShare(root string, args []string) error {
	caller := resolveCaller(root, flagToken)
	if len(args) == 0 {
		return errors.New("usage: quilzo share PAGE [--days 7] | list | revoke ID")
	}
	switch args[0] {
	case "list":
		if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
			return err
		}
		f, err := loadShares(root)
		if err != nil {
			return err
		}
		now := time.Now()
		sort.Slice(f.Shares, func(i, j int) bool { return f.Shares[i].Created.After(f.Shares[j].Created) })
		if w.JSON(f.Shares) {
			return nil
		}
		for _, s := range f.Shares {
			state := green + "until " + s.Expires.Local().Format("2 Jan 15:04") + reset
			if !s.Revoked.IsZero() {
				state = dim + "revoked" + reset
			} else if !s.live(now) {
				state = dim + "expired" + reset
			}
			w.Human("%s%s%s  %s, shared by %s  [%s]\n    %s\n", bold, s.Page, reset, s.ID, s.By, state, shareURL(root, s.ID))
		}
		return nil
	case "revoke":
		if len(args) != 2 {
			return errors.New("usage: quilzo share revoke ID")
		}
		// Whoever may edit the page the link is to may end it.
		f, err := loadShares(root)
		if err != nil {
			return err
		}
		page := "/"
		for _, s := range f.Shares {
			if s.ID == args[1] {
				page = "/" + s.Page
			}
		}
		if err := authorise(root, caller, auth.ActEditDraft, page); err != nil {
			return err
		}
		sh, err := revokeShare(root, "", args[1], time.Now())
		if err != nil {
			return err
		}
		record(root, caller.auditRecord("share.revoked", "/"+sh.Page, audit.Success, map[string]string{"share": sh.ID}))
		w.Human("  %srevoked: the link shows nothing from now on%s\n", green, reset)
		return nil
	}
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	days := fs.Int("days", 7, "how many days the link lives, up to 30")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: quilzo share PAGE [--days 7]")
	}
	// Sharing a draft shows it to somebody outside: whoever may publish the
	// page may, since publishing shows it to everybody.
	if err := authorise(root, caller, auth.ActPublish, "/"+rest[0]); err != nil {
		return err
	}
	s, err := store.Open(root)
	if err != nil {
		return err
	}
	sh, err := newShare(root, s, rest[0], caller.Name, *days, time.Now())
	if err != nil {
		return err
	}
	record(root, caller.auditRecord("share.created", "/"+sh.Page, audit.Success, map[string]string{
		"share": sh.ID, "days": strconv.Itoa(*days), "commit": sh.Commit[:min(12, len(sh.Commit))]}))
	if w.JSON(map[string]any{"id": sh.ID, "url": shareURL(root, sh.ID), "expires": sh.Expires}) {
		return nil
	}
	w.Human("%s%s%s\n  %sthe page as the draft is now, until %s; quilzo share revoke %s ends it%s\n",
		bold, shareURL(root, sh.ID), reset, dim, sh.Expires.Local().Format("2 Jan 15:04"), sh.ID, reset)
	return nil
}
