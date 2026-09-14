// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

// Moving a page, and everything under it.
//
// # Why there was no way to do this
//
// A page's name is where it is: the slash has been structure to the store, to
// the public server and to auth.covers since each of them existed. So moving a
// page is renaming it — and renaming was `add` the new one, `add --remove` the
// old one, and then find out at the publish gate which other pages named it.
//
// Nobody does that twice. What people do instead is leave the page where it is
// and put a link to it somewhere, which is how a site's structure stops being
// its names and starts being a menu that disagrees with them.
//
// # What makes it safe now
//
// schema.Store.Links answers what points at a page, which until recently
// nothing could. So a move can carry the references with it rather than
// breaking them and letting the publish gate complain afterwards about pages
// somebody changed for unrelated reasons.
//
// Three things are moved together, because a move that does two of them is a
// worse state than one that does none:
//
//   - the page, and every page beneath it
//   - every reference field naming any of them
//   - every menu entry pointing at any of them, which menu.Retarget was
//     written for and had one caller
//
// One commit. A move is one act and reads as one in the history, and a partial
// one cannot be left behind by a crash between two writes.

func cmdMove(root string, args []string) error {
	fs := flag.NewFlagSet("move", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "say what would move and change nothing")
	pos, flags := leadingArgs(args, 2)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf(
			"usage: quilzo move OLD NEW [--dry-run]\n" +
				"  moves the page and everything under it, and carries every\n" +
				"  reference and menu entry that names them")
	}
	from, to := strings.Trim(pos[0], "/"), strings.Trim(pos[1], "/")
	if from == to {
		return fmt.Errorf("%q is already where it is", from)
	}
	if strings.HasPrefix(to, from+"/") {
		return fmt.Errorf(
			"%q is inside %q, so the move would have to happen to itself",
			to, from)
	}

	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActEditDraft, "/"+from); err != nil {
		return err
	}
	// Both ends. Moving a page out of a subtree somebody is confined to is
	// taking it out of their reach, and moving one in is putting content where
	// they may not have meant to.
	if err := authorise(root, caller, auth.ActEditDraft, "/"+to); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		return err
	}

	moving := site.Under(pages, from)
	if len(moving) == 0 {
		return fmt.Errorf("there is no page called %q, and nothing under it",
			from)
	}
	renames := map[string]string{}
	for _, name := range moving {
		next := to + strings.TrimPrefix(name, from)
		if _, taken := pages[next]; taken {
			return fmt.Errorf(
				"%s is already a page, and moving %s here would replace it",
				next, name)
		}
		renames[name] = next
	}

	st, err := schema.Load(root)
	if err != nil {
		return err
	}
	// What points at anything being moved, before it moves.
	incoming := map[string][]schema.Link{}
	for _, name := range moving {
		if links := st.LinksTo(pages, name); len(links) > 0 {
			incoming[name] = links
		}
	}

	if *dry {
		return sayWhatWouldMove(moving, renames, incoming, root, from)
	}

	// The pages themselves.
	next := map[string]any{}
	for name, body := range pages {
		if to, moved := renames[name]; moved {
			next[to] = body
			continue
		}
		next[name] = body
	}
	// And every reference to them, through the same function menu.Retarget is
	// the counterpart of. Over the renamed set, because a page that names
	// something being moved may itself be moving.
	changedRefs := 0
	for was, now := range renames {
		changedRefs += len(st.Retarget(next, was, now))
	}

	// The same gate every other write passes. A move does not change what a
	// page says, so it cannot make one invalid — but the check is here rather
	// than exempted, because "this one cannot fail" is the sentence that
	// precedes the one that does.
	types, err := gateWrite(root, next)
	if err != nil {
		return err
	}
	commit, err := site.SaveDraftFrom(s, next, fmt.Sprintf("move %s to %s",
		from, to), caller.Name, s.GetRef(site.RefDraft))
	if err != nil {
		return err
	}
	// The type bindings follow the names, or a moved page stops being
	// validated and a later page of the old name is silently bound to
	// something nobody chose.
	if types != nil {
		moved := false
		for was, now := range renames {
			if bound, is := types.Bound[was]; is {
				delete(types.Bound, was)
				types.Bound[now] = bound
				moved = true
			}
		}
		if moved {
			if serr := types.Save(); serr != nil {
				return fmt.Errorf("the pages moved and their type bindings "+
					"did not: %w", serr)
			}
		}
	}

	// The menus, which live outside the content store and so are a second
	// write. Done after the content because a menu pointing at a page that is
	// not there yet is the state menu.Broken refuses; the other order would be
	// briefly wrong on disk.
	changedMenus := 0
	if set, merr := loadMenus(root); merr == nil && set != nil {
		for was, now := range renames {
			changedMenus += set.Retarget(was, now)
		}
		if changedMenus > 0 {
			if serr := saveJSON(menuPath(root), set); serr != nil {
				return fmt.Errorf(
					"the pages moved and the menus did not: %w\n"+
						"  quilzo structure — the entries still name the old "+
						"place", serr)
			}
		}
	}

	record(root, caller.auditRecord("content.move", "/"+from, audit.Success,
		map[string]string{
			"to": to, "pages": fmt.Sprint(len(moving)),
			"references": fmt.Sprint(changedRefs),
			"menus":      fmt.Sprint(changedMenus),
			"commit":     short(commit),
		}))

	if w.JSON(map[string]any{
		"from": from, "to": to, "pages": len(moving),
		"references": changedRefs, "menus": changedMenus,
		"commit": commit,
	}) {
		return nil
	}
	w.Human("moved %s to %s\n", from, to)
	w.Human("  %s%s%s\n", dim, count(len(moving), "page"), reset)
	if changedRefs > 0 {
		w.Human("  %s%s updated to point at the new place%s\n",
			dim, count(changedRefs, "reference"), reset)
	}
	if changedMenus > 0 {
		w.Human("  %s%s retargeted%s\n",
			dim, count(changedMenus, "menu entry"), reset)
	}
	// The one thing a move leaves behind. Said here rather than left to be
	// discovered by a reader following a link somebody sent them last month.
	w.Human("  %sthe old addresses now answer 404. `quilzo site "+
		"--redirects redirects.json` keeps them working%s\n", dim, reset)
	return nil
}

// sayWhatWouldMove is the dry run.
func sayWhatWouldMove(moving []string, renames map[string]string,
	incoming map[string][]schema.Link, root, from string) error {

	refs := 0
	for _, links := range incoming {
		refs += len(links)
	}
	menus := 0
	if set, err := loadMenus(root); err == nil && set != nil {
		for _, name := range moving {
			menus += len(set.Mentioning(name))
		}
	}

	if w.JSON(map[string]any{
		"pages": moving, "renames": renames,
		"references": refs, "menus": menus, "dry_run": true,
	}) {
		return nil
	}
	sort.Strings(moving)
	for _, name := range moving {
		w.Human("  %s  %s→%s  %s\n", name, dim, reset, renames[name])
	}
	w.Human("\n%s would move\n", count(len(moving), "page"))
	if refs > 0 {
		w.Human("  %s%s would be updated%s\n", dim, count(refs, "reference"), reset)
	}
	if menus > 0 {
		w.Human("  %s%s would be retargeted%s\n",
			dim, count(menus, "menu entry"), reset)
	}
	return nil
}
