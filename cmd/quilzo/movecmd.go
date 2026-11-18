// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
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
// Four things are moved together, because a move that does some of them is a
// worse state than one that does none:
//
//   - the page, and every page beneath it
//   - every reference field naming any of them
//   - every reuse of any of them as a block (site.RetargetBlocks), which was
//     left naming the old place, so the pages reusing a renamed block showed
//     nothing there and the move did not say so
//   - every menu entry pointing at any of them, which menu.Retarget was
//     written for and had one caller
//
// One commit. A move is one act and reads as one in the history, and a partial
// one cannot be left behind by a crash between two writes.

func cmdMove(root string, args []string) error {
	fs := flag.NewFlagSet("move", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "say what would move and change nothing")
	pos, flags := leadingArgs(args, 2)
	if err := parseFlags(fs, flags, &pos, 2); err != nil {
		return err
	}
	if len(pos) != 2 {
		return errMisused{fmt.Errorf(
			"usage: quilzo move OLD NEW [--dry-run]\n" +
				"  moves the page and everything under it, and carries every\n" +
				"  reference and menu entry that names them")}
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
	base, pages, err := draftRead(s)
	if err != nil {
		return err
	}

	moving := site.Under(pages, from)
	if len(moving) == 0 {
		return errNotFound{fmt.Errorf("there is no page called %q, and nothing under it",
			from)}
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

	// The pages reusing anything being moved as a block. A reuse is a
	// reference, and one left naming the old place shows nothing there.
	reuses := []string{}
	reusing := map[string]bool{}
	uses := site.BlockUses(pages)
	for _, name := range moving {
		for _, u := range uses[name] {
			if !reusing[u] {
				reusing[u] = true
				reuses = append(reuses, u)
			}
		}
	}
	sort.Strings(reuses)

	if *dry {
		return sayWhatWouldMove(moving, renames, incoming, reuses, root, from)
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
	// Every page this writes: the ones moving, under the names they had, and
	// the ones a reference or a reuse was rewritten in. For telling whoever
	// has claimed one of them (claimsByOthers), below.
	written := append([]string(nil), moving...)
	for was, now := range renames {
		pointing := st.Retarget(next, was, now)
		changedRefs += len(pointing)
		written = append(written, pointing...)
		written = append(written, site.RetargetBlocks(next, was, now)...)
	}

	// The same gate every other write passes. A move does not change what a
	// page says, so it cannot make one invalid — but the check is here rather
	// than exempted, because "this one cannot fail" is the sentence that
	// precedes the one that does.
	types, err := gateWrite(root, next)
	if err != nil {
		return err
	}
	// Against the draft the move was worked out from. A page somebody
	// changed while it was being moved is refused (the merge cannot say
	// whether the old name or the new one was meant), and anything else they
	// did is kept.
	commit, _, err := site.SaveDraftOver(s, next, fmt.Sprintf("move %s to %s",
		from, to), caller.Name, base)
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

	// The provenance follows the names too, as the type bindings do. A
	// record is keyed by a page's name and bound to its bytes, and a move
	// changes the one and, where it rewrites a reference, the other: left
	// behind, a page a model wrote read as "unrecorded" under its new name,
	// the publish gate offered the waiver it offers for hand-written pages,
	// and once somebody used it the model's words went out with no mark.
	carried, perr := carryProvenance(root, s, base, commit, renames, written, next)
	if perr != nil {
		return fmt.Errorf("the pages moved and their provenance did not: %w\n"+
			"  quilzo provenance check — the moved pages read as unrecorded", perr)
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
						"  quilzo menu check — the entries still name the old "+
						"place", serr)
			}
		}
	}

	record(root, caller.auditRecord("content.move", "/"+from, audit.Success,
		map[string]string{
			"to": to, "pages": fmt.Sprint(len(moving)),
			"references": fmt.Sprint(changedRefs),
			"menus":      fmt.Sprint(changedMenus),
			"reuses":     fmt.Sprint(len(reuses)),
			"provenance": fmt.Sprint(carried),
			"commit":     short(commit),
		}))

	// Somebody else's claim on a page this wrote. A move renamed the page
	// pat was half way through rewriting, or rewrote a reference in it, and
	// said nothing, where `quilzo add` and the browser's editor say who holds
	// it: his next save was refused and he had not been told why.
	claims := claimsByOthers(root, caller.Name, written)
	if w.JSON(map[string]any{
		"from": from, "to": to, "pages": len(moving),
		"references": changedRefs, "menus": changedMenus,
		"reuses": reuses, "commit": commit, "claimed": claims,
		"provenance": carried,
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
	if len(reuses) > 0 {
		w.Human("  %sthe block now shows on %s under its new name%s\n",
			dim, strings.Join(reuses, ", "), reset)
	}
	if carried > 0 {
		w.Human("  %swho or what wrote %s goes with it%s\n",
			dim, count(carried, "page"), reset)
	}
	sayOldAddresses(renames)
	sayClaims(claims)
	return nil
}

// sayOldAddresses is the one thing a move leaves behind: the addresses the
// pages had. Said here rather than left to be discovered by a reader
// following a link somebody sent them last month.
//
// As the command that keeps each working, to run once the move is live. It
// pointed at `quilzo site --redirects redirects.json`, a file the move never
// wrote, while the store keeps a redirect list of its own that the running
// site serves at once; so every moved address answered 404 until somebody
// wrote the redirects by hand. Not added by the move itself: a redirect
// changes the live site the moment it is stored, and takes what publishing
// takes, so one added now would send the old address, still live, to a page
// that is not live yet.
func sayOldAddresses(renames map[string]string) {
	olds := make([]string, 0, len(renames))
	for was := range renames {
		olds = append(olds, was)
	}
	sort.Strings(olds)
	w.Human("  %sonce this is published the old addresses answer 404; after "+
		"publishing, a redirect keeps each working:%s\n", dim, reset)
	const shown = 10
	for i, was := range olds {
		if i == shown {
			w.Human("  %s  and %d more, one for each page that moved%s\n",
				dim, len(olds)-shown, reset)
			break
		}
		w.Human("  %s  quilzo redirect add /%s /%s%s\n", dim, was, renames[was], reset)
	}
}

// carryProvenance gives each page the move wrote the provenance record it had
// under the name it had, bound to the bytes it has now, and says how many it
// carried.
//
// Copied to the new name, and not taken off the old one: the live site serves
// the old name until the move is published, and its mark goes with it until
// then. A page that keeps its name and had only a reference rewritten has its
// record rebound to its new bytes, as any write to a page rebinds it, with a
// note saying what changed them. A record is carried only where it was bound to the bytes the move
// read, so a record that was already stale stays a gap rather than being
// laundered into a fresh one; and only where the page now holds exactly what
// the move wrote, since a field somebody else changed meanwhile was merged
// into it (site.SaveDraftOver) and the record does not describe their words.
func carryProvenance(root string, s *store.Store, base, commit string,
	renames map[string]string, written []string, next map[string]any) (int, error) {

	idx, err := loadProvenance(root)
	if err != nil {
		return 0, err
	}
	before, err := site.PageIDsAt(s, base)
	if err != nil {
		return 0, err
	}
	after, err := site.PageIDsAt(s, commit)
	if err != nil {
		return 0, err
	}
	landed, err := site.PagesAt(s, commit)
	if err != nil {
		return 0, err
	}
	// Each page written, under the name it has now and the one it had.
	// written holds the moved pages under their old names and the pages a
	// reference or a reuse was rewritten in under their new ones.
	olds := map[string]string{}
	for was, now := range renames {
		olds[now] = was
	}
	touched := map[string]string{}
	for _, name := range written {
		switch now, moved := renames[name]; {
		case moved:
			touched[now] = name
		case olds[name] != "":
			touched[name] = olds[name]
		default:
			touched[name] = name
		}
	}
	carried := 0
	for now, was := range touched {
		rec, ok := idx.Get(was)
		if !ok || before[was] == "" || rec.ContentHash != before[was] || after[now] == "" {
			continue
		}
		if !sameBody(landed[now], next[now]) {
			continue
		}
		if now == was && after[now] == rec.ContentHash {
			continue
		}
		if after[now] != rec.ContentHash {
			rec.Note = strings.TrimSpace(rec.Note + " The move to " + now +
				" rewrote only the names of pages it points at.")
		}
		rec.ContentHash = after[now]
		if err := idx.Set(now, rec); err != nil {
			return carried, err
		}
		carried++
	}
	if carried == 0 {
		return 0, nil
	}
	return carried, saveJSON(provPath(root), idx)
}

// sameBody reports whether two page bodies hold the same thing.
func sameBody(a, b any) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	return err == nil && bytes.Equal(x, y)
}

// sayWhatWouldMove is the dry run.
func sayWhatWouldMove(moving []string, renames map[string]string,
	incoming map[string][]schema.Link, reuses []string, root, from string) error {

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
		"references": refs, "menus": menus, "reuses": reuses, "dry_run": true,
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
	if len(reuses) > 0 {
		w.Human("  %sthe block's reuses on %s would follow it%s\n",
			dim, strings.Join(reuses, ", "), reset)
	}
	return nil
}
