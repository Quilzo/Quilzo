// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/site"
)

// Sections from the terminal.
//
// # Why this exists when the JSON was already editable
//
// Because "edit the JSON" is not the same capability. Moving a section by hand
// means finding the right object in a nested array and cutting it to the right
// place, and the failure mode is a page that still parses and has two heroes.
// This does the index arithmetic in the one place the browser also does it, so
// the two cannot drift — which is the whole reason the moves live in
// internal/section rather than in either caller.
//
// It is also what makes the browser screen honest. A capability that exists in
// one interface is a capability somebody scripting a migration cannot have.

func cmdSection(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return sectionList(root, args[1:])
	case "kinds":
		return sectionKinds(args[1:])
	case "add":
		return sectionAdd(root, args[1:])
	case "remove", "rm":
		return sectionRemove(root, args[1:])
	case "move", "mv":
		return sectionMove(root, args[1:])
	case "fields":
		return sectionFields(root, args[1:])
	case "set":
		return sectionSet(root, args[1:])
	case "item":
		return sectionItem(root, args[1:])
	case "reuse":
		return sectionReuse(root, args[1:])
	case "block":
		return sectionBlock(root, args[1:])
	case "blocks":
		return sectionBlocks(root, args[1:])
	case "backdrop":
		return sectionBackdrop(root, args[1:])
	default:
		return fmt.Errorf("unknown section command %q; try list, kinds, add, "+
			"move, remove, fields, set, item, reuse, block, blocks or backdrop", args[0])
	}
}

// sectionBackdrop puts a picture or a recording behind a section or the
// hero, or takes it away.
//
// A command of its own because `section set` writes only the fields a section
// already has, so no edit could give one a backdrop. The file is checked when
// the page is published: a recording has to be one the library knows is
// silent, and the words over it readable against the worst picture the veil
// could cover.
func sectionBackdrop(root string, args []string) error {
	pos, flags := leadingArgs(args, 3)
	fs := flag.NewFlagSet("backdrop", flag.ContinueOnError)
	off := fs.Bool("off", false, "take the backdrop away")
	if err := parseFlags(fs, flags, &pos, 3); err != nil {
		return err
	}
	if len(pos) < 2 || len(pos) > 3 || (*off && len(pos) == 3) || (!*off && len(pos) != 3) {
		return fmt.Errorf("usage: quilzo section backdrop <page> <index>|hero /media/ID, or with --off and no file")
	}
	at := section.HeroAt
	where := "the hero"
	if pos[1] != "hero" {
		n, err := strconv.Atoi(pos[1])
		if err != nil {
			return fmt.Errorf("%q is not a section index or hero", pos[1])
		}
		at, where = n, fmt.Sprintf("section %d", n)
	}
	addr := ""
	if len(pos) == 3 {
		addr = strings.TrimSpace(pos[2])
		// A bare id, as `quilzo media list --json` gives it, is a /media/
		// address. Anything else is left as written, so that a refusal quotes
		// what was typed: an outside address came back as "/media/https://…".
		if medialib.ValidID(addr) == nil {
			addr = "/media/" + addr
		}
		if err := backdropFile(root, addr); err != nil {
			return err
		}
	}
	return editSections(root, pos[0], func(body any) (map[string]any, string, error) {
		if *off {
			next, err := section.ClearBackdrop(body, at)
			return next, fmt.Sprintf("take the backdrop away from %s of %s", where, pos[0]), err
		}
		next, err := section.SetBackdrop(body, at, addr)
		return next, fmt.Sprintf("put a backdrop behind %s of %s", where, pos[0]), err
	})
}

// backdropFile refuses, before anything is written, a backdrop the publish
// gate would refuse anyway: a file the library does not hold, one that is
// neither a picture nor a recording, and a recording the library does not
// know to be silent. The command used to write any of them and say the draft
// had moved, and the first anybody heard was a page refused at publish.
func backdropFile(root, addr string) error {
	id, isMedia := strings.CutPrefix(addr, "/media/")
	if !isMedia || medialib.ValidID(id) != nil {
		return nil // the address itself is refused by section.SetBackdrop
	}
	lib, err := openMedia(root)
	if err != nil {
		return err
	}
	f, err := lib.Stat(id)
	if err != nil {
		return fmt.Errorf("%s is not in the media library; `quilzo media list` prints what is", addr)
	}
	switch f.Kind {
	case media.Image:
		return nil
	case media.Video:
	default:
		return fmt.Errorf("%s is %s, and a backdrop is a picture or a silent video", f.Name, f.Kind)
	}
	switch sound, known := f.SoundKnown(); {
	case sound:
		return fmt.Errorf("%s has sound, so it cannot be a backdrop: a backdrop is muted, and "+
			"what is said in it would be lost to every reader. A video section shows it, with captions", f.Name)
	case !known:
		return fmt.Errorf("whether %s has sound was not recorded when it was added, so it "+
			"cannot be a backdrop: only a recording known to be silent can be muted without "+
			"losing anything", f.Name)
	}
	return nil
}

// sectionKinds is the catalogue: what a page can be built out of.
func sectionKinds(args []string) error {
	fs := flag.NewFlagSet("kinds", flag.ContinueOnError)
	if err := parseFlags(fs, args, nil, 0); err != nil {
		return err
	}
	kinds := section.Kinds()
	if w.JSON(kinds) {
		return nil
	}
	group := ""
	for _, k := range kinds {
		if k.Group != group {
			group = k.Group
			w.Human("\n%s%s%s\n", bold, group, reset)
		}
		w.Human("  %s%-10s%s %s\n", bold, k.Name, reset,
			wrapIndent(k.Summary, 62, 14))
	}
	w.Human("\n  %squilzo section add PAGE KIND     adds one, with content that "+
		"renders%s\n", dim, reset)
	return nil
}

func sectionList(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	live := fs.Bool("live", false, "read the published pages instead of the draft")
	if err := parseFlags(fs, flags, &pos, 1); err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	ref := site.RefDraft
	if *live {
		ref = site.RefLive
	}
	pages, err := site.PagesAt(s, ref)
	if err != nil {
		return err
	}

	if len(pos) == 0 {
		// Every page and how many sections it has, which is the question
		// somebody asks before they know which page they mean.
		type row struct {
			Page     string `json:"page"`
			Sections int    `json:"sections"`
		}
		rows := []row{}
		for _, name := range sortedKeys(pages) {
			rows = append(rows, row{name, len(section.On(pages[name]))})
		}
		if w.JSON(rows) {
			return nil
		}
		for _, r := range rows {
			if r.Sections == 0 {
				w.Human("  %-24s %snone%s\n", r.Page, dim, reset)
				continue
			}
			w.Human("  %-24s %d\n", r.Page, r.Sections)
		}
		w.Human("\n  %squilzo section list PAGE   what is on one page, in order%s\n",
			dim, reset)
		return nil
	}

	name := pos[0]
	body, exists := pages[name]
	if !exists {
		return fmt.Errorf("no page %q; have %s",
			name, strings.Join(sortedKeys(pages), ", "))
	}
	placed := section.On(body)
	if w.JSON(placed) {
		return nil
	}
	if len(placed) == 0 {
		w.Human("%s has no sections.\n\n", name)
		w.Human("  %squilzo section kinds   what it could have%s\n", dim, reset)
		return nil
	}
	w.Human("%s%s%s  %s%d section(s), in order%s\n\n", bold, name, reset,
		dim, len(placed), reset)
	for _, pl := range placed {
		mark := " "
		if pl.Unknown {
			mark = "!"
		}
		w.Human("  %s %2d  %s%-10s%s %s\n", mark, pl.Index, bold, pl.Kind, reset,
			trim(pl.Label, 44))
		if pl.Items > 0 {
			w.Human("          %s%d item(s)%s\n", dim, pl.Items, reset)
		}
		if pl.Unknown {
			w.Human("          %s! no layout renders this kind, so it puts "+
				"nothing on the page%s\n", dim, reset)
		}
	}
	return nil
}

func sectionAdd(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	at := fs.Int("at", -1, "position to insert at; the end by default")
	if err := parseFlags(fs, flags, &pos, 2); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo section add <page> <kind> [--at N]\n" +
			"  quilzo section kinds  lists the kinds")
	}
	return editSections(root, pos[0], func(body any) (map[string]any, string, error) {
		where := *at
		if where < 0 {
			where = len(section.On(body))
		}
		next, err := section.Insert(body, pos[1], where)
		return next, fmt.Sprintf("add a %s section to %s", pos[1], pos[0]), err
	})
}

func sectionRemove(root string, args []string) error {
	pos, err := positionals(args, 2)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo section remove <page> <index-or-id>\n" +
			"  quilzo section list <page>  shows both")
	}
	return editSections(root, pos[0], func(body any) (map[string]any, string, error) {
		index, err := sectionAt(body, pos[1])
		if err != nil {
			return nil, "", err
		}
		kind := "a"
		if placed := section.On(body); index >= 0 && index < len(placed) {
			kind = placed[index].Kind
		}
		next, err := section.Remove(body, index)
		return next, fmt.Sprintf("remove the %s section from %s", kind, pos[0]), err
	})
}

// sectionAt reads a section's position from an index or from its id.
//
// Either, because both are true names for it and which one somebody has
// depends on where they are looking: `section list` prints both, a script that
// counted rows has the index, and anything that kept a reference has the id.
//
// The id is the one that is still right after somebody else has arranged the
// page — see internal/section/id.go — so it is tried first and an index is
// only read when what was given is not one.
func sectionAt(body any, which string) (int, error) {
	if at, ok := section.IndexOf(body, which); ok {
		return at, nil
	}
	at, err := strconv.Atoi(which)
	if err != nil {
		return 0, fmt.Errorf(
			"%q is neither a section index nor the id of a section on this "+
				"page.\n  quilzo section list PAGE  shows both", which)
	}
	return at, nil
}

func sectionMove(root string, args []string) error {
	pos, flags := leadingArgs(args, 3)
	fs := flag.NewFlagSet("move", flag.ContinueOnError)
	if err := parseFlags(fs, flags, &pos, 3); err != nil {
		return err
	}
	if len(pos) != 3 {
		return fmt.Errorf("usage: quilzo section move <page> <index> up|down")
	}
	index, err := strconv.Atoi(pos[1])
	if err != nil {
		return fmt.Errorf("%q is not a section index", pos[1])
	}
	by := 0
	switch strings.ToLower(pos[2]) {
	case "up":
		by = -1
	case "down":
		by = 1
	default:
		return fmt.Errorf("%q is not a direction; up or down", pos[2])
	}
	return editSections(root, pos[0], func(body any) (map[string]any, string, error) {
		next, err := section.Move(body, index, by)
		return next, fmt.Sprintf("move a section %s on %s",
			strings.ToLower(pos[2]), pos[0]), err
	})
}

// editSections is the read, change, save that every verb above shares.
//
// One draft commit per change, with a message naming what happened — the same
// as the browser, because it is the same operation and there is only one way
// this store writes anything.
func editSections(root, page string,
	change func(body any) (map[string]any, string, error)) error {

	s, err := open(root)
	if err != nil {
		return err
	}
	// Authority is checked by the privilege table before the command runs —
	// see privilege.go, and the test that refuses a command which declares
	// none. Repeating it here would be a second copy of the rule to drift.
	caller := resolveCaller(root, "")

	// The commit the pages are read from, which is what the change is made
	// against (draftRead).
	base, pages, err := draftRead(s)
	if err != nil {
		return err
	}
	body, exists := pages[page]
	if !exists {
		return fmt.Errorf("no page %q; have %s",
			page, strings.Join(sortedKeys(pages), ", "))
	}

	next, msg, err := change(body)
	if err != nil {
		return err
	}
	pages[page] = next

	// The same gate as every other write path. Sections are content, so a page
	// bound to a content type has to still satisfy it after a section moves —
	// and a write surface that skips this is how type validation becomes a rule
	// about whichever interface you happened to read.
	types, err := gateWrite(root, pages)
	if err != nil {
		return err
	}
	cid, _, err := site.SaveDraftOver(s, pages, msg, caller.Name, base)
	if err != nil {
		return err
	}
	if err := types.Save(); err != nil {
		return err
	}
	record(root, caller.auditRecord("section.edit", "/"+page, audit.Success,
		map[string]string{"did": msg}))

	// One document for a script, whatever the edit was: these commands
	// printed nothing under --json, so a script that put a backdrop behind a
	// section, or added one, had only the exit status to say it had.
	placed := section.On(next)
	if placed == nil {
		placed = []section.Placed{}
	}
	if w.JSON(map[string]any{"page": page, "did": msg, "commit": cid, "sections": placed}) {
		return nil
	}
	w.Human("%s\n", msg)
	for _, pl := range placed {
		w.Human("  %2d  %s\n", pl.Index, pl.Kind)
	}
	w.Human("\n  %sthe draft moved; `quilzo publish` puts it live%s\n", dim, reset)
	return nil
}

// sectionFields prints what is editable inside one section.
//
// The paths this prints are the ones `section set` takes, so the two halves are
// one workflow rather than a guess about how a nested key is spelled.
func sectionFields(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("fields", flag.ContinueOnError)
	if err := parseFlags(fs, flags, &pos, 2); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo section fields <page> <index>")
	}
	index, err := strconv.Atoi(pos[1])
	if err != nil {
		return fmt.Errorf("%q is not a section index", pos[1])
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		return err
	}
	body, exists := pages[pos[0]]
	if !exists {
		return fmt.Errorf("no page %q; have %s",
			pos[0], strings.Join(sortedKeys(pages), ", "))
	}
	fields, err := section.Fields(body, index)
	if err != nil {
		return err
	}
	if w.JSON(fields) {
		return nil
	}
	kind, _ := section.KindAt(body, index)
	w.Human("%s%s%s  %ssection %d of %s%s\n\n", bold, kind, reset,
		dim, index, pos[0], reset)
	for _, f := range fields {
		mark := " "
		if f.Number {
			mark = "#"
		}
		w.Human("  %s %-28s %s\n", mark, f.Path, trim(f.Value, 44))
	}
	if lists := section.Lists(body, index); len(lists) > 0 {
		w.Human("\n  %slists: %s%s\n", dim, strings.Join(lists, ", "), reset)
	}
	w.Human("\n  %s# is a number and is written back as one%s\n", dim, reset)
	w.Human("  %squilzo section set %s %d title='New title'%s\n",
		dim, pos[0], index, reset)
	return nil
}

// sectionSet writes values into one section, by path.
func sectionSet(root string, args []string) error {
	pos, err := positionals(args, 99)
	if err != nil {
		return err
	}
	if len(pos) < 3 {
		return fmt.Errorf("usage: quilzo section set <page> <index> path=value [path=value …]\n" +
			"  quilzo section fields <page> <index>  lists the paths")
	}
	index, err := strconv.Atoi(pos[1])
	if err != nil {
		return fmt.Errorf("%q is not a section index", pos[1])
	}
	values := map[string]string{}
	for _, pair := range pos[2:] {
		path, value, found := strings.Cut(pair, "=")
		if !found {
			return fmt.Errorf("%q is not path=value", pair)
		}
		values[strings.TrimSpace(path)] = value
	}
	return editSections(root, pos[0], func(body any) (map[string]any, string, error) {
		next, err := section.Apply(body, index, values)
		if err != nil {
			return nil, "", err
		}
		// Which paths did nothing is worth knowing here: the command took
		// them, the section did not have them, and silence would read as
		// success. Only leaves that already exist may be written — see
		// internal/section/fields.go for why.
		before, _ := section.Fields(body, index)
		known := map[string]bool{}
		for _, f := range before {
			known[f.Path] = true
		}
		var ignored []string
		for path := range values {
			if !known[path] {
				ignored = append(ignored, path)
			}
		}
		if len(ignored) > 0 {
			sortStringsInPlace(ignored)
			return nil, "", fmt.Errorf(
				"this section has no %s.\n"+
					"  Only values that are already there may be set, because "+
					"a shape a command can extend is a shape nobody can reason "+
					"about.\n"+
					"  `quilzo section fields %s %d` lists what it has, and "+
					"`quilzo section item add` adds an entry",
				strings.Join(ignored, ", "), pos[0], index)
		}
		kind, _ := section.KindAt(body, index)
		return next, fmt.Sprintf("edit the %s section on %s", kind, pos[0]), nil
	})
}

// sectionItem adds and removes entries in a list inside a section.
func sectionItem(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: quilzo section item add|remove <page> <index> <list> [entry]")
	}
	verb := args[0]
	pos, err := positionals(args[1:], 4)
	if err != nil {
		return err
	}
	if len(pos) < 3 {
		return fmt.Errorf("usage: quilzo section item %s <page> <index> <list> [entry]", verb)
	}
	index, err := strconv.Atoi(pos[1])
	if err != nil {
		return fmt.Errorf("%q is not a section index", pos[1])
	}
	list := pos[2]

	switch verb {
	case "add":
		return editSections(root, pos[0], func(body any) (map[string]any, string, error) {
			next, err := section.AddItem(body, index, list)
			kind, _ := section.KindAt(body, index)
			return next, fmt.Sprintf("add an entry to %s on the %s section of %s",
				list, kind, pos[0]), err
		})
	case "remove", "rm":
		if len(pos) != 4 {
			return fmt.Errorf(
				"usage: quilzo section item remove <page> <index> <list> <entry>")
		}
		entry, cerr := strconv.Atoi(pos[3])
		if cerr != nil {
			return fmt.Errorf("%q is not an entry number", pos[3])
		}
		return editSections(root, pos[0], func(body any) (map[string]any, string, error) {
			next, err := section.RemoveItem(body, index, list, entry)
			kind, _ := section.KindAt(body, index)
			return next, fmt.Sprintf("remove an entry from %s on the %s section of %s",
				list, kind, pos[0]), err
		})
	default:
		return fmt.Errorf("unknown item command %q; try add or remove", verb)
	}
}

// sectionReuse is quilzo section reuse PAGE BLOCK [--at N]: a section that
// shows a reusable block's sections where it is put.
func sectionReuse(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("reuse", flag.ContinueOnError)
	at := fs.Int("at", -1, "position to insert at; the end by default")
	if err := parseFlags(fs, flags, &pos, 2); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo section reuse <page> <block> [--at N]\n" +
			"  quilzo section blocks  lists the blocks")
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		return err
	}
	if err := site.CanReuse(pos[0], pos[1], pages); err != nil {
		return fmt.Errorf("%w; quilzo section blocks lists them", err)
	}
	return editSections(root, pos[0], func(body any) (map[string]any, string, error) {
		next, err := section.InsertBlock(body, pos[1], *at)
		return next, fmt.Sprintf("reuse the block %s on %s", pos[1], pos[0]), err
	})
}

// sectionBlock is quilzo section block PAGE [--off]: a page made a reusable
// block, or a page again.
func sectionBlock(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("block", flag.ContinueOnError)
	off := fs.Bool("off", false, "make it a page of its own again")
	if err := parseFlags(fs, flags, &pos, 1); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo section block <page> [--off]")
	}
	name := pos[0]
	s, err := open(root)
	if err != nil {
		return err
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		return err
	}
	if err := site.BlockChange(name, pages, !*off); err != nil {
		return err
	}
	if err := editSections(root, name, func(body any) (map[string]any, string, error) {
		m, ok := body.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("%s is not a page with fields", name)
		}
		next := make(map[string]any, len(m)+1)
		for k, v := range m {
			next[k] = v
		}
		if *off {
			delete(next, site.BlockField)
			return next, fmt.Sprintf("make %s a page of its own again", name), nil
		}
		next[site.BlockField] = true
		return next, fmt.Sprintf("make %s a reusable block", name), nil
	}); err != nil {
		return err
	}
	if !*off {
		w.Human("  %sonce published it is no page of its own: it shows where a page reuses it "+
			"(quilzo section reuse PAGE %s)%s\n", dim, name, reset)
	}
	return nil
}

// sectionBlocks is quilzo section blocks: every block, and where it is used.
func sectionBlocks(root string, args []string) error {
	fs := flag.NewFlagSet("blocks", flag.ContinueOnError)
	live := fs.Bool("live", false, "read the published pages instead of the draft")
	if err := parseFlags(fs, args, nil, 0); err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	ref := site.RefDraft
	if *live {
		ref = site.RefLive
	}
	pages, err := site.PagesAt(s, ref)
	if err != nil {
		return err
	}
	uses := site.BlockUses(pages)
	if w.JSON(uses) {
		return nil
	}
	names := make([]string, 0, len(uses))
	for n := range uses {
		names = append(names, n)
	}
	slices.Sort(names)
	if len(names) == 0 {
		w.Human("  %sno blocks yet; quilzo section block PAGE makes a page one%s\n", dim, reset)
		return nil
	}
	for _, n := range names {
		switch {
		case !site.IsBlock(pages[n]):
			w.Human("%s%s%s  %snot a block, and reused on %s: it shows nothing there%s\n", bold, n, reset,
				yellow, strings.Join(uses[n], ", "), reset)
		case len(uses[n]) == 0:
			w.Human("%s%s%s  %sused nowhere yet%s\n", bold, n, reset, dim, reset)
		default:
			w.Human("%s%s%s  used on %s\n", bold, n, reset, strings.Join(uses[n], ", "))
		}
	}
	return nil
}
