package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
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
	default:
		return fmt.Errorf("unknown section command %q; try list, kinds, add, "+
			"move, remove, fields, set or item", args[0])
	}
}

// sectionKinds is the catalogue: what a page can be built out of.
func sectionKinds(args []string) error {
	fs := flag.NewFlagSet("kinds", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
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
	if err := fs.Parse(flags); err != nil {
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
	if err := fs.Parse(flags); err != nil {
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
	pos, _ := leadingArgs(args, 2)
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo section remove <page> <index>\n" +
			"  quilzo section list <page>  shows the indices")
	}
	index, err := strconv.Atoi(pos[1])
	if err != nil {
		return fmt.Errorf("%q is not a section index", pos[1])
	}
	return editSections(root, pos[0], func(body any) (map[string]any, string, error) {
		kind := "a"
		if placed := section.On(body); index >= 0 && index < len(placed) {
			kind = placed[index].Kind
		}
		next, err := section.Remove(body, index)
		return next, fmt.Sprintf("remove the %s section from %s", kind, pos[0]), err
	})
}

func sectionMove(root string, args []string) error {
	pos, flags := leadingArgs(args, 3)
	fs := flag.NewFlagSet("move", flag.ContinueOnError)
	if err := fs.Parse(flags); err != nil {
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

	pages, err := site.PagesAt(s, site.RefDraft)
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
	if _, err := site.SaveDraftFrom(s, pages, msg, caller.Name,
		s.GetRef(site.RefDraft)); err != nil {
		return err
	}
	if err := types.Save(); err != nil {
		return err
	}
	record(root, caller.auditRecord("section.edit", "/"+page, audit.Success,
		map[string]string{"did": msg}))

	w.Human("%s\n", msg)
	for _, pl := range section.On(next) {
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
	if err := fs.Parse(flags); err != nil {
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
	pos, _ := leadingArgs(args, 99)
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
	pos, _ := leadingArgs(args[1:], 4)
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
