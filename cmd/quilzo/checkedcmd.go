// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/checked"
	"github.com/quilzo/quilzo/internal/site"
)

// When did anybody last look at this?
//
// The history says when a page was last edited, which is a different question.
// A page nobody has edited in three years is either perfectly accurate or
// badly out of date, and nothing in the history says which. See
// internal/checked.

func cmdChecked(root string, args []string) error {
	if len(args) == 0 {
		args = []string{bareRuns["checked"]}
	}
	switch args[0] {
	case "set":
		return checkedSet(root, args[1:])
	case "list":
		return checkedList(root, args[1:], false)
	case "due":
		return checkedList(root, args[1:], true)
	case "own":
		return checkedOwn(root, args[1:])
	case "disown":
		return checkedDisown(root, args[1:])
	case "clear":
		return checkedClear(root, args[1:])
	default:
		return errMisused{fmt.Errorf(
			"unknown checked command %q; try set, list, due, own, disown or "+
				"clear", args[0])}
	}
}

func checkedDir(root string) string { return filepath.Join(root, "checked") }

func openChecked(root string) (*checked.Store, error) {
	return checked.Open(checkedDir(root))
}

// reviewEvery is the site's answer for a page that does not name its own.
func reviewEvery(root string) time.Duration {
	return mustConfig(root).Dur("content.review.every")
}

// draftPageIDs is every page in the draft and the store's id for what it says.
//
// Both at once because the survey needs both, and reading the draft twice is
// two chances for them to disagree about what is there.
//
// Named for the ids rather than the pages, because draftPages already means
// "the bodies" here and two functions a letter apart that return different
// things is how somebody picks the wrong one.
func draftPageIDs(root string) ([]string, map[string]string) {
	s, err := open(root)
	if err != nil {
		return nil, nil
	}
	ids, err := pageHashes(s, site.RefDraft)
	if err != nil {
		return nil, nil
	}
	names := make([]string, 0, len(ids))
	for name := range ids {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, ids
}

func checkedSet(root string, args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	every := fs.String("every", "",
		"how long until this page is wanted again, e.g. 168h; "+
			"omit for the site's own answer")
	note := fs.String("note", "", "what the next person should know")
	by := fs.String("by", "", "who to credit for the check; it is recorded as the signed-in principal's")
	rest, flags := leadingArgs(args, 1)
	if err := parseFlags(fs, flags, &rest, 1); err != nil {
		return err
	}
	if len(rest) != 1 {
		return errMisused{fmt.Errorf(
			"usage: quilzo checked set PAGE [--every 168h] [--note \"...\"]")}
	}
	page := rest[0]

	// Recorded as the verified caller's, whatever the flag says, as a note
	// is its signed-in writer's (noteAdd), with a name typed after --by
	// credited in the note (Caller.namedBy). The flag was taken as who
	// checked the page whenever it was given, so an author confirmed a page
	// in the publisher's name with "Legal has signed this off" for its note,
	// and `checked list` and the admin showed both as hers; the admin's own
	// button records whoever is signed in. At a console nobody signs in to,
	// the name typed is the one there is.
	caller := resolveCaller(root, "")
	who, credited := caller.namedBy(*by)
	if who == "" {
		who = caller.Name
	}
	*note = withCredit(*note, credited)
	if who == "" {
		return fmt.Errorf("who checked it? Pass --by, or sign in")
	}

	_, hashes := draftPageIDs(root)
	if _, exists := hashes[page]; !exists {
		// Refused rather than recorded. A check on a page that is not there is
		// a typo, and recording it produces a record nothing will ever clear.
		return errNotFound{fmt.Errorf("there is no page called %q in the draft", page)}
	}

	st, err := openChecked(root)
	if err != nil {
		return err
	}
	r, err := st.Set(checked.Record{
		Page: page, Content: hashes[page], By: who,
		Every: strings.TrimSpace(*every), Note: strings.TrimSpace(*note),
	}, time.Now())
	if err != nil {
		return err
	}
	record(root, caller.auditRecord("checked.set", "/"+page,
		audit.Success, map[string]string{"by": who, "every": r.Every}))

	if w.JSON(r) {
		return nil
	}
	w.Human("  %schecked %s%s\n", dim, page, reset)
	w.Human("  %snext wanted %s%s\n", dim,
		r.Due(reviewEvery(root)).UTC().Format("2006-01-02"), reset)
	return nil
}

func checkedList(root string, args []string, dueOnly bool) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	owner := fs.String("owner", "",
		"only pages this person is responsible for")
	unowned := fs.Bool("unowned", false, "only pages nobody is responsible for")
	if err := parseFlags(fs, args, nil, 0); err != nil {
		return err
	}
	if *unowned && strings.TrimSpace(*owner) != "" {
		return fmt.Errorf(
			"--owner and --unowned ask for different lists; pass one")
	}
	st, err := openChecked(root)
	if err != nil {
		return err
	}
	records, err := st.All()
	if err != nil {
		return err
	}
	pages, hashes := draftPageIDs(root)
	rows := checked.Survey(pages, hashes, records, reviewEvery(root), time.Now())

	// Only the pages the caller may read, as list_checked answers over MCP.
	// A reader may run this (privilege.go), and it listed every page in the
	// draft, so a reader denied a page was told its name here though every
	// list of pages they are shown leaves it out.
	may, err := pageCheck(root, resolveCaller(root, ""), auth.ActView)
	if err != nil {
		return err
	}
	readable := rows[:0]
	for _, r := range rows {
		if may(r.Page) {
			readable = append(readable, r)
		}
	}
	rows = readable

	if dueOnly {
		kept := rows[:0]
		for _, r := range rows {
			if checked.NeedsAttention(r.State) {
				kept = append(kept, r)
			}
		}
		rows = kept
	}
	// "What is mine" and "what is nobody's" are the two questions an owner
	// makes answerable, and both are the same list with a different row kept.
	if who := strings.TrimSpace(*owner); who != "" || *unowned {
		kept := rows[:0]
		for _, r := range rows {
			if (*unowned && r.Owner == "") || (!*unowned && r.Owner == who) {
				kept = append(kept, r)
			}
		}
		rows = kept
	}

	if w.JSON(rows) {
		return nil
	}
	if len(rows) == 0 {
		// Which of the four it is matters. "No page is finance's" about a
		// person who owns six pages, none of them due, is the empty list
		// describing the wrong absence — and somebody reads it as "nobody
		// gave finance anything".
		who := strings.TrimSpace(*owner)
		switch {
		case dueOnly && *unowned:
			w.Human("  %snothing unowned needs attention%s\n", dim, reset)
		case dueOnly && who != "":
			w.Human("  %snothing of %s's needs attention%s\n", dim, who, reset)
		case dueOnly:
			w.Human("  %severy page has been checked and none is due%s\n", dim, reset)
		case *unowned:
			w.Human("  %severy page has somebody responsible for it%s\n", dim, reset)
		case who != "":
			w.Human("  %sno page is %s's%s\n", dim, who, reset)
		default:
			w.Human("  %sthere are no pages%s\n", dim, reset)
		}
		return nil
	}
	for _, r := range rows {
		colour := dim
		if checked.NeedsAttention(r.State) {
			colour = yellow
		}
		// Who checked it, whose job it is and the note are whatever
		// somebody typed, as a note's author and text are (noteList).
		// Printed raw, a note or an owner carrying a line break and this
		// layout printed a second page confirmed fresh in somebody else's
		// name, and ESC and CR rewrote what the terminal showed. The names
		// stay on the row, and every line of the note at the note's depth.
		w.Human("  %s%-9s%s %-28s", colour, r.State, reset, onOneLine(r.Page))
		switch {
		case r.At == 0:
			w.Human("  %s—%s", dim, reset)
		default:
			w.Human("  %s%s by %s%s", dim,
				time.Unix(r.At, 0).UTC().Format("2006-01-02"), onOneLine(r.By), reset)
		}
		if r.Owner != "" {
			w.Human("  %s(%s)%s", dim, onOneLine(r.Owner), reset)
		}
		w.Human("\n")
		if r.Note != "" {
			w.Human("            %s%s%s\n", dim,
				indentedForTerminal(r.Note, "            "), reset)
		}
	}
	return nil
}

func checkedClear(root string, args []string) error {
	// A flag is refused rather than taken for the page: `checked clear
	// --zzflag` cleared a page called "--zzflag" and said so, exit 0.
	args, err := positionals(args, 1)
	if err != nil {
		return err
	}
	if len(args) != 1 {
		return errMisused{fmt.Errorf("usage: quilzo checked clear PAGE")}
	}
	st, err := openChecked(root)
	if err != nil {
		return err
	}
	if err := st.Clear(args[0]); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("checked.clear",
		"/"+args[0], audit.Success, nil))
	w.Human("  %scleared%s\n", dim, reset)
	return nil
}

// checkedOwn says whose job a page is.
//
// A verb of its own rather than a flag on set, because naming an owner is not
// the same act as confirming a page — see checked.Store.Own. Two positionals
// and no flags, so leadingArgs has nothing to trip over.
func checkedOwn(root string, args []string) error {
	if len(args) != 2 {
		return errMisused{fmt.Errorf("usage: quilzo checked own PAGE WHO")}
	}
	page, who := args[0], strings.TrimSpace(args[1])
	if who == "" {
		return fmt.Errorf(
			"who owns it? To take the owner off a page, use checked disown")
	}
	r, err := setOwner(root, page, who)
	if err != nil {
		return err
	}
	if w.JSON(r) {
		return nil
	}
	w.Human("  %s%s is %s's%s\n", dim, page, who, reset)
	return nil
}

// checkedDisown takes the owner off a page.
func checkedDisown(root string, args []string) error {
	if len(args) != 1 {
		return errMisused{fmt.Errorf("usage: quilzo checked disown PAGE")}
	}
	if _, err := setOwner(root, args[0], ""); err != nil {
		return err
	}
	if w.JSON(map[string]string{"page": args[0], "owner": ""}) {
		return nil
	}
	w.Human("  %snobody is responsible for %s%s\n", dim, args[0], reset)
	return nil
}

// setOwner is the half both verbs share: the page has to exist, and the act is
// logged with the name it lands on.
func setOwner(root, page, who string) (checked.Record, error) {
	_, hashes := draftPageIDs(root)
	if _, exists := hashes[page]; !exists {
		// Same refusal as set, for the same reason: an owner on a page that is
		// not there is a typo, and it produces a record nothing will ever
		// clear.
		return checked.Record{}, errNotFound{fmt.Errorf(
			"there is no page called %q in the draft", page)}
	}
	st, err := openChecked(root)
	if err != nil {
		return checked.Record{}, err
	}
	r, err := st.Own(page, who)
	if err != nil {
		return checked.Record{}, err
	}
	record(root, resolveCaller(root, "").auditRecord("checked.own", "/"+page,
		audit.Success, map[string]string{"owner": who}))
	return r, nil
}
