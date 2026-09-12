// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
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
		args = []string{"list"}
	}
	switch args[0] {
	case "set":
		return checkedSet(root, args[1:])
	case "list":
		return checkedList(root, args[1:], false)
	case "due":
		return checkedList(root, args[1:], true)
	case "clear":
		return checkedClear(root, args[1:])
	default:
		return fmt.Errorf(
			"unknown checked command %q; try set, list, due or clear", args[0])
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
	by := fs.String("by", "", "who checked it")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf(
			"usage: quilzo checked set PAGE [--every 168h] [--note \"...\"]")
	}
	page := rest[0]

	who := strings.TrimSpace(*by)
	if who == "" {
		who = resolveCaller(root, "").Name
	}
	if who == "" {
		return fmt.Errorf("who checked it? Pass --by, or sign in")
	}

	_, hashes := draftPageIDs(root)
	if _, exists := hashes[page]; !exists {
		// Refused rather than recorded. A check on a page that is not there is
		// a typo, and recording it produces a record nothing will ever clear.
		return fmt.Errorf("there is no page called %q in the draft", page)
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
	record(root, resolveCaller(root, "").auditRecord("checked.set", "/"+page,
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
	if err := fs.Parse(args); err != nil {
		return err
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

	if dueOnly {
		kept := rows[:0]
		for _, r := range rows {
			if checked.NeedsAttention(r.State) {
				kept = append(kept, r)
			}
		}
		rows = kept
	}

	if w.JSON(rows) {
		return nil
	}
	if len(rows) == 0 {
		if dueOnly {
			w.Human("  %severy page has been checked and none is due%s\n", dim, reset)
		} else {
			w.Human("  %sthere are no pages%s\n", dim, reset)
		}
		return nil
	}
	for _, r := range rows {
		colour := dim
		if checked.NeedsAttention(r.State) {
			colour = yellow
		}
		w.Human("  %s%-9s%s %-28s", colour, r.State, reset, r.Page)
		switch {
		case r.At == 0:
			w.Human("  %s—%s", dim, reset)
		default:
			w.Human("  %s%s by %s%s", dim,
				time.Unix(r.At, 0).UTC().Format("2006-01-02"), r.By, reset)
		}
		w.Human("\n")
		if r.Note != "" {
			w.Human("            %s%s%s\n", dim, r.Note, reset)
		}
	}
	return nil
}

func checkedClear(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo checked clear PAGE")
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
