// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/note"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

// Saying "this paragraph is wrong".
//
// internal/collab could already record that somebody agreed to a commit and a
// sentence about why. It could not record a remark about a particular field of
// a particular page, which is most of what editorial review actually consists
// of. See internal/note for why these live outside the store and why each one
// carries the hash it was written against.

func cmdNote(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "add":
		return noteAdd(root, args[1:])
	case "list":
		return noteList(root, args[1:])
	case "resolve":
		return noteResolve(root, args[1:])
	case "remove", "rm":
		return noteRemove(root, args[1:])
	default:
		return fmt.Errorf(
			"unknown note command %q; try add, list, resolve or remove", args[0])
	}
}

func notesDir(root string) string { return filepath.Join(root, "notes") }

func openNotes(root string) (*note.Store, error) { return note.Open(notesDir(root)) }

// pageHash is what a note is anchored to.
//
// The hash of the page as it stands in the draft. Empty when the page is not
// in the draft, which is not an error: a note about a page somebody is about
// to write is a reasonable thing to leave, and Stale is written to treat an
// unknown anchor as "cannot say" rather than as drift.
func pageHash(root, page string) string {
	s, err := open(root)
	if err != nil {
		return ""
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		return ""
	}
	body, ok := pages[page]
	if !ok {
		return ""
	}
	return schema.ContentHash(body)
}

func noteAdd(root string, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	field := fs.String("field", "", "which field this is about")
	author := fs.String("author", "", "who is saying it")
	rest, flags := leadingArgs(args, 2)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) < 2 {
		return fmt.Errorf(
			"usage: quilzo note add PAGE \"what you want to say\" " +
				"[--field NAME] [--author WHO]")
	}
	page, text := rest[0], rest[1]

	who := strings.TrimSpace(*author)
	if who == "" {
		// The caller this command already resolved, rather than a flag
		// somebody has to remember. An anonymous note is refused by the
		// package, so guessing wrongly here would be worse than asking.
		who = resolveCaller(root, "").Name
	}
	if who == "" {
		return fmt.Errorf("who is saying this? Pass --author, or sign in")
	}

	st, err := openNotes(root)
	if err != nil {
		return err
	}
	n, err := st.Add(note.Note{
		Page: page, Field: strings.TrimSpace(*field), Author: who,
		Text: text, Content: pageHash(root, page),
	}, time.Now())
	if err != nil {
		return err
	}
	// AU-3: who did what. A note names a colleague and can be removed, so
	// "somebody left this and somebody took it away" has to be answerable from
	// the log rather than from the directory, which is the thing that changed.
	record(root, resolveCaller(root, "").auditRecord("note.add", "/"+page,
		audit.Success, map[string]string{"id": n.ID, "field": n.Field}))

	if w.JSON(n) {
		return nil
	}
	w.Human("  %snoted on %s%s", dim, page, reset)
	if n.Field != "" {
		w.Human("%s, about %s%s", dim, n.Field, reset)
	}
	w.Human("  %s%s%s\n", dim, n.ID[:12], reset)
	return nil
}

func noteList(root string, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	all := fs.Bool("all", false, "include notes somebody has resolved")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}

	st, err := openNotes(root)
	if err != nil {
		return err
	}

	pages := rest
	if len(pages) == 0 {
		pages, err = st.Pages()
		if err != nil {
			return err
		}
	}
	if len(pages) == 0 {
		w.Human("  %snobody has left a note%s\n", dim, reset)
		return nil
	}

	type row struct {
		Page  string      `json:"page"`
		Notes []note.Note `json:"notes"`
	}
	var out []row
	for _, page := range pages {
		notes, lerr := st.List(page)
		if lerr != nil {
			return lerr
		}
		if !*all {
			kept := notes[:0]
			for _, n := range notes {
				if !n.Resolved {
					kept = append(kept, n)
				}
			}
			notes = kept
		}
		if len(notes) > 0 {
			out = append(out, row{page, notes})
		}
	}

	if w.JSON(out) {
		return nil
	}
	if len(out) == 0 {
		w.Human("  %snothing outstanding%s\n", dim, reset)
		return nil
	}
	for _, r := range out {
		now := pageHash(root, r.Page)
		w.Human("\n%s%s%s\n", bold, r.Page, reset)
		for _, n := range r.Notes {
			mark := " "
			if n.Resolved {
				mark = "✓"
			}
			where := ""
			if n.Field != "" {
				where = " (" + n.Field + ")"
			}
			w.Human("  %s %s%s%s%s\n", mark, n.Author, dim, where, reset)
			w.Human("    %s\n", n.Text)
			if n.Stale(now) {
				// Said, not hidden. The tool cannot know whether a remark
				// about a paragraph still applies after the paragraph was
				// rewritten; the person reading it can.
				w.Human("    %sthe page has changed since this was written%s\n",
					yellow, reset)
			}
			if n.Resolved {
				w.Human("    %sresolved by %s%s\n", dim, n.ResolvedBy, reset)
			}
			w.Human("    %s%s%s\n", dim, n.ID[:12], reset)
		}
	}
	w.Human("\n")
	return nil
}

func noteResolve(root string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: quilzo note resolve PAGE ID")
	}
	st, err := openNotes(root)
	if err != nil {
		return err
	}
	full, err := expandNoteID(st, args[0], args[1])
	if err != nil {
		return err
	}
	who := resolveCaller(root, "").Name
	if who == "" {
		who = "the console"
	}
	if err := st.Resolve(args[0], full, who, time.Now()); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("note.resolve",
		"/"+args[0], audit.Success, map[string]string{"id": full}))
	w.Human("  %sresolved%s\n", dim, reset)
	return nil
}

func noteRemove(root string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: quilzo note remove PAGE ID\n" +
			"  to finish with a note and keep the conversation readable, " +
			"resolve it instead")
	}
	st, err := openNotes(root)
	if err != nil {
		return err
	}
	full, err := expandNoteID(st, args[0], args[1])
	if err != nil {
		return err
	}
	if err := st.Remove(args[0], full); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("note.remove",
		"/"+args[0], audit.Success, map[string]string{"id": full}))
	w.Human("  %sremoved%s\n", dim, reset)
	return nil
}

// expandNoteID turns the short id the list prints into the whole one.
//
// The list shows twelve characters because thirty-two is unreadable, so those
// twelve have to be what you can type back. An ambiguous prefix is refused
// rather than resolved to the first match: resolving somebody else's note
// because two ids shared a prefix is a silent wrong answer.
func expandNoteID(st *note.Store, page, given string) (string, error) {
	notes, err := st.List(page)
	if err != nil {
		return "", err
	}
	var found []string
	for _, n := range notes {
		if strings.HasPrefix(n.ID, given) {
			found = append(found, n.ID)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", fmt.Errorf("no note on %s starts with %q", page, given)
	default:
		return "", fmt.Errorf(
			"%d notes on %s start with %q; give more of the id",
			len(found), page, given)
	}
}
