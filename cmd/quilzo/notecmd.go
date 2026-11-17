// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/note"
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
		args = []string{bareRuns["note"]}
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
// The store's own id for the page as it stands in the draft — the same anchor
// provenance and `checked` use, because three records that all mean "what did
// this page say" have to agree or one of them looks stale when it is not.
//
// Empty when the page is not in the draft, which is not an error: a note about
// a page somebody is about to write is a reasonable thing to leave, and Stale
// treats an unknown anchor as "cannot say" rather than as drift.
func pageHash(root, page string) string {
	s, err := open(root)
	if err != nil {
		return ""
	}
	ids, err := pageHashes(s, site.RefDraft)
	if err != nil {
		return ""
	}
	return ids[page]
}

func noteAdd(root string, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	field := fs.String("field", "", "which field this is about")
	author := fs.String("author", "", "who is saying it, at a console nobody signs in to")
	rest, flags := leadingArgs(args, 2)
	if err := parseFlags(fs, flags, &rest, 2); err != nil {
		return err
	}
	if len(rest) < 2 {
		return fmt.Errorf(
			"usage: quilzo note add PAGE \"what you want to say\" " +
				"[--field NAME] [--author WHO]")
	}
	page, text := rest[0], rest[1]

	who := strings.TrimSpace(*author)
	caller := resolveCaller(root, "")
	switch {
	case caller.Verified:
		// The signed-in caller, whatever the flag says. The flag was taken
		// as the author whenever it was given, so an author could leave
		// "approved for publication, go ahead" in the publisher's name, and
		// /notes and `note list` showed it as the publisher's; only the
		// audit log knew otherwise. Refused rather than overridden, so the
		// person who typed another name is told it was not used.
		if who != "" && !strings.EqualFold(who, caller.Name) {
			return fmt.Errorf("you are signed in as %s, so a note you leave is %s's; "+
				"--author names the writer only at a console nobody signs in to",
				onOneLine(caller.Name), onOneLine(caller.Name))
		}
		who = caller.Name
	case who == "":
		// The caller this command already resolved, rather than a flag
		// somebody has to remember. An anonymous note is refused by the
		// package, so guessing wrongly here would be worse than asking.
		who = caller.Name
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
	record(root, caller.auditRecord("note.add", "/"+page,
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
	if err := parseFlags(fs, flags, &rest, 1); err != nil {
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
	// Only the pages the caller may read, as list_notes answers over MCP.
	// A reader may run this (privilege.go), and it listed every page with
	// notes: a reader denied a page was shown its name and what colleagues
	// had written about it, which the deny was there to keep from them.
	may, err := pageCheck(root, resolveCaller(root, ""), auth.ActView)
	if err != nil {
		return err
	}
	kept := pages[:0]
	for _, page := range pages {
		if may(page) {
			kept = append(kept, page)
		}
	}
	pages = kept
	type row struct {
		Page  string      `json:"page"`
		Notes []note.Note `json:"notes"`
	}
	if len(pages) == 0 {
		// [] under --json, as below when nothing is outstanding. This wrote
		// only through Human, so a script asking for the notes on a store
		// nobody had noted was answered with nothing, exited 0, and took
		// the empty output for the answer.
		if w.JSON([]row{}) {
			return nil
		}
		w.Human("  %snobody has left a note%s\n", dim, reset)
		return nil
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
		w.Human("\n%s%s%s\n", bold, onOneLine(r.Page), reset)
		for _, n := range r.Notes {
			mark := " "
			if n.Resolved {
				mark = "✓"
			}
			where := ""
			if n.Field != "" {
				where = " (" + n.Field + ")"
			}
			// The author, the field and the text are whatever somebody
			// typed. Printed raw, a newline let one note print a second
			// shaped exactly as a note of the publisher's, and ESC and CR
			// rewrote what the terminal showed. The name and field stay on
			// their line, and the text's own lines sit deeper than any line
			// this list prints about a note, so none can pass for one.
			w.Human("  %s %s%s%s%s\n", mark, onOneLine(n.Author), dim, onOneLine(where), reset)
			w.Human("    %s\n", indentedForTerminal(n.Text, "      "))
			if n.Stale(now) {
				// Said, not hidden. The tool cannot know whether a remark
				// about a paragraph still applies after the paragraph was
				// rewritten; the person reading it can.
				w.Human("    %sthe page has changed since this was written%s\n",
					yellow, reset)
			}
			if n.Resolved {
				w.Human("    %sresolved by %s%s\n", dim, onOneLine(n.ResolvedBy), reset)
			}
			w.Human("    %s%s%s\n", dim, n.ID[:12], reset)
		}
	}
	w.Human("\n")
	return nil
}

func noteResolve(root string, args []string) error {
	// The page and the note, and a word after them is not dropped.
	args, err := positionals(args, 2)
	if err != nil {
		return err
	}
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
	// The note as it now stands under --json. This answered only through
	// Human, so a script was given nothing, exit 0, and took that for the
	// answer.
	if n, gerr := st.Get(args[0], full); gerr == nil && w.JSON(n) {
		return nil
	}
	w.Human("  %sresolved%s\n", dim, reset)
	return nil
}

func noteRemove(root string, args []string) error {
	args, err := positionals(args, 2)
	if err != nil {
		return err
	}
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
	n, err := st.Get(args[0], full)
	if err != nil {
		return err
	}
	// A note's author may take it back; taking down somebody else's is a
	// publisher's act, as taking down somebody else's message in a room
	// was. Any author could remove anyone's note, so the author whose
	// heading a publisher had questioned could make the question vanish,
	// leaving no trace outside the audit log. On a store with no access
	// control authorise lets everyone through, as the rest of it does.
	//
	// Whose it is, by the name to the letter. The policy holds "Pat" and
	// "pat" apart as two people (auth.Policy.Evaluate), and compared without
	// regard to capitals Pat the author took down a remark of pat the
	// publisher's as her own.
	caller := resolveCaller(root, "")
	theirs := caller.Name != n.Author
	if theirs {
		if err := authorise(root, caller, auth.ActPublish, pageResource(args[0])); err != nil {
			return fmt.Errorf("this note is %s's; taking down somebody else's note "+
				"takes a publisher: %w\n  to finish with it and keep the "+
				"conversation readable, resolve it instead",
				onOneLine(n.Author), err)
		}
	}
	if err := st.Remove(args[0], full); err != nil {
		return err
	}
	detail := map[string]string{"id": full}
	if theirs {
		detail["taken_down"] = "true"
	}
	record(root, caller.auditRecord("note.remove", "/"+args[0], audit.Success, detail))
	// Something under --json, as resolve answers; see there.
	if w.JSON(map[string]any{"page": args[0], "id": full, "removed": true}) {
		return nil
	}
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
