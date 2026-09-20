// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/site"
)

// Replacing a picture with a newer one.
//
// media.File.Supersedes was declared with a comment saying exactly why it
// matters — "a page still pointing at last season's packaging shot is not a
// corrupted store, it is a store where nobody recorded that a newer one
// exists" — and nothing in this program ever wrote it or read it. A field
// whose own documentation describes a problem it does not solve.
//
// # Why this is not "upload over the top of it"
//
// Because nothing here can be overwritten, and that is the point rather than a
// limitation. A file is addressed by the hash of its bytes: different bytes
// are a different address, always. So replacing a picture is not one operation
// on one object, it is two facts — this file is the successor of that one, and
// every piece of content that pointed at the old one now points at the new.
//
// Recording only the first leaves a library that knows and a site that does
// not. Doing only the second leaves a site that is right and no record of why
// it changed, so the next person to find the old file in the library has no
// way to know it was retired.
//
// # Why the rewrite is the default
//
// It edits content, which usually earns a flag here. It does not earn one this
// time, for the reason the storage model exists: the rewrite lands as an
// ordinary draft commit, the commit it moved from is still stored under its
// own name, and undoing it is a pointer move rather than a restore. The
// dangerous version of this command would be the one that changed the live
// site, and this one cannot.

func mediaReplace(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("replace", flag.ContinueOnError)
	recordOnly := fs.Bool("record-only", false,
		"note the succession and leave the content pointing at the old file")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf(
			"usage: quilzo media replace OLD NEW [--record-only]\n" +
				"  OLD is the picture being retired and NEW is the one " +
				"taking its place")
	}
	oldID, newID := pos[0], pos[1]

	lib, err := openMedia(root)
	if err != nil {
		return fmt.Errorf("the media library could not be opened: %w", err)
	}
	old, err := lib.Stat(oldID)
	if err != nil {
		return fmt.Errorf("the picture being replaced: %w", err)
	}
	next, err := lib.Stat(newID)
	if err != nil {
		return fmt.Errorf("the picture replacing it: %w", err)
	}
	if old.ID == next.ID {
		return fmt.Errorf(
			"%s is the same file as itself. Two identical pictures have one "+
				"address here, so uploading the same bytes again does not "+
				"make a newer one", short(old.ID))
	}
	if old.Kind != next.Kind {
		// A video standing in for a picture would leave every page rendering
		// an <img> at a file no browser will draw, and the page would look
		// broken rather than wrong.
		return fmt.Errorf(
			"%s is a %s and %s is a %s. A replacement has to be the same kind "+
				"of thing, because the content around it was written for one",
			old.Name, old.Kind, next.Name, next.Kind)
	}
	if err := noSuccessionLoop(lib, old.ID, next.ID); err != nil {
		return err
	}

	// The succession, first. If the rewrite fails halfway there is at least a
	// record that somebody meant to retire this file; if the record failed
	// after a successful rewrite, the site would be right and the library
	// would say nothing about why.
	if err := noteSuccession(lib, next, old.ID); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	changed := 0
	var where []string
	if !*recordOnly {
		st, oerr := open(root)
		if oerr != nil {
			return oerr
		}
		changed, where, err = site.ReplaceAsset(st, old.ID, next.ID, caller.Name)
		if err != nil {
			return err
		}
	}

	record(root, caller.auditRecord("media.replace", "/"+next.ID,
		audit.Success, map[string]string{
			"replaced": short(old.ID), "with": short(next.ID),
			"rewritten": fmt.Sprint(changed),
		}))

	if w.JSON(map[string]any{
		"replaced": old.ID, "with": next.ID,
		"rewritten": changed, "where": where,
	}) {
		return nil
	}
	w.Human("%s%s%s now supersedes %s%s%s\n",
		bold, next.Name, reset, bold, old.Name, reset)
	if *recordOnly {
		w.Human("  %sthe content still points at %s; this only records that a "+
			"newer one exists%s\n", dim, old.Name, reset)
		return nil
	}
	if changed == 0 {
		w.Human("  %snothing in the draft pointed at it, so only the library "+
			"changed%s\n", dim, reset)
	} else {
		w.Human("  %s%d reference(s) rewritten in the draft%s\n",
			dim, changed, reset)
		for _, p := range where {
			w.Human("    %s%s%s\n", dim, p, reset)
		}
		w.Human("  %sthe commit this moved from is still stored, so undoing "+
			"it is `quilzo rollback` rather than a restore%s\n", dim, reset)
	}
	// The half the field was declared for. A live site still pointing at the
	// retired file is not an error and is exactly what somebody needs to know.
	if used, uerr := mediaInUse(root, old.ID); uerr == nil && used {
		w.Human("  %sthe live site still uses %s; publish to change that%s\n",
			yellow, old.Name, reset)
	}
	return nil
}

// noteSuccession writes Supersedes onto the replacement.
func noteSuccession(lib *medialib.Library, next media.File, oldID string) error {
	if next.Supersedes == oldID {
		return nil
	}
	next.Supersedes = oldID
	_, body, err := lib.Get(next.ID)
	if err != nil {
		return err
	}
	// Written back through the library, which re-derives the narrower copies.
	// The same treatment `media focus` gives, for the same reason: each
	// rendition is its own file at its own hash.
	next.Renditions = nil
	return lib.Put(next, body)
}

// noSuccessionLoop refuses a chain that comes back to where it started.
//
// A chain is ordinary — season one to two to three — and a loop is not. It
// would make "what did this replace" a walk with no end, and the walk is the
// only reason to record the relationship at all.
func noSuccessionLoop(lib *medialib.Library, oldID, newID string) error {
	seen := map[string]bool{newID: true}
	at := oldID
	for range 64 {
		if at == "" {
			return nil
		}
		if seen[at] {
			return fmt.Errorf(
				"%s already supersedes %s, directly or through a chain. "+
					"Recording this would make the succession a loop, and "+
					"the point of recording it is being able to follow it",
				short(oldID), short(newID))
		}
		seen[at] = true
		f, err := lib.Stat(at)
		if err != nil {
			return nil
		}
		at = f.Supersedes
	}
	return fmt.Errorf(
		"the succession behind %s is more than 64 deep, which is not a "+
			"history somebody made", short(oldID))
}
