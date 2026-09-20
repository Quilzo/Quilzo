// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package site

import (
	"fmt"
	"sort"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/store"
)

// Pointing every reference at a different file.
//
// # Why this is here rather than in the command that first needed it
//
// Because the browser needs the same answer, and two surfaces that each
// implement "replace this picture everywhere" will disagree — one of them will
// walk pages and not records, or match the bare id and not the path spelling,
// and the site will be half replaced by whichever surface somebody used. That
// is not a hypothetical: the image-rights gate matched bare ids only, so a
// licence expiring on a hero image did not stop a publish, and internal/media
// now holds one answer about what a reference looks like for exactly that
// reason.
//
// # Pages and records both
//
// In a shop the product photograph is on a record, so rewriting only pages
// would leave the catalogue on the retired picture. Records live in nested
// subtrees that PagesAt skips by design, so they are a second walk — the same
// shape brandFindings documents, and the same trap: a version that reads only
// PagesAt reports success having checked none of them.
//
// # One commit
//
// Records are written into the tree first and the pages are built onto that
// tree, so the two land together. Two commits would leave a site that is half
// replaced between them, which is the state this whole operation exists to get
// out of.

// ReplaceAsset points every draft reference at a different stored file.
//
// Returns how many references changed and what they were in. Nothing is
// committed when nothing matched: an empty commit is a history entry that says
// somebody did something, and nobody did.
func ReplaceAsset(s *store.Store, oldID, newID, author string) (
	int, []string, error) {

	if oldID == newID {
		return 0, nil, fmt.Errorf(
			"a file cannot replace itself; two identical pictures have one " +
				"address here")
	}
	tree, err := draftTreeOf(s)
	if err != nil {
		return 0, nil, err
	}
	total := 0
	var touched []string

	// Records first, because the tree they produce is what the pages are then
	// written into. The other order builds a tree from pages and then replaces
	// it, losing the record edits without saying so.
	if tree != "" {
		cache := collection.NewCache()
		names, nerr := cache.Names(s, tree)
		if nerr != nil {
			return 0, nil, fmt.Errorf(
				"the collections could not be listed, so no record was "+
					"rewritten and the result would have been half done: %w",
				nerr)
		}
		sort.Strings(names)
		for _, name := range names {
			idx, ierr := cache.For(s, tree, name)
			if ierr != nil {
				return 0, nil, fmt.Errorf(
					"collection %s could not be read, so nothing in it was "+
						"rewritten: %w", name, ierr)
			}
			recs, _ := idx.Query(collection.Query{})
			var batch []collection.Record
			for _, rec := range recs {
				out, n := media.ReplaceID(rec.Fields, oldID, newID)
				fields, ok := out.(map[string]any)
				if n == 0 || !ok {
					continue
				}
				total += n
				touched = append(touched, name+"/"+rec.ID)
				rec.Fields = fields
				batch = append(batch, rec)
			}
			if len(batch) == 0 {
				continue
			}
			tree, _, err = collection.PutMany(s, tree, name, batch, time.Now())
			if err != nil {
				return 0, nil, err
			}
		}
	}

	pages, err := PagesAt(s, RefDraft)
	if err != nil {
		return 0, nil, err
	}
	for name, body := range pages {
		out, n := media.ReplaceID(body, oldID, newID)
		if n == 0 {
			continue
		}
		total += n
		touched = append(touched, name)
		pages[name] = out
	}
	if total == 0 {
		return 0, nil, nil
	}
	sort.Strings(touched)

	// Preserved from the tree the records were written into rather than from
	// the parent commit: reading the parent would carry the version before the
	// record edits, and the edits would vanish with no error anywhere.
	flat, err := store.BuildTree(s, pages)
	if err != nil {
		return 0, nil, err
	}
	carried, err := collection.Preserve(s, tree)
	if err != nil {
		return 0, nil, err
	}
	final := flat
	if len(carried) > 0 {
		final, err = s.PutNested(flat, carried)
		if err != nil {
			return 0, nil, err
		}
	}

	message := fmt.Sprintf("media: %s replaces %s in %d place(s)",
		shortID(newID), shortID(oldID), total)
	if err := commitDraft(s, final, message, author); err != nil {
		return 0, nil, err
	}
	return total, touched, nil
}

// draftTreeOf is the tree the draft is at, falling back to what is live.
func draftTreeOf(s *store.Store) (string, error) {
	cid := s.GetRef(RefDraft)
	if cid == "" {
		cid = s.GetRef(RefLive)
	}
	if cid == "" {
		return "", nil
	}
	c, err := s.GetCommit(cid)
	if err != nil {
		return "", err
	}
	return c.Tree, nil
}

// commitDraft moves the draft onto a tree, under the ref lock.
func commitDraft(s *store.Store, tree, message, author string) error {
	return s.WithRefLock(func() error {
		parent := s.GetRef(RefDraft)
		if parent == "" {
			parent = s.GetRef(RefLive)
		}
		var parents []string
		if parent != "" {
			parents = []string{parent}
		}
		cid, err := s.PutCommit(store.Commit{
			Tree: tree, Parents: parents, Message: message,
			Author: author, At: time.Now().Unix(),
		})
		if err != nil {
			return err
		}
		return s.SetRef(RefDraft, cid)
	})
}
