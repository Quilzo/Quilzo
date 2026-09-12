// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Saying where content came from when this program is the thing that made it.
//
// # The gap
//
// Publishing refuses content that declares no provenance, which is the right
// gate. Three paths put content into a store and declared nothing: `quilzo
// demo`, `quilzo import`, and the transfer import in the browser. Only the
// assistant and the admin's editor ever wrote a record.
//
// So the first publish after any of them was refused, naming every page, and
// the operator's only ways forward were to mark each one by hand or to waive
// the gate for the whole site with --force-unmarked. `quilzo demo` was the
// worst of the three: it is the first command anybody runs, it writes twelve
// pages, and the site it makes could be published once by the demo command
// itself and not again.
//
// `quilzo add` is deliberately not in that list. Somebody staging a page they
// wrote is the case where the program genuinely does not know — a person may
// have written it, or pasted it out of a model — and inventing an answer there
// is the thing the gate exists to prevent. These three know, because this
// program produced the bytes.
//
// `quilzo template use` is not in it either: it writes a sample file to disk
// and tells you to `quilzo add` it, so nothing reaches the store until a
// person decides it should.
//
// `quilzo provenance backfill` cannot help and is right not to: "an absence of
// evidence is never written down as human authorship". That rule is what makes
// the mark worth believing, and the answer is not to weaken it — it is for the
// commands that *do* know where content came from to say so at the time.
//
// # Why algorithmicMedia
//
// The vocabulary names this case exactly: "produced by software that is not a
// trained model — a template, an import, a scripted migration. Deliberately
// distinct, because calling a database import 'AI-generated' devalues the mark
// that matters."
//
// A demo emits a template. An import converts somebody else's export. Neither
// involves a model, so neither requires an Article 50 disclosure — and
// asserting one would be a false claim in the direction that matters least,
// but still a false claim, and still one that devalues the mark for the
// content where it counts.
//
// humanEdits would be the wrong answer even though a person wrote the demo's
// prose. The record describes how *this store's copy* came to exist, and it
// came to exist because a command emitted it. Recording "a person wrote this"
// for a page the operator has never read is the exact substitution the
// backfill refuses, arrived at by a different route.
//
// # Why the author is the person who ran it
//
// "Article 50 places the obligation on a person or organisation, never on the
// tool." The tool cannot be accountable for what a store publishes; whoever
// ran the command chose to put it there and is. The note names the command, so
// the record says both who is answerable and what actually produced the bytes.

// markGenerated records that this program produced these pages.
//
// Pages that already carry a record are left alone: a second run of `import`
// must not overwrite what somebody has since said about a page, and the
// operator's own statement always outranks a command's guess about itself.
//
// Silent when there is nothing to do, and non-fatal when it fails. This runs
// after the content is already written, and turning "the provenance file is
// read-only" into "your import did not happen" would be the worse outcome —
// the publish gate still refuses unmarked content, so a failure here surfaces
// then, with a message about provenance rather than about an import.
func markGenerated(root string, s *store.Store, by, note string) error {
	idx, err := loadProvenance(root)
	if err != nil {
		return err
	}
	ids, err := site.PageIDsAt(s, site.RefDraft)
	if err != nil {
		return err
	}
	if by == "" {
		by = "the operator"
	}

	changed := false
	for page, hash := range ids {
		if _, already := idx.Records[page]; already {
			continue
		}
		if err := idx.Set(page, provenance.Record{
			ContentHash: hash,
			SourceType:  provenance.AlgorithmicMedia,
			Author:      by,
			Note:        note,
		}); err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return saveJSON(provPath(root), idx)
}

// markGeneratedQuietly is markGenerated for a caller that has already written
// the content and cannot usefully fail.
//
// The error is dropped rather than reported, because every caller here has
// just printed what it did and a second message about a file the operator did
// not ask about is noise at the moment they are reading a success. The gate
// still refuses unmarked content, so nothing is hidden — only deferred to the
// place where it means something.
func markGeneratedQuietly(root string, s *store.Store, by, note string) {
	_ = markGenerated(root, s, by, note)
}
