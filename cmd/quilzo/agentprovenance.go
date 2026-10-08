// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// What an agent writes says that a model wrote it.
//
// # The gap
//
// An agent's write_page stored the page and recorded nothing about where it
// came from. The commit said "agent:", so the review queue knew; the
// provenance index did not, so the page had no mark — and an unmarked page
// is one `provenance check` calls a gap and the publish gate refuses, until
// somebody records by hand that a person did not write it. The one writer
// that certainly used a model was the one writer that never said so.
//
// # What the record says
//
// That a trained model generated it (IPTC trainedAlgorithmicMedia), which
// model, what the run was asked to do, and which agent. The author is the
// person who ran or continued the run: Article 50 puts the obligation on a
// person, never on the tool. When a person approved this very write before it
// happened, they are recorded as having reviewed it, because they read exactly
// what was written — that is what an ask-first approval shows them.
//
// Every write replaces the page's record. The content changed, so the old
// record describes bytes the page no longer has.

// markAgentWrite records the provenance of one page an agent wrote.
//
// Non-fatal: the write has happened, and turning "the provenance file is
// read-only" into a failed run would be worse. The publish gate refuses an
// unmarked page, so a failure here surfaces there.
func markAgentWrite(root string, s *store.Store, page, agentName, model,
	goal string, by *Caller, reviewed bool) {

	idx, err := loadProvenance(root)
	if err != nil {
		return
	}
	ids, err := site.PageIDsAt(s, site.RefDraft)
	if err != nil || ids[page] == "" {
		return
	}
	rec := provenance.Record{
		ContentHash: ids[page],
		SourceType:  provenance.TrainedAlgorithmicMedia,
		Model:       model,
		Instruction: clipGoal(goal),
		Note:        "written by the agent " + agentName,
	}
	if model == "" {
		// A walk of the manifest with no model: a program wrote it, and no
		// trained model was involved.
		rec.SourceType = provenance.AlgorithmicMedia
	}
	if by != nil {
		rec.Author = by.Name
		if reviewed {
			rec.ReviewedBy = by.Name
		}
	}
	if rec.Author == "" {
		rec.Author = "the operator"
	}
	if err := idx.Set(page, rec); err != nil {
		return
	}
	_ = saveJSON(provPath(root), idx)
}

// approvedWrite reports whether the write to page is the one a person just
// approved, having been shown it.
func approvedWrite(from *agentResume, page string) bool {
	if from == nil || from.Verdict == nil || !from.Verdict.Approve ||
		from.Prior == nil || from.Prior.Trace.Waiting == nil {
		return false
	}
	w := from.Prior.Trace.Waiting
	if w.N != from.Verdict.N || w.Action.Op != "write_page" {
		return false
	}
	asked, _ := w.Action.Input["page"].(string)
	return asked == page
}

// clipGoal bounds the instruction a record keeps, at a character boundary.
func clipGoal(goal string) string {
	r := []rune(goal)
	if len(r) > 500 {
		return string(r[:500]) + "…"
	}
	return goal
}
