package site

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/store"
)

// Saving when somebody else got there first.
//
// SaveDraftFrom refuses a write whose base has moved. That is exact and it
// never loses anything, and it puts the whole cost on whoever saved second:
// they are told the draft moved and left to redo the work by hand.
//
// Almost none of those refusals are real collisions. Two people editing
// different pages collide on the ref and nothing else; two people on one page
// usually touch different fields. This tries the merge, and refuses only what
// is genuinely a disagreement — the same compare-and-swap underneath, with the
// easy cases answered instead of returned.
//
// # It still never resolves a disagreement
//
// A field both people changed differently is reported, not decided. So a
// successful merge here means "nobody disagreed", which is a claim worth
// making automatically. A merge that guessed would be one somebody has to
// audit, and nobody audits a merge that says it succeeded.

// MergeConflict is a merge that could not be completed without deciding
// something only a person can decide.
type MergeConflict struct {
	// Base is what the writer read, Actual what the draft is now.
	Base, Actual string
	// Result carries the merge as far as it got, including every conflict and
	// what was resolved. Nothing has been written.
	Result collab.Merged
}

func (m *MergeConflict) Error() string {
	return fmt.Sprintf("%s\n\n  you were editing %s, the draft is now %s\n"+
		"  nothing was written",
		m.Result.Summary(), shortID(m.Base), shortID(m.Actual))
}

// MergeDraftFrom writes a draft, merging with whatever moved underneath it.
//
// Returns the merge either way, so a caller can report what was taken from
// each side on success as well as what needs deciding on failure. A merge
// reported only when it fails is a merge nobody trusts.
func MergeDraftFrom(s *store.Store, pages map[string]any, message, author,
	base string) (string, collab.Merged, error) {

	var cid string
	var merged collab.Merged
	err := s.WithRefLock(func() error {
		current := s.GetRef(RefDraft)
		if current == "" {
			current = s.GetRef(RefLive)
		}
		// Nothing moved, or the caller did not say what they read. Either way
		// there is nothing to merge against and the ordinary write applies —
		// including its own base check, which stays the safety property.
		if base == "" || sameCommit(base, current) {
			var err error
			cid, err = SaveDraftLocked(s, pages, message, author, base)
			return err
		}

		// The three sides. Read inside the lock, because reading the current
		// draft outside it and merging against what it used to be is the bug
		// compare-and-swap exists to prevent, wearing a merge as a disguise.
		full := resolveCommit(s, base)
		wasPages, err := PagesAt(s, full)
		if err != nil {
			return fmt.Errorf("cannot read the commit you were editing (%s): %w",
				shortID(base), err)
		}
		nowPages, err := PagesAt(s, current)
		if err != nil {
			return fmt.Errorf("cannot read the current draft: %w", err)
		}

		merged = collab.Merge(wasPages, pages, nowPages)
		if !merged.Clean() {
			return &MergeConflict{Base: full, Actual: current, Result: merged}
		}

		// Written against `current`, not against the base the writer read. The
		// merge already accounts for everything between them, and passing the
		// stale base would fail the check this just resolved.
		cid, err = SaveDraftLocked(s, merged.Pages, message, author, current)
		return err
	})
	return cid, merged, err
}
