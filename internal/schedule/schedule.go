// Package schedule publishes at a time somebody chose earlier.
//
// # Why this is small
//
// Publishing here is a pointer move, so scheduling it is a note saying which
// commit and when. There is no staging area to build, no copy to keep in sync,
// and no half-published state to recover from — the same properties that make
// rollback safe make this nearly free.
//
// # The gates do not get skipped because time passed
//
// The interesting failure in every scheduled-publishing feature is that the
// checks run when somebody clicks the button and not when the thing actually
// goes out. A page approved on Monday, edited on Tuesday and published by a
// timer on Wednesday went out unapproved, and the audit trail says it was
// approved.
//
// Here the gates run at the moment of publication, against the content as it
// stands then. Approvals are bound to a content hash, so an edit after
// scheduling invalidates them by construction and the scheduled publish is
// refused rather than shipping unreviewed work.
//
// # A schedule names a commit, not "the draft"
//
// An entry describes a specific set of bytes. If the draft moves on, the entry
// is stale: it describes publishing something nobody has looked at since.
// Stale entries are reported and not fired, because "publish whatever is
// current at nine on Friday" is a different and much worse instruction than the
// one somebody thought they were giving.
package schedule

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

// MaxAhead bounds how far into the future something may be scheduled.
//
// A year. Beyond that the person who scheduled it has usually left, the content
// is stale, and nobody remembers it is coming.
const MaxAhead = 365 * 24 * time.Hour

var reCommit = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Entry is one scheduled publication.
type Entry struct {
	Commit string `json:"commit"`
	At     int64  `json:"at"`
	// By and Note are for whoever finds this in the list next week.
	By   string `json:"by"`
	Note string `json:"note,omitempty"`
	// CreatedAt is when the decision was made, which is what makes "scheduled
	// three months ago" visible.
	CreatedAt int64 `json:"created_at"`
	// Done records the outcome, so a fired entry stays in the record rather
	// than vanishing.
	Done   bool   `json:"done,omitempty"`
	Result string `json:"result,omitempty"`
}

// Due reports whether this entry's time has come.
func (e Entry) Due(now time.Time) bool { return !e.Done && now.Unix() >= e.At }

// Schedule is the set of scheduled publications.
type Schedule struct {
	Entries []Entry `json:"entries"`
}

// Add schedules a commit.
func (s *Schedule) Add(commit string, at time.Time, by, note string,
	now time.Time) error {

	if !reCommit.MatchString(commit) {
		return fmt.Errorf("a schedule names a commit, and %q is not one", commit)
	}
	if at.Before(now) {
		return fmt.Errorf(
			"%s is in the past. A schedule with a past time either fires "+
				"immediately or never, and which one it does should not depend "+
				"on when a timer happens to run",
			at.UTC().Format(time.RFC3339))
	}
	if at.Sub(now) > MaxAhead {
		return fmt.Errorf(
			"%s is more than a year away. By then whoever scheduled it has "+
				"usually moved on and the content is stale",
			at.UTC().Format(time.RFC3339))
	}
	for _, e := range s.Entries {
		if !e.Done && e.Commit == commit {
			return fmt.Errorf("%s is already scheduled for %s", commit[:12],
				time.Unix(e.At, 0).UTC().Format(time.RFC3339))
		}
	}
	s.Entries = append(s.Entries, Entry{
		Commit: commit, At: at.Unix(), By: by, Note: note, CreatedAt: now.Unix(),
	})
	sort.Slice(s.Entries, func(i, j int) bool { return s.Entries[i].At < s.Entries[j].At })
	return nil
}

// Cancel removes a pending entry, accepting the shortened id the tool prints.
func (s *Schedule) Cancel(commit string) bool {
	for i := range s.Entries {
		if !s.Entries[i].Done && matches(s.Entries[i].Commit, commit) {
			s.Entries = append(s.Entries[:i], s.Entries[i+1:]...)
			return true
		}
	}
	return false
}

// matches compares a full id against a prefix, refusing prefixes short enough
// to collide — a cancel that removes the wrong entry is worse than one that
// removes none.
func matches(full, given string) bool {
	if full == given {
		return true
	}
	if len(given) < 8 || len(given) > len(full) {
		return false
	}
	return full[:len(given)] == given
}

// Pending returns the entries that have not fired.
func (s *Schedule) Pending(now time.Time) []Entry {
	var out []Entry
	for _, e := range s.Entries {
		if !e.Done {
			out = append(out, e)
		}
	}
	return out
}

// Due returns the entries whose time has come.
func (s *Schedule) Due(now time.Time) []Entry {
	var out []Entry
	for _, e := range s.Entries {
		if e.Due(now) {
			out = append(out, e)
		}
	}
	return out
}

// Complete records what happened to an entry.
//
// Kept rather than removed. A schedule that deletes entries as it fires them
// leaves nobody able to answer "what went out on Friday and who decided that",
// which is the question an audit asks first.
func (s *Schedule) Complete(commit, result string) {
	for i := range s.Entries {
		if s.Entries[i].Commit == commit && !s.Entries[i].Done {
			s.Entries[i].Done = true
			s.Entries[i].Result = result
			return
		}
	}
}

// Staleness is what an entry describes relative to the current draft.
type Staleness struct {
	Entry Entry
	// Stale means the draft has moved since this was scheduled.
	Stale bool
	// Current is what the draft is now, for the message.
	Current string
}

// Check compares pending entries against the current draft.
func (s *Schedule) Check(draft string, now time.Time) []Staleness {
	var out []Staleness
	for _, e := range s.Pending(now) {
		out = append(out, Staleness{
			Entry: e, Stale: draft != "" && e.Commit != draft, Current: draft,
		})
	}
	return out
}
