package seo

import (
	"time"

	"github.com/quilzo/quilzo/internal/store"
)

// LastChanged returns, for every page live at head, the time its content last
// actually changed.
//
// The walk is backwards through history comparing object ids. A page whose id
// is the same in commit N and commit N-1 did not change in commit N, whatever
// the commit message says and whoever saved it. That is not an approximation of
// "meaningfully modified" — in a content-addressed store it is the definition,
// because the id *is* the content.
//
// This is what every other CMS gets wrong, and it is not their fault: with rows
// in a table there is no cheap way to tell "saved" from "changed", so
// updated_at moves on every save and lastmod inherits the lie. Google's
// published position — that it may stop trusting lastmod on sites where it
// moves without the content moving — is a direct response to that.
//
// limit bounds the walk. A site with a very long history does not need all of
// it: pages older than the walk simply have no date, and an absent lastmod is
// honest where a guessed one is not.
func LastChanged(s *store.Store, head string, limit int) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	if head == "" {
		return out, nil
	}

	history, err := s.History(head, limit)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return out, nil
	}

	// Walk newest to oldest. The first time a page's id differs from the id it
	// had in the *older* commit, that older-to-newer transition is the change.
	var newer map[string]string
	for i, h := range history {
		tree, err := s.GetTree(h.Commit.Tree)
		if err != nil {
			return nil, err
		}
		when := time.Unix(h.Commit.At, 0).UTC()

		if i == 0 {
			// Everything present at head starts with the head commit's time as
			// its provisional answer, and gets pushed back as the walk finds
			// older commits with the same id.
			for name := range tree {
				out[name] = when
			}
			newer = tree
			continue
		}
		for name, oid := range tree {
			// Only pages still live at head matter; one deleted along the way
			// has no URL to put in a sitemap.
			if _, live := out[name]; !live {
				continue
			}
			if newer[name] == oid {
				// Unchanged between this commit and the next one along, so the
				// change is at least this old.
				out[name] = when
			}
		}
		newer = tree
	}
	return out, nil
}
