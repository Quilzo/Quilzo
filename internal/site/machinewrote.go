// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"fmt"
	"slices"

	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/store"
)

// machineWalkLimit is how many commits MachineWroteSince reads before it
// stops and answers as though a model wrote what it did not read.
//
// Bounded because the review screen asks on every visit, and a store that
// has never been published asks of its whole history. Ten thousand saves
// since the last publish is far past any draft somebody reviews, and past
// it the answer that asks a person is the one that cannot put a model's
// change live unread. A variable so a test can reach the bound without
// writing ten thousand commits.
var machineWalkLimit = 10000

// MachineWroteSince is the newest commit a machine wrote among those that
// publishing commit would put live, or nil when people wrote all of them.
//
// Those are commit itself and its ancestors, back to whatever has been
// live. A version that has been live passed this question when it went
// live, and what is behind it went with it, so the walk stops there rather
// than only at the version live now: after a rollback the draft is built
// on a version that is no longer the live one, and stopping only at the
// live one would send the walk back through history that was read and
// approved long ago. Commit itself is always
// asked, live before or not, so putting a model's commit live again is
// asked about as it always was.
//
// One function for every surface. The admin, quilzo publish, the machine
// interface, scheduled publishing and promotion each read the newest
// commit's message and nothing else, so a person's typo fix on top of an
// agent's change made the agent's change a person's on all five of them.
//
// A history that cannot be read to the end, too long or with a commit
// missing, is answered with a MachineChange saying why (Unread), not with
// nil and not with an error: nobody can show a person wrote it, and an
// error would stop a person's approval being the way through. Commit
// itself not being readable is an error, as it is for publishing it.
//
// The walk goes on past the newest machine's commit, to the same bound,
// for everybody the machines wrote for (MachineChange.People). It stopped
// there, so a proposal named only the person that one commit was made for:
// dana's client rewrote the pricing, lee's client then wrote the about
// page, and with a count of approvals set dana's own approval counted for
// her client's prices. Past the bound, or at a commit that cannot be read,
// the newest machine's change is still the answer, as it was, and whoever
// a machine wrote for further back is not known.
func MachineWroteSince(s *store.Store, commit string) (*collab.MachineChange, error) {
	if _, err := s.GetCommit(commit); err != nil {
		return nil, err
	}
	// The record of what has been live, or failing that what is live now.
	// Without the record the walk goes further back, and is never wrong
	// for it.
	reviewed := map[string]bool{}
	pubs, err := Publications(s)
	if err != nil {
		pubs = []string{s.GetRef(RefLive)}
	}
	for _, p := range pubs {
		reviewed[p] = true
	}

	var found *collab.MachineChange
	seen := map[string]bool{commit: true}
	queue := []string{commit}
	for read := 0; len(queue) > 0; read++ {
		id := queue[0]
		queue = queue[1:]
		if read >= machineWalkLimit {
			if found != nil {
				return found, nil
			}
			return &collab.MachineChange{Commit: id, Unread: fmt.Sprintf(
				"more than %d commits since the last publish", machineWalkLimit)}, nil
		}
		c, err := s.GetCommit(id)
		if err != nil {
			if found != nil {
				return found, nil
			}
			return &collab.MachineChange{Commit: id, Unread: fmt.Sprintf(
				"commit %s cannot be read: %v", shortID(id), err)}, nil
		}
		if collab.MachineWrote(c.Message) {
			if found == nil {
				found = &collab.MachineChange{Commit: id, Author: c.Author, Message: c.Message}
			}
			if _, person := collab.WrittenFor(c.Message, c.Author); person != "" &&
				!slices.Contains(found.People, person) {
				found.People = append(found.People, person)
			}
		}
		// Every parent, not the first alone: a merge brings in the other
		// side's commits too, and whoever wrote them is asked as well.
		for _, p := range c.Parents {
			if p == "" || seen[p] || reviewed[p] {
				continue
			}
			seen[p] = true
			queue = append(queue, p)
		}
	}
	return found, nil
}
