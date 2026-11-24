// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/store"
)

// saveAs drafts one page as author, with this message.
func saveAs(t *testing.T, s *store.Store, body, message, author string) string {
	t.Helper()
	id, err := SaveDraft(s, map[string]any{"index": map[string]any{"title": "Home", "body": body}},
		message, author)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A model's change behind a person's later one is found, and named: the
// commit, who it is recorded as written by, and what it said.
//
// The newest commit was the only one ever asked, so a person fixing a typo
// after an agent rewrote the pricing made the whole draft a person's.
func TestAModelsChangeBehindAPersonsIsFound(t *testing.T) {
	for _, prefix := range []string{collab.AgentPrefix, "assist: ", "mcp: "} {
		s := openStore(t)
		saveAs(t, s, "first", "first", "dana")
		if _, err := Publish(s, ""); err != nil {
			t.Fatal(err)
		}
		model := saveAs(t, s, "new prices", prefix+"rewrote the pricing", "writer")
		draft := saveAs(t, s, "new prices, spelt right", "fixed a typo", "dana")

		got, err := MachineWroteSince(s, draft)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatalf("a %q change behind a person's later commit was not found", prefix)
		}
		if got.Commit != model || got.Author != "writer" || got.Message != prefix+"rewrote the pricing" ||
			got.Unread != "" {
			t.Fatalf("found %+v, want the model's commit %s by writer", got, model[:12])
		}
	}
}

// What has been live stops the walk: it went through this question when it
// went live, so a person's change after an approved model's change, or
// after a rollback past one, is a person's.
func TestWhatHasBeenLiveIsNotAskedAgain(t *testing.T) {
	s := openStore(t)
	first := saveAs(t, s, "first", "first", "dana")
	if _, err := Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	saveAs(t, s, "new prices", collab.AgentPrefix+"rewrote the pricing", "writer")
	if _, err := Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	draft := saveAs(t, s, "new prices, spelt right", "fixed a typo", "dana")
	if got, err := MachineWroteSince(s, draft); err != nil || got != nil {
		t.Fatalf("a person's change after a published model's change is judged %+v (%v)", got, err)
	}

	// Rolled back past the model's change, which was live, and the person's
	// change on top of it is still only the person's.
	if _, err := Rollback(s, 1); err != nil {
		t.Fatal(err)
	}
	if s.GetRef(RefLive) != first {
		t.Fatal("the rollback did not go back to the first version")
	}
	if got, err := MachineWroteSince(s, draft); err != nil || got != nil {
		t.Fatalf("after a rollback, a person's change on a version that was live is judged %+v (%v)", got, err)
	}
}

// The commit being published is always asked, even when it has been live:
// putting a model's change live again is not made unasked by its having
// been live once.
func TestTheCommitBeingPublishedIsAlwaysAsked(t *testing.T) {
	s := openStore(t)
	saveAs(t, s, "first", "first", "dana")
	model := saveAs(t, s, "new prices", collab.AgentPrefix+"rewrote the pricing", "writer")
	if _, err := Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	if got, err := MachineWroteSince(s, model); err != nil || got == nil || got.Commit != model {
		t.Fatalf("a model's commit that is live is judged %+v (%v)", got, err)
	}
}

// A first publish asks the whole history, and a person's history is a
// person's.
func TestAFirstPublishAsksTheWholeHistory(t *testing.T) {
	s := openStore(t)
	model := saveAs(t, s, "first", collab.AgentPrefix+"drafted the site", "writer")
	for _, body := range []string{"second", "third", "fourth"} {
		saveAs(t, s, body, "edited "+body, "dana")
	}
	draft := s.GetRef(RefDraft)
	if got, err := MachineWroteSince(s, draft); err != nil || got == nil || got.Commit != model {
		t.Fatalf("a model's first commit under three of a person's is judged %+v (%v)", got, err)
	}

	people := openStore(t)
	for _, body := range []string{"first", "second", "third"} {
		saveAs(t, people, body, "edited "+body, "dana")
	}
	if got, err := MachineWroteSince(people, people.GetRef(RefDraft)); err != nil || got != nil {
		t.Fatalf("a history only people wrote is judged %+v (%v)", got, err)
	}
}

// A history that cannot be read to the end is not taken as a person's: too
// long to walk, or holding a commit that cannot be read, it is answered as
// a model's, and says why.
func TestAHistoryThatCannotBeReadIsNotAPersons(t *testing.T) {
	s := openStore(t)
	for _, body := range []string{"first", "second", "third", "fourth"} {
		saveAs(t, s, body, "edited "+body, "dana")
	}
	draft := s.GetRef(RefDraft)

	was := machineWalkLimit
	machineWalkLimit = 2
	got, err := MachineWroteSince(s, draft)
	machineWalkLimit = was
	if err != nil || got == nil || got.Unread == "" {
		t.Fatalf("a history longer than is read is judged %+v (%v)", got, err)
	}

	missing := strings.Repeat("ab", 32)
	orphan, err := s.PutCommit(store.Commit{Tree: mustTree(t, s), Parents: []string{missing},
		Message: "edited on a copy", Author: "dana"})
	if err != nil {
		t.Fatal(err)
	}
	got, err = MachineWroteSince(s, orphan)
	if err != nil || got == nil || got.Unread == "" {
		t.Fatalf("a history with a commit that cannot be read is judged %+v (%v)", got, err)
	}

	// The commit being published itself not being readable is an error,
	// as it was: there is nothing to publish.
	if _, err := MachineWroteSince(s, missing); err == nil {
		t.Fatal("a commit that does not exist was judged rather than refused")
	}
}

func mustTree(t *testing.T, s *store.Store) string {
	t.Helper()
	c, err := s.GetCommit(s.GetRef(RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	return c.Tree
}

// Everybody a machine wrote for in what a publish would put live is named,
// not only the person the newest machine's commit was made for, and that
// commit is still the one the answer is about.
//
// The walk stopped at the newest machine's commit. Dana's client rewrote
// the pricing and lee's client then wrote another page, the answer named
// lee, and with a count of approvals set dana's own approval counted for
// her client's prices.
func TestEverybodyAMachineWroteForIsNamed(t *testing.T) {
	s := openStore(t)
	saveAs(t, s, "first", "first", "dana")
	if _, err := Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	saveAs(t, s, "dana's prices", "mcp: write pricing", "dana")
	saveAs(t, s, "an agent's prices", collab.AgentPrefix+"tidy wrote pricing", "agent/tidy")
	saveAs(t, s, "dana's prices again", "assist: tidy the prices", "dana")
	lees := saveAs(t, s, "lee's about page", "mcp: write about", "lee")
	draft := saveAs(t, s, "spelt right", "fixed a typo", "sam")

	got, err := MachineWroteSince(s, draft)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Commit != lees || got.Author != "lee" {
		t.Fatalf("found %+v, want lee's client's commit %s", got, lees[:12])
	}
	if strings.Join(got.People, ",") != "lee,dana" {
		t.Errorf("the machines wrote for lee and dana, and the answer names %q", got.People)
	}

	// What has been live is not asked again, for whom any more than whether.
	if _, err := Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	next := saveAs(t, s, "lee's again", "mcp: write about", "lee")
	if got, err := MachineWroteSince(s, next); err != nil || got == nil || strings.Join(got.People, ",") != "lee" {
		t.Errorf("after a publish, the answer is %+v (%v), want lee alone", got, err)
	}
}
