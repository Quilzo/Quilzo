// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
)

// demoStore builds a store with the demonstration in it, unpublished.
//
// main() builds the writer; a test that calls a command function directly has
// to as well, or the first thing that prints dereferences nil — the same guard
// runCmd carries, for the same reason.
func demoStore(t *testing.T) string {
	t.Helper()
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"-publish=false"}); err != nil {
		t.Fatal(err)
	}
	return root
}

// A demonstration can be published more than once.
//
// `quilzo demo` wrote twelve pages and declared nothing about any of them, so
// the publish gate refused the next publish and named all twelve. The
// operator's only ways forward were to mark each by hand or to waive the gate
// for the whole site. It is the first command anybody runs.
//
// `provenance backfill` cannot help and is right not to — "an absence of
// evidence is never written down as human authorship" — so the fix is for the
// command that knows where the content came from to say so at the time.
func TestADemonstrationCanBePublishedMoreThanOnce(t *testing.T) {
	root := demoStore(t)

	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	unmarked, err := unmarkedAt(root, s, s.GetRef(site.RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	if len(unmarked) != 0 {
		t.Fatalf("the demonstration left %d page(s) undeclared, so the next "+
			"publish is refused and names them: %v", len(unmarked), unmarked)
	}

	// And it publishes, which is the thing somebody actually tries.
	if err := runPublish(t, root, "--no-a11y-check"); err != nil {
		t.Fatalf("a fresh demonstration refused to publish: %v", err)
	}
}

// What it says about itself is what is true, not what is convenient.
//
// algorithmicMedia is the vocabulary's own name for "a template, an import, a
// scripted migration", and it carries no Article 50 disclosure because no
// model was involved. humanEdits would clear the same gate and would be a
// claim that a person wrote a page the operator has never read — the exact
// substitution the backfill exists to refuse, reached by another route.
func TestGeneratedContentSaysItWasGeneratedBySoftware(t *testing.T) {
	root := demoStore(t)
	idx, err := loadProvenance(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Records) == 0 {
		t.Fatal("no provenance was recorded at all")
	}

	for page, rec := range idx.Records {
		if rec.SourceType != provenance.AlgorithmicMedia {
			t.Errorf("%s is recorded as %q; software wrote it, and claiming a "+
				"person did is a claim nobody checked", page, rec.SourceType)
		}
		// No model was involved, so no disclosure is owed. Asserting one would
		// devalue the mark on the content where it counts.
		if rec.SourceType.RequiresDisclosure() {
			t.Errorf("%s is marked as needing an Article 50 disclosure and no "+
				"model touched it", page)
		}
		// "Article 50 places the obligation on a person or organisation, never
		// on the tool."
		if strings.TrimSpace(rec.Author) == "" {
			t.Errorf("%s names nobody accountable", page)
		}
		if strings.TrimSpace(rec.Note) == "" {
			t.Errorf("%s does not say what produced it", page)
		}
	}
}

// Staging a page by hand is still the operator's to declare.
//
// `quilzo add` is the case where this program genuinely does not know: a
// person may have written the file, or pasted it out of a model. Marking it
// would be inventing the answer the gate exists to ask for, and it is the
// difference between "this program produced these bytes" and "somebody handed
// this program some bytes".
func TestStagingAPageByHandIsStillUndeclared(t *testing.T) {
	root := newStoreWithDraft(t)

	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	unmarked, err := unmarkedAt(root, s, s.GetRef(site.RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range unmarked {
		if p == "index" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a hand-staged page was declared on the operator's behalf: "+
			"%v. Whether a person or a model wrote it is the question the gate "+
			"is asking, and answering it here is inventing the answer",
			unmarked)
	}
}

// A record somebody already made is never overwritten.
//
// A second `import` must not replace what has since been said about a page,
// and a command's statement about itself never outranks the operator's.
func TestMarkingDoesNotOverwriteWhatSomebodyAlreadySaid(t *testing.T) {
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	page := t.TempDir() + "/p.json"
	if err := os.WriteFile(page, []byte(`{"title":"T"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdAdd(root, []string{"index=" + page, "-m", "first"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdProvenance(root, []string{"set", "index",
		"--source", "trainedAlgorithmicMedia", "--model", "some-model",
		"--author", "ada"}); err != nil {
		t.Fatal(err)
	}

	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := markGenerated(root, s, "the tool", "written by a command"); err != nil {
		t.Fatal(err)
	}

	idx, err := loadProvenance(root)
	if err != nil {
		t.Fatal(err)
	}
	got := idx.Records["index"]
	if got.SourceType != provenance.TrainedAlgorithmicMedia || got.Author != "ada" {
		t.Errorf("a command overwrote what somebody had declared: %+v\n"+
			"That would quietly remove an Article 50 disclosure, which is the "+
			"one direction this must never move in", got)
	}
}

// The moment a person edits generated content, the mark stops applying.
//
// This is the property that makes marking a demonstration safe to do at all.
// The record binds to the content hash, so it describes the bytes the command
// produced and nothing else: edit the page and the record is stale, and
// publishing asks who wrote the new version.
//
// Without it, "produced by software" would sit on a page a person had since
// rewritten — a false claim about authorship, which is the one thing the
// backfill's rule exists to prevent, reached by yet another route.
func TestEditingGeneratedContentMakesTheMarkStale(t *testing.T) {
	root := demoStore(t)

	// A valid edit: the page is bound to a type, and an edit that fails the
	// type gate never lands, which would make this test pass for the wrong
	// reason.
	page := t.TempDir() + "/r.json"
	if err := os.WriteFile(page, []byte(
		`{"title":"Returns","body":"Changed by a person.","updated":"2026-09-12"}`,
	), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdAdd(root, []string{"returns=" + page, "-m", "edit"}); err != nil {
		t.Fatalf("the edit did not land, so this proves nothing: %v", err)
	}

	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	unmarked, err := unmarkedAt(root, s, s.GetRef(site.RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range unmarked {
		if p == "returns" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a page a person rewrote still carries the command's mark: "+
			"%v. \"Produced by software\" on content somebody else wrote is a "+
			"false claim about authorship", unmarked)
	}
	// And the pages nobody touched still carry theirs, so the binding is per
	// page rather than the whole index being invalidated.
	for _, p := range unmarked {
		if p == "about" {
			t.Error("an untouched page lost its mark when a different page " +
				"was edited")
		}
	}
}
