// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/site"
	"strings"
	"testing"
)

// The command line refuses to publish a page that declares no provenance.
//
// README states that publishing unmarked content is refused rather than warned
// about, without naming a surface. It was true of the admin and of the agent
// interface and had never been true here — the one interface a deployment
// script drives. `quilzo publish && deploy` shipped unmarked content with
// status zero, which is the shape of every failure this program is arranged to
// refuse.
func TestPublishRefusesUnmarkedContent(t *testing.T) {
	root := newStoreWithDraft(t)
	err := runPublish(t, root)
	if err == nil {
		t.Fatal("published a page with no provenance")
	}
	if !strings.Contains(err.Error(), "no provenance") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	// The message has to name commands that work when they are pasted. The
	// first version of it suggested `--source human`, which is not a value
	// this program accepts — the vocabulary is IPTC digitalSourceType.
	for _, want := range []string{"humanEdits", "--author", "--force-unmarked"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so it does not tell "+
				"somebody how to proceed:\n%v", want, err)
		}
	}
}

// A person can override it, and cannot do so silently.
//
// The gate blocks pages with no provenance record, which on a fresh store is
// every page somebody has just written by hand — not AI content. `quilzo
// provenance check` calls that "a gap, not a claim that a person wrote it".
// A gate with no override would have refused the first publish of a
// hand-authored site, so it has one, and the reason is required because an
// override with no reason records only that somebody wanted one.
func TestTheUnmarkedOverrideNeedsAReason(t *testing.T) {
	root := newStoreWithDraft(t)
	if err := runPublish(t, root, "--force-unmarked"); err == nil {
		t.Fatal("overrode the gate with no reason")
	} else if !strings.Contains(err.Error(), "--reason") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	// --no-a11y-check because this fixture has no templates directory, and
	// that gate correctly refuses when it cannot run.
	if err := runPublish(t, root, "--no-a11y-check", "--force-unmarked",
		"--reason", "hand-authored, backfill pending"); err != nil {
		t.Fatalf("a reasoned override was still refused: %v", err)
	}
}

// Marking the page is the way through that is not an override.
func TestMarkedContentPublishes(t *testing.T) {
	root := newStoreWithDraft(t)
	if err := runCmd(t, root, "provenance", "set", "index",
		"--source", "humanEdits", "--author", "someone"); err != nil {
		t.Fatalf("could not mark the page: %v", err)
	}
	if err := runPublish(t, root, "--no-a11y-check"); err != nil {
		t.Fatalf("a marked page was refused: %v", err)
	}
}

// runCmd dispatches one command the way main does, minus the process exit.
func runCmd(t *testing.T, root string, args ...string) error {
	t.Helper()
	// main() builds this; a test that calls a command function directly has
	// to as well, or the first thing that prints dereferences nil.
	if w == nil {
		w = out.New(false)
	}
	switch args[0] {
	case "init":
		return cmdInit(root)
	case "add":
		return cmdAdd(root, args[1:])
	case "provenance":
		return cmdProvenance(root, args[1:])
	case "records":
		return cmdRecords(root, args[1:])
	}
	t.Fatalf("no dispatch for %q in this helper", args[0])
	return nil
}

func runPublish(t *testing.T, root string, args ...string) error {
	t.Helper()
	return cmdPublish(root, args)
}

func newStoreWithDraft(t *testing.T) string {
	t.Helper()
	root := t.TempDir() + "/st"
	page := t.TempDir() + "/p.json"
	if err := os.WriteFile(page, []byte(`{"title":"T","body":"b"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCmd(t, root, "init"); err != nil {
		t.Fatal(err)
	}
	if err := runCmd(t, root, "add", "index="+page, "-m", "first"); err != nil {
		t.Fatal(err)
	}
	return root
}

// A records collection is not a page, so it is not content anybody can mark.
//
// unmarkedAt walked the commit tree directly, and a collection is a tree
// sharing that root — called "data". So it was handed to provenance.Check as
// though it were a page, reported as unmarked, and could never stop being
// reported: nothing can give a tree a provenance record, and
// `quilzo provenance backfill` correctly writes nothing for one.
//
// The result was that any site holding records could never publish again once
// this gate existed. A fresh `quilzo demo` — which ships two collections —
// could be published once, by the demo command itself, and never after. Found
// by running the demo rather than by any test, because every test here used a
// store with pages and nothing else.
//
// The comment on pageHashes already described this exact bug and named two
// places it had been fixed, `lang check` and `provenance check`. This was a
// third caller and the one where it mattered most.
func TestARecordsCollectionIsNotReportedAsUnmarkedContent(t *testing.T) {
	root := newStoreWithDraft(t)

	// A collection, which lands in the tree as "data" beside the pages.
	if err := runCmd(t, root, "records", "add", "products",
		"name=A brass pen", "price=48"); err != nil {
		t.Fatal(err)
	}

	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	unmarked, err := unmarkedAt(root, s, s.GetRef(site.RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range unmarked {
		if name == "data" {
			t.Fatalf("the records collection is reported as content needing "+
				"provenance: %v\nNothing can mark a tree, so this refuses "+
				"every publish on any site holding records, permanently",
				unmarked)
		}
	}
	// The page is still reported, so this did not pass by reporting nothing.
	found := false
	for _, name := range unmarked {
		if name == "index" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no page was reported as unmarked: %v; the filter is too "+
			"wide and the gate now checks nothing", unmarked)
	}
}

// And the whole way through: a store with records publishes once its pages are
// marked.
//
// The unit above pins the cause; this pins the thing somebody actually hit.
func TestAStoreHoldingRecordsCanPublishOnceItsPagesAreMarked(t *testing.T) {
	root := newStoreWithDraft(t)
	if err := runCmd(t, root, "records", "add", "products",
		"name=A brass pen", "price=48"); err != nil {
		t.Fatal(err)
	}
	if err := runCmd(t, root, "provenance", "set", "index",
		"--source", "humanEdits", "--author", "ada"); err != nil {
		t.Fatal(err)
	}

	if err := runPublish(t, root, "--no-a11y-check"); err != nil {
		t.Fatalf("a store holding records refused to publish with every page "+
			"marked: %v", err)
	}
}
