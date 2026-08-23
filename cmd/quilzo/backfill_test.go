package main

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The bug this exists for, and the layer it lived at.
//
// internal/provenance had eight passing tests for the backfill rules, and the
// command built on them marked every page on the site as AI-generated —
// including one written by hand seconds earlier — all citing the same commit.
//
// A commit names a tree, and that tree holds the whole site, not only what the
// commit changed. So walking every commit's tree says every page appears in
// every commit, and one assistant-written commit anywhere marks everything.
//
// The package could not see it. It was handed appearances and reasoned about
// them correctly; the fault was in what the appearances said. So this test
// builds a real store, writes real commits through the real API, and asserts
// on what comes out — the only level at which the question can be asked.
func historyStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	page := func(title string) map[string]any {
		return map[string]any{"title": title, "body": title + " body."}
	}

	// Three commits. The middle one is machine-written and, like every commit,
	// carries a tree containing all the pages that exist by then.
	if _, err := site.SaveDraft(s, map[string]any{
		"index": page("Home"), "about": page("About"),
	}, "add the first pages", "dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": page("Home"), "about": page("About"),
		"news": page("News"),
	}, "assist: write a news page", "dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": page("Home"), "about": page("About"),
		"news": page("News"), "terms": page("Terms"),
	}, "add the terms page", "dana"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOnlyThePageAMachineWroteIsMarked(t *testing.T) {
	s := historyStore(t)

	current, err := pageHashes(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	history, read, err := appearances(s, site.RefDraft, 100)
	if err != nil {
		t.Fatal(err)
	}
	if read < 3 {
		t.Fatalf("read %d commits; the walk found almost no history and this "+
			"test would prove nothing", read)
	}

	plan := provenance.BuildPlan(current, history, provenance.NewIndex(), 1)

	if len(plan.Inferred) != 1 {
		names := []string{}
		for _, p := range plan.Inferred {
			names = append(names, p.Page)
		}
		t.Fatalf("marked %d pages %v; exactly one page was written by a "+
			"machine.\n"+
			"  Marking pages a person wrote devalues the mark on the pages "+
			"that need it, which is the whole point of the exercise.",
			len(plan.Inferred), names)
	}
	if got := plan.Inferred[0].Page; got != "news" {
		t.Errorf("marked %q; the machine-written page is news", got)
	}

	// And every other page is undecidable, never recorded as human authorship.
	if plan.Total() != len(current) {
		t.Fatalf("plan covers %d pages, the tree has %d", plan.Total(), len(current))
	}
	if len(plan.Undecidable) != len(current)-1 {
		t.Errorf("%d pages undecidable, want %d — every page that is not the "+
			"machine-written one", len(plan.Undecidable), len(current)-1)
	}
}

// A page carried forward unchanged by a later machine-written commit was not
// written by that commit. This is the same bug one step smaller: the whole
// tree moves forward on every write, so "present in a machine commit" and
// "written by a machine" are different questions.
func TestAPageCarriedForwardIsNotAttributedToTheCommitThatCarriedIt(t *testing.T) {
	s := historyStore(t)

	history, _, err := appearances(s, site.RefDraft, 100)
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, a := range history {
		checked++
		if a.Page != "news" && a.Message == "assist: write a news page" {
			t.Errorf("%s is attributed to the machine-written commit, but that "+
				"commit only introduced news", a.Page)
		}
	}
	// Count what was examined: an empty history produces no complaints and
	// looks exactly like a pass.
	if checked == 0 {
		t.Fatal("the walk produced no appearances at all")
	}
	t.Logf("%d appearance(s) examined across the history", checked)
}

// Each page's content is introduced once, so it should be attributed once.
// Duplicates would mean the walk is still recording carried-forward content.
func TestEachContentIsAttributedToExactlyOneCommit(t *testing.T) {
	s := historyStore(t)
	history, _, err := appearances(s, site.RefDraft, 100)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]int{}
	for _, a := range history {
		seen[a.Page+"@"+a.ContentHash]++
	}
	if len(seen) == 0 {
		t.Fatal("no appearances at all")
	}
	for key, n := range seen {
		if n != 1 {
			t.Errorf("%s is attributed to %d commits; content is introduced "+
				"once", key, n)
		}
	}
}

// A records collection is not a page.
//
// pageHashes returned the commit's tree as it stood, and a collection is a tree
// under the same root — so "data" came back as a page. `lang check` then
// reported a missing French translation for it and `provenance check` listed it
// as content nobody had recorded, on every site holding a single record, with
// no way to satisfy either. Found while translating two pages of a demo site
// and counting what was left.
func TestARecordsCollectionIsNotAPage(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home"},
	}, "the first page", "dana"); err != nil {
		t.Fatal(err)
	}

	// A record, written through the real API, which puts a tree beside the
	// pages.
	base := ""
	if cid := s.GetRef(site.RefDraft); cid != "" {
		c, cerr := s.GetCommit(cid)
		if cerr != nil {
			t.Fatal(cerr)
		}
		base = c.Tree
	}
	tree, _, err := collection.Put(s, base, "cloth", collection.Record{
		Fields: map[string]any{"slug": "indigo-linen", "name": "Indigo linen"},
	}, time.Unix(1787000000, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitTree(t.TempDir(), s, tree, "add a record", "dana"); err != nil {
		t.Fatal(err)
	}

	pages, err := pageHashes(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if _, listed := pages["data"]; listed {
		t.Error("the records collection is listed as a page, so every check " +
			"that walks pages reports a page nobody can write or translate")
	}
	if _, listed := pages["index"]; !listed {
		t.Error("the real page is missing")
	}
}
