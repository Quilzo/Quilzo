package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/brand"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// A rules file that exists and does not parse must stop a publication.
//
// Treating it as "no rules" would make corrupting one file the way to publish
// anything — the same fail-open shape as the policy.json bug this project
// already shipped, where an unreadable file disabled access control entirely.
func TestUnreadableClaimRulesFailClosed(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "brand.json"),
		[]byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadBrand(root)
	if err == nil {
		t.Fatal("an unreadable rules file was treated as no rules, so every " +
			"claim would publish unchecked")
	}
	if !strings.Contains(err.Error(), "no claim") {
		t.Errorf("the refusal does not say nothing was checked: %v", err)
	}
}

// An absent file is not an error.
//
// The other direction, and the one that gets a control deleted: most sites
// need no claim rules, and a gate that demands configuration in order to be
// switched off is one people remove rather than configure.
func TestAbsentClaimRulesAreNotAnError(t *testing.T) {
	r, err := loadBrand(t.TempDir())
	if err != nil {
		t.Fatalf("a store with no rules file could not publish: %v", err)
	}
	if len(r.Terms) != 0 {
		t.Errorf("rules appeared from nowhere: %v", r.Terms)
	}
}

// The gate reads records, not only pages, and reads each one exactly once.
//
// In a shop the product copy is a record. A gate that examined only pages
// would report clean on a catalogue full of unsubstantiated claims, which is
// the failure mode where the feature exists and means nothing.
//
// # This test was wrong once, and the way it was wrong is the point
//
// Its first version wrote a record by inserting a flat "data/coll/xx/yy/id"
// key into the tree. A real record is written by collection.PutMany, which
// builds nested subtrees — so the fake one came back out of PagesAt as a blob
// and the real one never does. On that false evidence the gate's two walks
// were collapsed into one, and the collapsed gate checked every page and no
// product at all while reporting success.
//
// So this writes records the way the store writes them, and asserts the count
// of what was examined rather than only the findings — a gate that examines
// nothing also finds nothing.
func TestTheClaimGateReadsRecordsAndNotOnlyPages(t *testing.T) {
	root := t.TempDir()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "Nothing to answer for."},
		"about": map[string]any{"title": "About", "body": "Nor here."},
	}, "pages", "test"); err != nil {
		t.Fatal(err)
	}
	putTestRecords(t, s, "products", []collection.Record{
		{Fields: map[string]any{"name": "Copper kettle",
			"description": "Guaranteed for life."}},
		{Fields: map[string]any{"name": "Enamel mug",
			"description":     "Guaranteed for two years.",
			"guarantee_terms": "https://example.com/terms"}},
	})

	rules := brand.Rules{Terms: []brand.Term{
		{Match: "guaranteed", Needs: "guarantee_terms",
			Why: "somebody has to honour it"},
	}}
	if err := rules.Compile(); err != nil {
		t.Fatal(err)
	}

	findings, checked, err := brandFindings(s, &rules, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if checked != 4 {
		t.Errorf("%d item(s) examined, want 4 (two pages, two records). "+
			"Fewer means the records were never read; more means something "+
			"is being walked twice", checked)
	}
	if len(findings) != 1 {
		t.Fatalf("want one finding — the kettle, whose guarantee nothing "+
			"backs up — got %d: %v", len(findings), findings)
	}
	// Named the way a person refers to it, not by its shard path.
	if !strings.HasPrefix(findings[0].Where, "products/") {
		t.Errorf("the finding names %q; an author cannot go and fix that",
			findings[0].Where)
	}
}

// putTestRecords writes records the way the store writes them.
//
// Through collection.PutMany, which builds the nested subtrees a real commit
// has. Writing them any other way produces a store shape that does not occur,
// and a test against a shape that does not occur proves nothing about the one
// that does — which is exactly what happened here.
func putTestRecords(t *testing.T, s *store.Store, coll string, recs []collection.Record) {
	t.Helper()
	commit := s.GetRef(site.RefDraft)
	c, err := s.GetCommit(commit)
	if err != nil {
		t.Fatal(err)
	}
	next, _, err := collection.PutMany(s, c.Tree, coll, recs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cid, err := s.PutCommit(store.Commit{
		Tree: next, Parents: []string{commit}, Message: "records",
		Author: "test", At: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRef(site.RefDraft, cid); err != nil {
		t.Fatal(err)
	}
}

// A store whose collections cannot be read must not report a clean gate.
//
// The direction that matters: "nothing was found" and "nothing was looked at"
// have to be distinguishable, or a store with a missing object publishes
// anything that was in it.
//
// Two ways in, because they are different branches and the first version of
// this test only reached one — an unresolvable commit fails before the
// collection walk starts, so a `continue` swallowing a per-collection error
// stayed uncovered and a sabotage of it passed.
func TestAGateThatCannotReadMustNotReportClean(t *testing.T) {
	rules := brand.Rules{Terms: []brand.Term{
		{Match: "guaranteed", Needs: "guarantee_terms", Why: "somebody honours it"}}}
	if err := rules.Compile(); err != nil {
		t.Fatal(err)
	}

	t.Run("a commit that does not resolve", func(t *testing.T) {
		root := t.TempDir()
		s, err := store.Open(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := site.SaveDraft(s, map[string]any{
			"index": map[string]any{"title": "Home"}}, "pages", "test"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := brandFindings(s, &rules, strings.Repeat("0", 64)); err == nil {
			t.Error("a commit that cannot be read reported a clean gate")
		}
	})

	t.Run("a collection whose objects are gone", func(t *testing.T) {
		root := t.TempDir()
		s, err := store.Open(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := site.SaveDraft(s, map[string]any{
			"index": map[string]any{"title": "Home"}}, "pages", "test"); err != nil {
			t.Fatal(err)
		}
		putTestRecords(t, s, "products", []collection.Record{
			{Fields: map[string]any{"name": "Kettle",
				"description": "Guaranteed for life."}}})

		// Prove the gate finds it before anything is broken, or the assertion
		// below passes for the wrong reason.
		if found, _, err := brandFindings(s, &rules, site.RefDraft); err != nil ||
			len(found) != 1 {
			t.Fatalf("before corruption: %d finding(s), err %v — this test "+
				"cannot show what corruption does if it was never working",
				len(found), err)
		}

		// Remove the subtree the collection lives under. Its object is
		// addressed by its own hash, so deleting the file is exactly the
		// "an object went missing" case, not a synthetic one.
		c, err := s.GetCommit(s.GetRef(site.RefDraft))
		if err != nil {
			t.Fatal(err)
		}
		tree, err := s.GetTree(c.Tree)
		if err != nil {
			t.Fatal(err)
		}
		oid, ok := tree["data"]
		if !ok {
			t.Fatal("no data subtree; the records were not written as records")
		}
		if err := os.Remove(filepath.Join(root, "objects", oid[:2], oid[2:])); err != nil {
			t.Fatal(err)
		}

		if found, checked, err := brandFindings(s, &rules, site.RefDraft); err == nil {
			t.Errorf("a collection that could not be read reported a clean "+
				"gate: %d item(s) checked, %d finding(s). Nothing found and "+
				"nothing looked at have to be different answers",
				checked, len(found))
		}
	})
}
