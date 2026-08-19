package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
// The "exactly once" half is here because the first version got it wrong.
// GetTree returns flattened leaf paths, so a record is already in PagesAt as a
// blob — walking the collections as well reported every product's findings
// twice and doubled the count of what had been checked. A live run showed it;
// no unit test did, because the helper that wrote records bypassed the index
// the second walk used, so the duplicate never appeared in the one place it
// was being looked for.
func TestTheClaimGateReadsEveryRecordExactlyOnce(t *testing.T) {
	root := t.TempDir()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "Nothing to answer for."},
	}, "pages", "test"); err != nil {
		t.Fatal(err)
	}
	if err := putTestRecord(t, s, "products", collection.Record{
		ID: "a3f9c0d1e2b3a4958677889900aabbcc", Fields: map[string]any{
			"title": "Copper kettle", "description": "Guaranteed for life."},
	}); err != nil {
		t.Fatal(err)
	}

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
	if checked != 2 {
		t.Errorf("%d item(s) examined, want 2 (one page, one record). More "+
			"than that means something is being walked twice", checked)
	}
	if len(findings) != 1 {
		t.Fatalf("want one finding, got %d: %v. Two is the duplicate-walk "+
			"bug, zero is the record never being read", len(findings), findings)
	}
	// Named the way a person refers to it, not by its shard path, because the
	// author has to be able to find it.
	if findings[0].Where != "products/a3f9c0d1e2b3a4958677889900aabbcc" {
		t.Errorf("the finding names %q; an author cannot find that",
			findings[0].Where)
	}
}

// putTestRecord writes one record into the draft at the path the store uses.
func putTestRecord(t *testing.T, s *store.Store, coll string, rec collection.Record) error {
	t.Helper()
	blob, err := s.PutBlob(rec.Fields)
	if err != nil {
		return err
	}
	commit := s.GetRef(site.RefDraft)
	c, err := s.GetCommit(commit)
	if err != nil {
		return err
	}
	entries, err := s.GetTree(c.Tree)
	if err != nil {
		return err
	}
	entries[collection.Path(coll, rec.ID)] = blob
	tree, err := s.PutTree(entries)
	if err != nil {
		return err
	}
	cid, err := s.PutCommit(store.Commit{
		Tree: tree, Parents: []string{commit}, Message: "a product",
		Author: "test"})
	if err != nil {
		return err
	}
	return s.SetRef(site.RefDraft, cid)
}
