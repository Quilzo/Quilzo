package store

import (
	"os"
	"path/filepath"
	"testing"
)

// Content addressing is only worth having if a tampered object is actually
// detected rather than assumed not to happen, and if an id that becomes a
// filename cannot be used to leave the store.

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIdenticalContentDeduplicates(t *testing.T) {
	s := newStore(t)
	a, err := s.PutBlob(map[string]any{"title": "Home", "body": "one"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.PutBlob(map[string]any{"body": "one", "title": "Home"})
	if err != nil {
		t.Fatal(err)
	}
	// Key order differs; canonical encoding must make these the same object, or
	// nothing shares and every edit rewrites the whole site.
	if a != b {
		t.Fatalf("same content got different ids:\n  %s\n  %s", a, b)
	}
}

func TestKindIsFoldedIntoTheID(t *testing.T) {
	// A blob and a tree with identical payload bytes must not collide, or one
	// object could be presented as the other.
	if ObjectID(KindBlob, []byte("{}")) == ObjectID(KindTree, []byte("{}")) {
		t.Fatal("blob and tree with identical bytes share an id")
	}
}

func TestEditingLeavesTheOldVersionIntact(t *testing.T) {
	s := newStore(t)
	t1, err := BuildTree(s, map[string]any{
		"index": map[string]any{"body": "one"},
		"about": map[string]any{"body": "two"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t2, err := BuildTree(s, map[string]any{
		"index": map[string]any{"body": "EDITED"},
		"about": map[string]any{"body": "two"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tree1, _ := s.GetTree(t1)
	tree2, _ := s.GetTree(t2)

	var old map[string]any
	if err := s.GetBlob(tree1["index"], &old); err != nil {
		t.Fatal(err)
	}
	if old["body"] != "one" {
		t.Fatalf("the old version was mutated: %v", old)
	}
	// Structural sharing: the untouched page must be literally the same object,
	// which is what makes Diff able to compare ids instead of content.
	if tree1["about"] != tree2["about"] {
		t.Fatal("an unchanged page produced a new object")
	}
}

func TestTamperingIsDetected(t *testing.T) {
	s := newStore(t)
	oid, err := s.PutBlob(map[string]any{"body": "honest"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(); err != nil {
		t.Fatalf("a clean store failed verification: %v", err)
	}

	path := filepath.Join(s.Root(), "objects", oid[:2], oid[2:])
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append([]byte(KindBlob), 0),
		[]byte(`{"body":"TAMPERED"}`)...), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Verify(); err == nil {
		t.Fatal("Verify passed over an altered object")
	}
	var v map[string]any
	if err := s.GetBlob(oid, &v); err == nil {
		t.Fatalf("the altered content was served: %v", v)
	}
}

func TestIDsCannotEscapeTheStore(t *testing.T) {
	s := newStore(t)
	var v any
	for _, bad := range []string{
		"../../etc/passwd",
		"..",
		"",
		"ZZ" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		"0123456789abcdef", // right charset, wrong length
		"/etc/passwd",
	} {
		if err := s.GetBlob(bad, &v); err == nil {
			t.Errorf("id %q was accepted", bad)
		}
	}
}

func TestTreeEntriesCannotTraverse(t *testing.T) {
	s := newStore(t)
	oid, _ := s.PutBlob(map[string]any{"x": 1})
	// "a/b" was on this list until a multilingual site needed fr/about. One
	// slash is now permitted and the traversal cases below are unchanged —
	// relaxing the rule must not be relaxing the defence, so the list of
	// refusals got longer rather than shorter.
	for _, bad := range []string{
		"../evil", ".hidden", "", "with space",
		"a/../b", "a/..", "../a", "./a", "a/./b",
		"a//b", "/a", "a/",
		// Depth is bounded rather than unlimited: nesting needs five levels
		// and nothing needs nine.
		"a/b/c/d/e/f/g/h/i",
		"..", ".", "a\\b",
	} {
		if _, err := s.PutTree(map[string]string{bad: oid}); err == nil {
			t.Errorf("tree entry %q was accepted", bad)
		}
	}
}

func TestRefCannotPointAtNothing(t *testing.T) {
	s := newStore(t)
	missing := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := s.SetRef("live", missing); err == nil {
		t.Fatal("a ref was pointed at an object that is not stored")
	}
	if err := s.SetRef("../evil", missing); err == nil {
		t.Fatal("a traversing ref name was accepted")
	}
}

func TestHistoryWalksParents(t *testing.T) {
	s := newStore(t)
	tree, _ := BuildTree(s, map[string]any{"index": map[string]any{"body": "a"}})
	c1, err := s.PutCommit(Commit{Tree: tree, Message: "first", Author: "rsh1k", At: 1})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := s.PutCommit(Commit{Tree: tree, Parents: []string{c1},
		Message: "second", Author: "rsh1k", At: 2})
	if err != nil {
		t.Fatal(err)
	}
	hist, err := s.History(c2, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 || hist[0].Commit.Message != "second" || hist[1].Commit.Message != "first" {
		t.Fatalf("history walked wrong: %+v", hist)
	}
}

func TestCommitRejectsBadReferences(t *testing.T) {
	s := newStore(t)
	if _, err := s.PutCommit(Commit{Tree: "not-an-id"}); err == nil {
		t.Fatal("a commit with a bogus tree was stored")
	}
	tree, _ := BuildTree(s, map[string]any{"i": map[string]any{}})
	if _, err := s.PutCommit(Commit{Tree: tree, Parents: []string{"nope"}}); err == nil {
		t.Fatal("a commit with a bogus parent was stored")
	}
}

// A single slash is allowed so a multilingual site can store fr/about. Bounded
// to one, with each half satisfying the same rule as a bare name — the point is
// that relaxing this must not reintroduce traversal.
func TestPageNamesAllowOneSlashAndNothingElse(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oid, err := s.PutBlob(map[string]any{"title": "x"})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"about", "fr/about", "zh-Hant/about", "news.2026", "a/b",
	} {
		if _, err := s.PutTree(map[string]string{name: oid}); err != nil {
			t.Errorf("%q was refused: %v", name, err)
		}
	}

	for _, name := range []string{
		"../etc/passwd", "/leading", "trailing/", "a//b",
		"a/b/c/d/e/f/g/h/i",
		"..", "a/..", "../a", "./a", "a/./b", "", "/", "//",
		".hidden", "a/.hidden", "a b", "a\\b", "a\x00b",
	} {
		if _, err := s.PutTree(map[string]string{name: oid}); err == nil {
			t.Errorf("%q was accepted as a page name", name)
		}
	}
}
