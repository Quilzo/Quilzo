// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package board

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func store(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "boards"))
	if err != nil {
		t.Fatal(err)
	}
	n := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { n = n.Add(time.Second); return n }
	return s
}

var (
	open = Board{Name: "comments", Title: "Comments", Moderation: "post"}
	held = Board{Name: "letters", Title: "Letters", Moderation: "pre"}
)

func TestABoardDeclarationIsChecked(t *testing.T) {
	for _, b := range []Board{
		{Name: "Bad Name", Title: "x", Moderation: "post"},
		{Name: "x", Moderation: "post"},
		{Name: "x", Title: "x", Moderation: "sometimes"},
		{Name: "x", Title: "x", Moderation: "post", MaxLength: MaxLength + 1},
	} {
		if b.Validate() == nil {
			t.Errorf("%+v was accepted", b)
		}
	}
	set := &Set{}
	if err := set.Put(open); err != nil {
		t.Fatal(err)
	}
	if got, ok := set.Get("comments"); !ok || got.Title != "Comments" {
		t.Error("a declared board cannot be found")
	}
}

func TestAPostIsCleanedAndBounded(t *testing.T) {
	for in, want := range map[string]string{
		"  hello  ":                 "hello",
		"one\r\ntwo":                "one\ntwo",
		"a\n\n\n\n\nb":              "a\n\nb",
		"bell\a and   sep":          "bell and  sep",
		"<script>alert(1)</script>": "<script>alert(1)</script>",
	} {
		got, err := CleanBody(in, 100)
		if err != nil || got != want {
			t.Errorf("%q became %q (%v), want %q", in, got, err, want)
		}
	}
	if _, err := CleanBody("   \n ", 100); err == nil {
		t.Error("an empty post was accepted")
	}
	if _, err := CleanBody(strings.Repeat("é", 101), 100); err == nil {
		t.Error("a post over the limit was accepted")
	}
}

func TestAPostIsShownOrHeldAsTheBoardSays(t *testing.T) {
	s := store(t)
	a, err := s.Add(open, "index", "m1", "Ada", "First!")
	if err != nil || a.State != Visible {
		t.Fatalf("%+v %v", a, err)
	}
	h, _ := s.Add(held, "index", "m1", "Ada", "Dear editor")
	if h.State != Held {
		t.Fatalf("a post on a held board is %s", h.State)
	}
	if got := s.Thread("letters", "index", ""); len(got) != 0 {
		t.Error("a held post is shown to everybody")
	}
	if got := s.Thread("letters", "index", "m1"); len(got) != 1 {
		t.Error("an author cannot see their own held post")
	}
	if got := s.Thread("letters", "index", "m2"); len(got) != 0 {
		t.Error("another member sees a held post")
	}
	before := s.Version("letters", "index")
	if err := s.Approve(h.ID); err != nil {
		t.Fatal(err)
	}
	if got := s.Thread("letters", "index", ""); len(got) != 1 {
		t.Error("an approved post is not shown")
	}
	if s.Version("letters", "index") == before {
		t.Error("approving a post did not change the thread's version")
	}
	// An edited post on a held board waits again.
	if p, _ := s.Edit(held, h.ID, "m1", "Dear editor, again"); p.State != Held {
		t.Error("an edit to an approved post was shown without a person")
	}
	if _, err := s.Add(Board{Name: "x", Title: "X", Moderation: "post", Closed: true}, "index", "m1", "Ada", "hi"); err == nil {
		t.Error("a closed board took a post")
	}
}

func TestOnlyTheAuthorEditsOrDeletesAndStaffMayRemove(t *testing.T) {
	s := store(t)
	p, _ := s.Add(open, "index", "m1", "Ada", "Mine")
	if _, err := s.Edit(open, p.ID, "m2", "Not yours"); !errors.Is(err, ErrNotYours) {
		t.Errorf("another member edited a post: %v", err)
	}
	if err := s.Remove(p.ID, "m2"); !errors.Is(err, ErrNotYours) {
		t.Errorf("another member deleted a post: %v", err)
	}
	if err := s.Remove(p.ID, "m1"); err != nil {
		t.Errorf("the author could not delete: %v", err)
	}
	q, _ := s.Add(open, "index", "m1", "Ada", "Again")
	if err := s.Remove(q.ID, ""); err != nil {
		t.Errorf("staff could not remove: %v", err)
	}
	if _, err := s.Get(q.ID); !errors.Is(err, ErrNotFound) {
		t.Error("a removed post is still there")
	}
	for _, bad := range []string{"", "../../etc/passwd", strings.Repeat("a", 24)} {
		if _, err := s.Get(bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("looking up %q: %v", bad, err)
		}
	}
}

// Deleting an account deletes what it wrote.
func TestAnAuthorsPostsGoWithTheirAccount(t *testing.T) {
	s := store(t)
	s.Add(open, "index", "m1", "Ada", "one")
	s.Add(held, "about", "m1", "Ada", "two")
	keep, _ := s.Add(open, "index", "m2", "Bo", "three")
	if n := s.RemoveAuthor("m1"); n != 2 {
		t.Errorf("removed %d posts, want 2", n)
	}
	_ = filepath.WalkDir(s.Dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(path); strings.Contains(string(b), `"m1"`) {
				t.Errorf("%s still holds the deleted author's post", path)
			}
		}
		return nil
	})
	if _, err := s.Get(keep.ID); err != nil {
		t.Error("another author's post went too")
	}
}

// A thread's directory comes from a hash, never from the page name itself.
func TestAThreadNameCannotReachOutsideTheStore(t *testing.T) {
	s := store(t)
	p, err := s.Add(open, "../../../../tmp/escape", "m1", "Ada", "hi")
	if err != nil {
		t.Fatal(err)
	}
	path, _, err := s.find(p.ID)
	if err != nil || !strings.HasPrefix(path, s.Dir+string(os.PathSeparator)) {
		t.Errorf("the post was written at %s", path)
	}
}

// A board name that is not one a board could have reaches no file.
func TestABoardNameFromAnAddressReachesNoFile(t *testing.T) {
	s := store(t)
	s.Add(open, "index", "m1", "Ada", "hi")
	for _, bad := range []string{"..", "../comments", "comments/../comments", "/etc", ""} {
		if got := s.Thread(bad, "index", ""); len(got) != 0 {
			t.Errorf("the board %q read %d posts", bad, len(got))
		}
		if v := s.Version(bad, "index"); v != s.Version("nothing", "index") {
			t.Errorf("the board %q has a version of its own", bad)
		}
	}
}
