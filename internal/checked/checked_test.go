// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package checked

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const year = 365 * 24 * time.Hour

func store(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// The four states, and the order they are decided in.
//
// Changed comes before Overdue on purpose: a page edited last week and also
// past its interval needs somebody to read the edit, and saying "overdue"
// sends them looking for something that has already happened.
func TestWhereAPageStands(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	checkedAt := now.Add(-30 * 24 * time.Hour)

	fresh := Record{Page: "p", Content: "h1", By: "ada", At: checkedAt.Unix()}
	old := Record{Page: "p", Content: "h1", By: "ada",
		At: now.Add(-2 * year).Unix()}

	for _, c := range []struct {
		why     string
		rec     Record
		nowHash string
		want    State
	}{
		{"nobody has ever checked it", Record{}, "h1", Never},
		{"checked recently, unchanged", fresh, "h1", Fresh},
		{"edited since it was checked", fresh, "h2", Changed},
		{"past its interval", old, "h1", Overdue},
		{"both edited and overdue", old, "h2", Changed},
		// An unknown current hash is not a claim that it changed, the same way
		// note.Stale treats an unknown anchor.
		{"current hash unknown", fresh, "", Fresh},
		{"record has no anchor", Record{Page: "p", By: "ada",
			At: checkedAt.Unix()}, "h2", Fresh},
	} {
		if got := Status(c.rec, c.nowHash, year, now); got != c.want {
			t.Errorf("%s: got %q, want %q", c.why, got, c.want)
		}
	}

	if NeedsAttention(Fresh) {
		t.Error("a fresh page needs attention")
	}
	for _, s := range []State{Never, Overdue, Changed} {
		if !NeedsAttention(s) {
			t.Errorf("%q does not need attention", s)
		}
	}
}

// A per-page interval overrides the site's, and a broken one falls back
// rather than making the page permanently overdue.
func TestTheIntervalIsPerPageOrTheSiteDefault(t *testing.T) {
	for _, c := range []struct {
		every string
		want  time.Duration
	}{
		{"", year},
		{"   ", year},
		{"168h", 168 * time.Hour},
		// Unparseable and nonsensical values fall back. A record written by
		// hand with "6 months" in it should not make a page overdue forever
		// with nothing saying why — Set refuses those, and this is what
		// happens to one that got in some other way.
		{"6 months", year},
		{"0s", year},
		{"-1h", year},
	} {
		if got := (Record{Every: c.every}).Interval(year); got != c.want {
			t.Errorf("Every %q gave %s, want %s", c.every, got, c.want)
		}
	}
}

// A check names somebody and is about a page.
func TestACheckNeedsAPageAndAPerson(t *testing.T) {
	st := store(t)
	now := time.Now()

	for _, c := range []struct {
		why string
		rec Record
	}{
		{"no page", Record{By: "ada"}},
		{"no person", Record{Page: "hello"}},
		{"blank person", Record{Page: "hello", By: "  "}},
		{"an interval that is not a length of time",
			Record{Page: "hello", By: "ada", Every: "6 months"}},
		{"an interval of nothing",
			Record{Page: "hello", By: "ada", Every: "0s"}},
	} {
		if _, err := st.Set(c.rec, now); err == nil {
			t.Errorf("%s was accepted", c.why)
		}
	}

	// And a usable one is kept, with the time filled in.
	got, err := st.Set(Record{Page: "hello", By: "ada", Content: "h1",
		Every: "168h", Note: "prices confirmed with the shop"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.At != now.Unix() {
		t.Errorf("the record does not carry when it was made")
	}
	back, err := st.Get("hello")
	if err != nil || back.By != "ada" || back.Note != "prices confirmed with the shop" {
		t.Errorf("the record did not come back: %+v %v", back, err)
	}
}

// The latest check replaces the one before it.
//
// One record per page and not a history: the question is "when was this last
// confirmed", and the audit log holds the sequence for anybody who needs it.
func TestTheLatestCheckReplacesTheOneBefore(t *testing.T) {
	st := store(t)
	first := time.Unix(1_700_000_000, 0)

	if _, err := st.Set(Record{Page: "hello", By: "ada", Content: "h1"}, first); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Set(Record{Page: "hello", By: "grace", Content: "h2"},
		first.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get("hello")
	if got.By != "grace" || got.Content != "h2" {
		t.Errorf("the later check did not replace the earlier: %+v", got)
	}
	if all, _ := st.All(); len(all) != 1 {
		t.Errorf("two records for one page: %v", all)
	}
}

// A page nobody has checked is an ordinary state, not a lookup failure.
func TestAPageNobodyHasCheckedReadsAsNever(t *testing.T) {
	st := store(t)
	got, err := st.Get("never-touched")
	if err != nil {
		t.Fatalf("reading an unchecked page failed: %v", err)
	}
	if Status(got, "h1", year, time.Now()) != Never {
		t.Errorf("an unchecked page is not Never: %+v", got)
	}
}

// A page name becomes a path segment, so it cannot leave the directory.
func TestNothingCanWriteOutsideTheDirectory(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "checked"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	for _, page := range []string{
		"../escaped", "../../escaped", "a/../../escaped", "/etc/passwd",
		`..\escaped`, "..", ".", "",
	} {
		if _, err := st.Set(Record{Page: page, By: "ada"}, now); err == nil {
			t.Errorf("a record was written for page %q", page)
		}
		if _, err := st.Get(page); err == nil {
			t.Errorf("a record was read for page %q", page)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "checked" {
			t.Errorf("%q appeared next to the directory", e.Name())
		}
	}

	// A nested page name is ordinary and still works.
	if _, err := st.Set(Record{Page: "people/ada", By: "ada"}, now); err != nil {
		t.Errorf("a nested page name was refused: %v", err)
	}
	if r, gerr := st.Get("people/ada"); gerr != nil || r.By != "ada" {
		t.Errorf("a nested page's record did not come back: %+v %v", r, gerr)
	}
}

// The survey puts what needs doing at the top.
//
// A list somebody skims has to lead with the thing to act on, and within a
// state the page nobody has looked at for longest is the one to look at next.
func TestTheSurveyLeadsWithWhatNeedsDoing(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	records := map[string]Record{
		"fresh":   {Page: "fresh", By: "ada", Content: "h", At: now.Add(-time.Hour).Unix()},
		"overdue": {Page: "overdue", By: "ada", Content: "h", At: now.Add(-2 * year).Unix()},
		"changed": {Page: "changed", By: "ada", Content: "old", At: now.Add(-time.Hour).Unix()},
		"older":   {Page: "older", By: "ada", Content: "h", At: now.Add(-3 * year).Unix()},
	}
	hashes := map[string]string{
		"fresh": "h", "overdue": "h", "changed": "h", "older": "h", "never": "h",
	}
	rows := Survey([]string{"fresh", "overdue", "changed", "older", "never"},
		hashes, records, year, now)

	want := []struct {
		page  string
		state State
	}{
		{"never", Never},
		{"older", Overdue},   // overdue longest
		{"overdue", Overdue}, // overdue less long
		{"changed", Changed},
		{"fresh", Fresh},
	}
	if len(rows) != len(want) {
		t.Fatalf("survey returned %d rows, want %d", len(rows), len(want))
	}
	for i, w := range want {
		if rows[i].Page != w.page || rows[i].State != w.state {
			t.Errorf("row %d is %s/%s, want %s/%s",
				i, rows[i].Page, rows[i].State, w.page, w.state)
		}
	}

	// Every checked row says when it is next wanted, so a screen does not have
	// to do the arithmetic.
	for _, r := range rows {
		if r.State == Never {
			continue
		}
		if r.Due == 0 {
			t.Errorf("%s has no due date", r.Page)
		}
	}
}

// The survey is the same order every time.
//
// Records arrive from a map, and a list that reorders between two visits to
// the same screen reads as the store changing.
func TestTheSurveyIsStable(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	pages := []string{"a", "b", "c", "d", "e", "f"}
	records := map[string]Record{}
	for _, p := range pages {
		records[p] = Record{Page: p, By: "ada", Content: "h",
			At: now.Add(-2 * year).Unix()}
	}
	first := Survey(pages, map[string]string{}, records, year, now)
	for i := 0; i < 20; i++ {
		again := Survey(pages, map[string]string{}, records, year, now)
		for j := range first {
			if again[j].Page != first[j].Page {
				t.Fatalf("run %d reordered the survey", i)
			}
		}
	}
}
