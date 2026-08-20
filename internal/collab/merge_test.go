package collab_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/collab"
)

func page(fields ...string) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(fields); i += 2 {
		m[fields[i]] = fields[i+1]
	}
	return m
}

func base() map[string]any {
	return map[string]any{
		"index": page("title", "Home", "body", "Welcome."),
		"about": page("title", "About", "body", "Founded 2019."),
	}
}

// The case that makes almost every refusal unnecessary: two people edited
// different pages. They collided on the ref and on nothing else, and a system
// that refuses this teaches people to retry without reading — which is how the
// real collisions get overwritten too.
func TestTwoPeopleOnDifferentPagesBothKeepTheirWork(t *testing.T) {
	mine := base()
	mine["index"] = page("title", "Home", "body", "Rewritten front page.")
	theirs := base()
	theirs["about"] = page("title", "About us", "body", "Founded 2019.")

	got := collab.Merge(base(), mine, theirs)
	if !got.Clean() {
		t.Fatalf("refused a merge with no overlap: %s", got.Summary())
	}
	if v := got.Pages["index"].(map[string]any)["body"]; v != "Rewritten front page." {
		t.Errorf("my change to index was lost: %v", v)
	}
	if v := got.Pages["about"].(map[string]any)["title"]; v != "About us" {
		t.Errorf("their change to about was lost: %v", v)
	}
}

// The common real case: same page, different fields. One writes the body, the
// other fixes the title.
func TestSamePageDifferentFieldsMerges(t *testing.T) {
	mine := base()
	mine["index"] = page("title", "Home", "body", "A much longer welcome.")
	theirs := base()
	theirs["index"] = page("title", "Welcome", "body", "Welcome.")

	got := collab.Merge(base(), mine, theirs)
	if !got.Clean() {
		t.Fatalf("refused a merge of different fields: %s", got.Summary())
	}
	idx := got.Pages["index"].(map[string]any)
	if idx["body"] != "A much longer welcome." {
		t.Errorf("my body was lost: %v", idx["body"])
	}
	if idx["title"] != "Welcome" {
		t.Errorf("their title was lost: %v", idx["title"])
	}
}

// The rule the whole thing rests on: never resolve a disagreement by picking a
// side. A merge that guessed would need auditing, and nobody audits a merge
// that says it succeeded.
func TestTheSameFieldChangedTwoWaysIsReportedNotDecided(t *testing.T) {
	mine := base()
	mine["index"] = page("title", "My title", "body", "Welcome.")
	theirs := base()
	theirs["index"] = page("title", "Their title", "body", "Welcome.")

	got := collab.Merge(base(), mine, theirs)
	if got.Clean() {
		t.Fatal("merged a field both sides changed differently")
	}
	if len(got.Conflicts) != 1 {
		t.Fatalf("reported %d conflicts, want 1: %s", len(got.Conflicts), got.Summary())
	}
	c := got.Conflicts[0]
	if c.Page != "index" || c.Field != "title" {
		t.Errorf("conflict is on %s.%s, want index.title", c.Page, c.Field)
	}
	// All three values, so whoever decides can see them rather than being told
	// the names of two.
	if c.Base != "Home" || c.Mine != "My title" || c.Theirs != "Their title" {
		t.Errorf("conflict does not carry all three values: %+v", c)
	}
	// The unresolved field keeps what the draft actually has, so the result is
	// never a value nobody wrote.
	if v := got.Pages["index"].(map[string]any)["title"]; v != "Their title" {
		t.Errorf("the unresolved field is %v; it should still be the draft's "+
			"value, not mine and not something invented", v)
	}
}

// Agreement is not conflict. Two people making the same edit is the same
// content either way, and refusing it would be refusing a no-op.
func TestTheSameChangeMadeTwiceIsNotAConflict(t *testing.T) {
	mine := base()
	mine["index"] = page("title", "Home page", "body", "Welcome.")
	theirs := base()
	theirs["index"] = page("title", "Home page", "body", "Welcome.")

	got := collab.Merge(base(), mine, theirs)
	if !got.Clean() {
		t.Fatalf("two identical edits were treated as a disagreement: %s",
			got.Summary())
	}
	if v := got.Pages["index"].(map[string]any)["title"]; v != "Home page" {
		t.Errorf("the agreed value was not kept: %v", v)
	}
}

// Removing a page somebody is writing is not a merge either way. No rule can
// say which was meant, so neither is applied.
func TestARemovedPageSomebodyElseEditedIsAConflict(t *testing.T) {
	mine := base()
	delete(mine, "about")
	theirs := base()
	theirs["about"] = page("title", "About us", "body", "Founded 2019.")

	got := collab.Merge(base(), mine, theirs)
	if got.Clean() {
		t.Fatal("silently removed a page somebody else was editing")
	}
	// Their version survives. A merge that applied my deletion would destroy
	// their work and report success.
	if _, still := got.Pages["about"]; !still {
		t.Error("the page was removed despite the conflict, so their edit is gone")
	}

	// And the reason has to say what happened. Removing the deletion check
	// still produces a conflict — the field walk cannot descend into a page
	// that is not there — but it reports "at least one version is not an
	// object", which is true of the data and useless to the person reading it.
	// The message is the whole difference, so the message is what is asserted.
	if len(got.Conflicts) != 1 {
		t.Fatalf("reported %d conflicts, want 1: %s", len(got.Conflicts), got.Summary())
	}
	if why := got.Conflicts[0].Why; !strings.Contains(why, "removed") {
		t.Errorf("the conflict says %q, which does not tell somebody that a "+
			"page was removed while they were writing it", why)
	}
	if f := got.Conflicts[0].Field; f != "" {
		t.Errorf("the conflict names field %q; this is about the page itself", f)
	}
}

// The same in the other direction. Symmetry is worth a test of its own: the
// two branches are written separately and only one of them was exercised.
func TestAPageTheyRemovedWhileIWasEditingIsAConflict(t *testing.T) {
	mine := base()
	mine["about"] = page("title", "About", "body", "My new text.")
	theirs := base()
	delete(theirs, "about")

	got := collab.Merge(base(), mine, theirs)
	if got.Clean() {
		t.Fatal("my edit was silently dropped because they removed the page")
	}
	if len(got.Conflicts) != 1 {
		t.Fatalf("reported %d conflicts, want 1: %s", len(got.Conflicts), got.Summary())
	}
	if why := got.Conflicts[0].Why; !strings.Contains(why, "removed") {
		t.Errorf("the conflict says %q, which does not mention the removal", why)
	}
}

// A page one side removed and nobody else touched is simply removed. Treating
// every deletion as a conflict would make deletion impossible whenever anybody
// else had the draft open.
func TestARemovedPageNobodyElseTouchedIsRemoved(t *testing.T) {
	mine := base()
	delete(mine, "about")
	theirs := base()
	theirs["index"] = page("title", "Home", "body", "Changed elsewhere.")

	got := collab.Merge(base(), mine, theirs)
	if !got.Clean() {
		t.Fatalf("refused an uncontested deletion: %s", got.Summary())
	}
	if _, still := got.Pages["about"]; still {
		t.Error("the page I removed is still there")
	}
}

// A field one side removed and the other changed is the same problem one level
// down, and gets the same answer.
func TestARemovedFieldSomebodyElseChangedIsAConflict(t *testing.T) {
	mine := base()
	mine["index"] = page("title", "Home")
	theirs := base()
	theirs["index"] = page("title", "Home", "body", "Their new body.")

	got := collab.Merge(base(), mine, theirs)
	if got.Clean() {
		t.Fatal("silently dropped a field somebody else had just written")
	}
	if v := got.Pages["index"].(map[string]any)["body"]; v != "Their new body." {
		t.Errorf("their field is %v; it should survive an unresolved conflict", v)
	}
}

// Two people adding the same page with different content is a disagreement,
// not a race one of them wins.
func TestBothAddingTheSamePageDifferentlyIsAConflict(t *testing.T) {
	mine := base()
	mine["news"] = page("title", "News")
	theirs := base()
	theirs["news"] = page("title", "Latest")

	got := collab.Merge(base(), mine, theirs)
	if got.Clean() {
		t.Fatal("one side's new page silently replaced the other's")
	}
}

// Nothing may appear in the result that no side wrote. A merge that invents a
// value is worse than one that refuses, because it looks like agreement.
func TestTheResultOnlyContainsValuesSomebodyWrote(t *testing.T) {
	mine := base()
	mine["index"] = page("title", "Mine", "body", "My body.")
	theirs := base()
	theirs["index"] = page("title", "Theirs", "body", "Welcome.")

	got := collab.Merge(base(), mine, theirs)
	checked := 0
	for name, p := range got.Pages {
		fields, ok := p.(map[string]any)
		if !ok {
			continue
		}
		for k, v := range fields {
			checked++
			if in(v, base()[name]) || in(v, mine[name]) || in(v, theirs[name]) {
				continue
			}
			t.Errorf("%s.%s is %v, which no side wrote", name, k, v)
		}
	}
	// Count what was examined: a loop over an empty result finds nothing wrong.
	if checked == 0 {
		t.Fatal("the merged result has no fields at all")
	}
}

func in(v any, p any) bool {
	fields, ok := p.(map[string]any)
	if !ok {
		return false
	}
	for _, got := range fields {
		if reflect.DeepEqual(v, got) {
			return true
		}
	}
	return false
}

// The summary is what the person reads. It has to say what happened rather
// than that something happened.
func TestTheSummarySaysWhatNeedsDeciding(t *testing.T) {
	mine := base()
	mine["index"] = page("title", "Mine", "body", "Welcome.")
	theirs := base()
	theirs["index"] = page("title", "Theirs", "body", "Welcome.")

	s := collab.Merge(base(), mine, theirs).Summary()
	for _, want := range []string{"index.title", "changed this field"} {
		if !strings.Contains(s, want) {
			t.Errorf("the summary does not mention %q:\n%s", want, s)
		}
	}
	if !strings.Contains(s, "Nothing was overwritten") {
		t.Errorf("the summary does not say no work was lost:\n%s", s)
	}
}

// Merging a draft with itself changes nothing. The identity case is worth
// naming because a merge that alters an unchanged draft would produce a commit
// on every save that touched nothing.
func TestMergingWithNoChangesLeavesTheDraftAlone(t *testing.T) {
	got := collab.Merge(base(), base(), base())
	if !got.Clean() {
		t.Fatalf("an unchanged draft conflicted with itself: %s", got.Summary())
	}
	if !reflect.DeepEqual(got.Pages, base()) {
		t.Errorf("merging a draft with itself changed it:\n%v\n%v",
			got.Pages, base())
	}
	if len(got.TookMine)+len(got.TookTheirs) != 0 {
		t.Errorf("reported changes where there were none: %v %v",
			got.TookMine, got.TookTheirs)
	}
}
