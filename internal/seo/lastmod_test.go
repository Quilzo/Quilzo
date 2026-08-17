package seo

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The property every other CMS cannot offer: saving a page without changing it
// must not move its date. In a row-based store there is no cheap way to tell
// "saved" from "changed", so updated_at moves on every save and lastmod
// inherits the lie — which is why Google says it may stop trusting the field.
func TestSavingWithoutChangingDoesNotMoveTheDate(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	original := map[string]any{
		"index": map[string]any{"title": "Home", "body": "Welcome."},
		"about": map[string]any{"title": "About", "body": "Who we are."},
	}
	if _, err := site.SaveDraft(s, original, "first", "t"); err != nil {
		t.Fatal(err)
	}
	pub, _ := site.Publish(s, "")
	head := pub.Published

	first, err := LastChanged(s, head, 100)
	if err != nil {
		t.Fatal(err)
	}
	indexDate, aboutDate := first["index"], first["about"]

	// Save again with identical content for index, changed content for about.
	// A row-based CMS would move both.
	time.Sleep(1100 * time.Millisecond) // commit times have second resolution
	next := map[string]any{
		"index": map[string]any{"title": "Home", "body": "Welcome."},
		"about": map[string]any{"title": "About", "body": "Who we are now."},
	}
	if _, err := site.SaveDraft(s, next, "second", "t"); err != nil {
		t.Fatal(err)
	}
	pub, _ = site.Publish(s, "")
	head = pub.Published

	second, err := LastChanged(s, head, 100)
	if err != nil {
		t.Fatal(err)
	}

	if !second["index"].Equal(indexDate) {
		t.Errorf("index was re-saved with identical bytes and its date moved "+
			"from %s to %s; that is the lie this exists to avoid",
			indexDate.Format(time.RFC3339), second["index"].Format(time.RFC3339))
	}
	if !second["about"].After(aboutDate) {
		t.Errorf("about genuinely changed and its date did not move: %s -> %s",
			aboutDate.Format(time.RFC3339), second["about"].Format(time.RFC3339))
	}
}

// Publishing the whole site must not touch every page's date either. This is
// the bulk-operation case, which is how most sitemaps end up claiming every
// page changed on the same day.
func TestRepublishingEverythingChangesNothing(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"a": map[string]any{"title": "A"},
		"b": map[string]any{"title": "B"},
		"c": map[string]any{"title": "C"},
	}
	if _, err := site.SaveDraft(s, pages, "first", "t"); err != nil {
		t.Fatal(err)
	}
	pub, _ := site.Publish(s, "")
	head := pub.Published
	before, _ := LastChanged(s, head, 100)

	time.Sleep(1100 * time.Millisecond)
	if _, err := site.SaveDraft(s, pages, "republish everything", "t"); err != nil {
		t.Fatal(err)
	}
	pub, _ = site.Publish(s, "")
	head = pub.Published
	after, _ := LastChanged(s, head, 100)

	for name := range pages {
		if !after[name].Equal(before[name]) {
			t.Errorf("%s moved on a no-op republish: %s -> %s", name,
				before[name].Format(time.RFC3339), after[name].Format(time.RFC3339))
		}
	}
}

// A page added later carries its own date, not the site's.
func TestANewPageGetsItsOwnDate(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"old": map[string]any{"title": "Old"}}, "first", "t"); err != nil {
		t.Fatal(err)
	}
	pub, _ := site.Publish(s, "")
	head := pub.Published
	first, _ := LastChanged(s, head, 100)

	time.Sleep(1100 * time.Millisecond)
	if _, err := site.SaveDraft(s, map[string]any{
		"old": map[string]any{"title": "Old"},
		"new": map[string]any{"title": "New"}}, "second", "t"); err != nil {
		t.Fatal(err)
	}
	pub, _ = site.Publish(s, "")
	head = pub.Published
	second, _ := LastChanged(s, head, 100)

	if !second["old"].Equal(first["old"]) {
		t.Error("an untouched page moved when a new one was added")
	}
	if !second["new"].After(first["old"]) {
		t.Error("the new page did not get a later date than the old one")
	}
}

// A deleted page has no URL, so it has no place in a sitemap.
func TestDeletedPagesAreNotReported(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"keep": map[string]any{"t": "k"},
		"drop": map[string]any{"t": "d"}}, "first", "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"keep": map[string]any{"t": "k"}}, "second", "t"); err != nil {
		t.Fatal(err)
	}
	pub, _ := site.Publish(s, "")
	head := pub.Published

	got, err := LastChanged(s, head, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := got["drop"]; present {
		t.Error("a deleted page was reported as live")
	}
	if _, present := got["keep"]; !present {
		t.Error("a live page was lost")
	}
}

func TestAnEmptyStoreIsNotAnError(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got, err := LastChanged(s, "", 100)
	if err != nil || len(got) != 0 {
		t.Errorf("an unpublished store gave %v, %v", got, err)
	}
}
