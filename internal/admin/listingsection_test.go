// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/site"
)

// The name field on a listing section offers the listings this site has.
//
// It is the one field on any section whose value has to match something
// declared elsewhere, and a page naming a listing that does not exist refuses
// to publish — the right refusal arriving after the editing is done, because
// nothing on the screen said what the names were. A datalist is plain HTML, so
// it works on an interface that serves script-src 'none'.
func TestTheListingSectionOffersTheListingsThatExist(t *testing.T) {
	srv, token := setup(t)

	set := &listing.Set{}
	for _, name := range []string{"recent", "catalogue"} {
		if err := set.Add(listing.Listing{
			Name: name, Collection: "products", Fields: []string{"name"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv.Listings = &Listings{
		Load: func() (*listing.Set, error) { return set, nil },
	}

	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	// A listing section first, then a prose one after it, so the two screens
	// differ only in the kind.
	body, err := section.Insert(pages["index"], listing.SectionKind, 0)
	if err != nil {
		t.Fatal(err)
	}
	if body, err = section.Insert(body, "prose", 1); err != nil {
		t.Fatal(err)
	}
	pages["index"] = body
	if _, err := site.SaveDraft(srv.Store, pages, "two sections", "test"); err != nil {
		t.Fatal(err)
	}

	html := get(t, srv, "/sections/fields?page=index&at=0", token).Body.String()
	for _, want := range []string{
		`<datalist id="listing-names">`,
		`<option value="catalogue">`,
		`<option value="recent">`,
		`list="listing-names"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the listing section's screen does not carry %s", want)
		}
	}

	// And the prose section beside it carries none of it. A suggestion list of
	// listing names on a field that is not a listing name is worse than none:
	// it invites somebody to put one there.
	plain := get(t, srv, "/sections/fields?page=index&at=1", token).Body.String()
	if strings.Contains(plain, "listing-names") {
		t.Error("a prose section's screen offers listing names")
	}
}

// With no listings wired, the field is a field. Not an error, and not a screen
// that refuses to draw.
func TestTheListingSectionScreenWorksWithNoListings(t *testing.T) {
	srv, token := setup(t)
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	body, err := section.Insert(pages["index"], listing.SectionKind, 0)
	if err != nil {
		t.Fatal(err)
	}
	pages["index"] = body
	if _, err := site.SaveDraft(srv.Store, pages, "a listing", "test"); err != nil {
		t.Fatal(err)
	}

	w := get(t, srv, "/sections/fields?page=index&at=0", token)
	if w.Code != 200 {
		t.Fatalf("the screen answered %d with no listings wired", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "listing-names") {
		t.Error("a datalist was drawn with nothing in it")
	} else if !strings.Contains(body, `id="f-name"`) {
		t.Error("the name field is not on the screen at all")
	}
}
