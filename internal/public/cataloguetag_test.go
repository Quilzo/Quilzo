// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The catalogue had no validator and no cache directive at all.
//
// It is the largest response this site serves — larger than the home page —
// on the one route whose entire purpose is being polled by a machine. A
// shopping agent asking every few minutes transferred all of it every time,
// and the answer is almost always that nothing changed.
//
// Found by listing the validators across every route on a running server, not
// by reading the handler:
//
//	ROUTE                  ETAG   CACHE     BYTES
//	/                      yes    public…   6428
//	/site.css              yes    public…   7327
//	/catalogue.json        NO     none      8450
func TestTheCatalogueHasAValidator(t *testing.T) {
	st := catalogueSite(t, "shop")

	first := get(st, "/catalogue.json", nil)
	if first.Code != http.StatusOK {
		t.Fatalf("the catalogue returned %d", first.Code)
	}
	tag := first.Header().Get("ETag")
	if tag == "" {
		t.Fatal("the catalogue serves no ETag, so every poll is a full transfer")
	}
	if first.Header().Get("Cache-Control") == "" {
		t.Error("the catalogue serves no Cache-Control")
	}

	again := get(st, "/catalogue.json", map[string]string{"If-None-Match": tag})
	if again.Code != http.StatusNotModified {
		t.Fatalf("a client holding the catalogue was sent it again (%d)", again.Code)
	}
	if again.Body.Len() != 0 {
		t.Errorf("a 304 carried %d bytes", again.Body.Len())
	}
}

// A weakened tag still revalidates, which is what a client that received the
// compressed representation sends back.
func TestTheCatalogueRevalidatesForACompressedClient(t *testing.T) {
	st := catalogueSite(t, "shop")
	tag := get(st, "/catalogue.json", nil).Header().Get("ETag")

	again := get(st, "/catalogue.json",
		map[string]string{"If-None-Match": "W/" + tag})
	if again.Code != http.StatusNotModified {
		t.Errorf("a weakened tag was treated as a different catalogue (%d)",
			again.Code)
	}
}

// A different view is a different document, so it gets a different tag.
// Otherwise a client holding the unfiltered catalogue would be told a filtered
// one had not changed.
func TestAFilteredCatalogueHasItsOwnTag(t *testing.T) {
	st := catalogueSite(t, "shop")

	all := get(st, "/catalogue.json", nil).Header().Get("ETag")
	some := get(st, "/catalogue.json?limit=1", nil).Header().Get("ETag")
	if all == "" || some == "" {
		t.Fatal("no tag on one of them")
	}
	if all == some {
		t.Error("a filtered catalogue carries the same tag as the whole one")
	}
	// And the wrong tag transfers rather than 304s.
	res := get(st, "/catalogue.json?limit=1",
		map[string]string{"If-None-Match": all})
	if res.Code == http.StatusNotModified {
		t.Error("a client holding the whole catalogue was told a filtered " +
			"one had not changed")
	}
}

// A publish reaches the pages and not the records.
//
// st.Listings.Tree is captured once, in siteFor, from the live commit at
// process start. Nothing refreshes it. So every listing-backed route — the
// catalogue, the feeds, the detail routes, a listing section on a page —
// serves whatever the records were when the server booted, while the pages
// around them update on every publish.
//
// Demonstrated on a running server: editing a page and publishing changed
// /about in the same process, with no restart.
func TestTheCatalogueSeesAPublishedRecord(t *testing.T) {
	st := catalogueSite(t, "shop")
	first := get(st, "/catalogue.json", nil)
	before := first.Header().Get("ETag")
	if !strings.Contains(first.Body.String(), "Kettle") {
		t.Fatalf("the fixture is wrong: %s", first.Body.String())
	}
	if strings.Contains(first.Body.String(), "Grinder") {
		t.Fatal("the fixture already has the record this adds")
	}
	if before == "" {
		t.Fatal("no tag to compare against")
	}

	// A record added and published, exactly as the CLI and the admin do it.
	tree, _, err := collection.Put(st.Listings.Store, st.Listings.Tree,
		"products", collection.Record{
			ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Fields: map[string]any{
				"title": "Grinder", "price": "55.00", "cost": "20.00"},
		}, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := st.Store.PutCommit(store.Commit{
		Tree: tree, Message: "a new product", Author: "test",
		At: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Store.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := st.Store.SetRef(site.RefLive, commit); err != nil {
		t.Fatal(err)
	}

	res := get(st, "/catalogue.json", nil)
	if !strings.Contains(res.Body.String(), "Grinder") {
		t.Error("a published record is not in the catalogue: the listing " +
			"tree was captured at start-up and nothing refreshes it, so " +
			"this route serves whatever the records were when the server " +
			"booted while the pages around it update on every publish")
	}

	// And the validator moves with it, or it is a cache that never expires.
	// The two belong in one test because they are one property: the tag has
	// to be keyed on the thing the body is built from, and keying it on the
	// live commit while the body came from a frozen tree is what showed the
	// staleness in the first place.
	if after := res.Header().Get("ETag"); after == before {
		t.Errorf("a record was published and the tag did not move (%s), so "+
			"a client would be told nothing changed", before)
	}
	if stale := get(st, "/catalogue.json",
		map[string]string{"If-None-Match": before}); stale.Code == http.StatusNotModified {
		t.Error("a stale tag still answered 304 after the records changed")
	}
}
