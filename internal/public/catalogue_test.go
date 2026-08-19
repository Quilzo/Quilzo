package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/store"
)

// catalogueSite builds a site with two products and a listing over them.
func catalogueSite(t *testing.T, catalogue string) *Site {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	tree := ""
	now := time.Now()
	for _, r := range []collection.Record{
		{ID: "0123456789abcdef0123456789abcdef", Fields: map[string]any{
			"title": "Kettle", "price": "39.00", "cost": "11.00"}},
		{ID: "fedcba9876543210fedcba9876543210", Fields: map[string]any{
			"title": "Toaster", "price": "25.00", "cost": "8.00"}},
	} {
		tree, _, err = collection.Put(s, tree, "products", r, now, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	set := &listing.Set{}
	// Fields is an allow-list, and "cost" is deliberately outside it: what a
	// shop pays is not what a shop publishes.
	if err := set.Add(listing.Listing{
		Name: "shop", Label: "Everything for sale", Collection: "products",
		Fields: []string{"title", "price"}, Sort: "title", Rows: 50,
	}); err != nil {
		t.Fatal(err)
	}

	return &Site{
		Store:     s,
		Catalogue: catalogue,
		Listings: &listing.Resolver{
			Store: s, Index: nil, Tree: tree, Set: set,
		},
	}
}

func getJSON(t *testing.T, st *Site, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	st.catalogue(w, httptest.NewRequest("GET", path, nil))
	var out map[string]any
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("not valid JSON: %v\n%s", err, w.Body.String())
		}
	}
	return w, out
}

// The catalogue serves the declared listing.
func TestTheCatalogueServesTheDeclaredListing(t *testing.T) {
	st := catalogueSite(t, "shop")
	w, out := getJSON(t, st, "/catalogue.json")
	if w.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", w.Code, w.Body.String())
	}
	if out["catalogue"] != "shop" {
		t.Errorf("catalogue is %v", out["catalogue"])
	}
	items, _ := out["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("%d items, want 2", len(items))
	}
}

// The listing's field allow-list holds.
//
// This is the reason a catalogue is a listing rather than a new query path: the
// allow-list already exists and is already enforced. A feed that reached around
// it would expose what a shop pays for its stock to anybody who fetched a URL.
func TestTheCatalogueCannotReachOutsideTheAllowedFields(t *testing.T) {
	st := catalogueSite(t, "shop")
	_, out := getJSON(t, st, "/catalogue.json")

	items, _ := out["items"].([]any)
	for _, it := range items {
		row, _ := it.(map[string]any)
		if _, leaked := row["cost"]; leaked {
			t.Fatal("the feed published a field the listing does not allow; " +
				"what a shop pays is not what a shop publishes")
		}
		if row["title"] == nil {
			t.Error("an allowed field is missing")
		}
	}
}

// The listing is named by configuration, never by the request.
//
// A caller that could choose would be selecting from every listing declared,
// including ones a page embeds behind a filter somebody assumed was private.
func TestTheRequestCannotChooseWhichListingRuns(t *testing.T) {
	st := catalogueSite(t, "shop")

	// Every plausible spelling of "run a different one".
	for _, q := range []string{
		"/catalogue.json?listing=secret",
		"/catalogue.json?catalogue=secret",
		"/catalogue.json?name=secret",
	} {
		w, out := getJSON(t, st, q)
		if w.Code != http.StatusOK {
			t.Fatalf("%s answered %d", q, w.Code)
		}
		if out["catalogue"] != "shop" {
			t.Errorf("%s ran %v instead of the configured listing", q, out["catalogue"])
		}
	}
}

// Nothing declared, nothing served — and not an empty document.
//
// "No products" and "this site does not publish a catalogue" are different
// claims, and an agent told the first will not ask again.
func TestNoCatalogueIsNotAnEmptyCatalogue(t *testing.T) {
	st := catalogueSite(t, "")
	w, _ := getJSON(t, st, "/catalogue.json")
	if w.Code != http.StatusNotFound {
		t.Errorf("answered %d with nothing configured, want 404", w.Code)
	}
}

// A catalogue naming a listing that does not exist is this side's mistake.
func TestAMisconfiguredCatalogueSaysSoRatherThan404ing(t *testing.T) {
	st := catalogueSite(t, "nonexistent")
	w, _ := getJSON(t, st, "/catalogue.json")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("answered %d for a listing that does not exist; a "+
			"misconfiguration and an absent resource need different answers",
			w.Code)
	}
}

// The terms travel with the data.
//
// An agent reading a catalogue is about to repeat it to somebody. Making it
// fetch a second document to find out whether it may is how terms get skipped.
func TestTheTermsTravelWithTheCatalogue(t *testing.T) {
	st := catalogueSite(t, "shop")
	st.Licence = &Licence{
		Prohibits: []string{"train"}, Attribution: "https://example.com",
	}
	w, out := getJSON(t, st, "/catalogue.json")

	terms, ok := out["terms"].(map[string]any)
	if !ok {
		t.Fatal("the feed carries no terms")
	}
	if terms["policy"] != "/license.xml" {
		t.Errorf("terms point at %v", terms["policy"])
	}
	// And the mining reservation is on the response that carried the products.
	if got := w.Header().Get("tdm-reservation"); got != "1" {
		t.Errorf("tdm-reservation is %q on a catalogue that prohibits training", got)
	}
}

// A site with no declared licence asserts none here either.
func TestACatalogueWithoutTermsClaimsNone(t *testing.T) {
	st := catalogueSite(t, "shop")
	_, out := getJSON(t, st, "/catalogue.json")
	if _, present := out["terms"]; present {
		t.Error("terms were published for a site that declared none")
	}
}

// A page points at the catalogue, so an agent finds it without being told.
//
// Shopping agents arrive at a page rather than at a well-known path, so the
// page is where the pointer has to be. A feed nobody can discover is a feed
// nobody reads.
func TestAPagePointsAtTheCatalogue(t *testing.T) {
	st := catalogueSite(t, "shop")
	got := st.injectHead("<html><head></head><body></body></html>", "index", "")
	if !strings.Contains(got, `href="/catalogue.json"`) {
		t.Errorf("no page points at the catalogue:\n%s", got)
	}
	if !strings.Contains(got, `rel="alternate"`) {
		t.Error("the pointer is not marked as an alternate representation")
	}
}

// A site with no catalogue points at nothing.
//
// A link to a route that 404s teaches whatever followed it that this site's
// metadata is unreliable, which is worse than having none.
func TestASiteWithoutACatalogueLinksToNothing(t *testing.T) {
	st := catalogueSite(t, "")
	got := st.injectHead("<html><head></head><body></body></html>", "index", "")
	if strings.Contains(got, "catalogue.json") {
		t.Error("a site with no catalogue advertised one")
	}
}
