package public

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/listing"
)

// The detail declaration is read off the page, and half of one is refused.
//
// A page naming a listing and no key cannot answer for any record. Reported
// rather than 404ing, because a misconfigured detail route that silently does
// nothing looks exactly like a record that is not there.
func TestHalfADetailDeclarationIsReportedRatherThanIgnored(t *testing.T) {
	for name, body := range map[string]any{
		"no key":     map[string]any{"detail": "catalogue"},
		"no listing": map[string]any{"detail_key": "slug"},
	} {
		d, declared := detailOf(body)
		if !declared {
			t.Errorf("%s: the declaration was not noticed at all, so the "+
				"route quietly does nothing", name)
			continue
		}
		st := &Site{}
		_, err := st.findRecord(d, "anything", nil)
		if err == nil {
			t.Errorf("%s: a half-written declaration answered", name)
			continue
		}
		if err == errNoRecord {
			t.Errorf("%s: it reads as a missing record, which sends somebody "+
				"looking for the wrong thing", name)
		}
	}
	// And a page with neither is simply not a detail page.
	if _, declared := detailOf(map[string]any{"title": "Home"}); declared {
		t.Error("an ordinary page was treated as a detail route")
	}
}

// The three answers a key lookup can give, and the one that matters.
//
// Taking the first of several is a decision made by whatever order the index
// happened to return, which nobody reviewed — and the two pages would swap
// places on a reindex.
func TestAKeyNamesOneRecordOrNone(t *testing.T) {
	rows := []listing.Row{
		{"slug": "kettle", "name": "A kettle"},
		{"slug": "pen", "name": "A pen"},
	}

	got, err := matchOne(rows, "slug", "pen")
	if err != nil {
		t.Fatalf("a key naming exactly one record failed: %v", err)
	}
	if got["name"] != "A pen" {
		t.Errorf("the wrong record came back: %v", got)
	}

	if _, err := matchOne(rows, "slug", "nothing"); err != errNoRecord {
		t.Errorf("a key naming nothing gave %v, want the shared not-found", err)
	}

	// The collision.
	dupes := append(rows, listing.Row{"slug": "pen", "name": "Another pen"})
	_, err = matchOne(dupes, "slug", "pen")
	if err == nil {
		t.Fatal("two records sharing a key resolved to one of them, chosen " +
			"by index order")
	}
	if err == errNoRecord {
		t.Error("an ambiguous key reads as a missing record")
	}
	for _, want := range []string{"2", "slug", "pen"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// A record the listing excludes has no page, and says the same thing as one
// that does not exist.
//
// Distinguishing them turns the route into an oracle: a different answer for
// "no such product" and "a product you may not see" tells anybody who asks
// which unpublished slugs exist.
func TestAMissingRecordAndAnExcludedOneAnswerTheSame(t *testing.T) {
	if errNoRecord.Error() == "" {
		t.Fatal("there is no shared error, so the two cases must differ")
	}
	if strings.Contains(errNoRecord.Error(), "permission") ||
		strings.Contains(errNoRecord.Error(), "excluded") {
		t.Errorf("the shared error distinguishes the two cases: %v", errNoRecord)
	}
}

// The structured data is rendered from the row, so the allow-list applies to
// it exactly as it applies to the page.
//
// Rendering from the record instead would be a second path by which a field
// nobody published reaches a crawler — and two renderers reading different
// sources is how a page says one price and its metadata says another.
func TestProductStructuredDataCarriesOnlyWhatTheListingExposed(t *testing.T) {
	row := listing.Row{
		"name": "Brass pen", "description": "Turned from solid brass.",
		"price": float64(4200), "currency": "GBP",
		"availability": "low_stock", "material": "brass",
	}
	got := productLD(row, "Marginalia")
	if got == "" {
		t.Fatal("no structured data was emitted for a product with a name")
	}
	for _, want := range []string{
		`"@type":"Product"`, `"price":"42.00"`, `"priceCurrency":"GBP"`,
		`schema.org/InStock`, `"name":"Marginalia"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the structured data lacks %s:\n  %s", want, got)
		}
	}
	// The price is the number, divided. A consumer has to compare it, and
	// "£42.00" is not a number in any locale's arithmetic.
	if strings.Contains(got, "4200") {
		t.Error("the price was emitted in pence, so every consumer reads it " +
			"as forty-two hundred pounds")
	}
	// A field the listing never exposed cannot appear, because it is not here.
	if strings.Contains(got, "MG-PN-BRS") {
		t.Error("a field outside the allow-list reached the structured data")
	}
}

// An unknown availability maps to nothing rather than to InStock.
//
// Guessing in the available direction is how a sold-out product stays listed
// as buyable.
func TestAnUnknownAvailabilityIsNotGuessedAsInStock(t *testing.T) {
	for token, want := range map[string]string{
		"in_stock":      "https://schema.org/InStock",
		"low_stock":     "https://schema.org/InStock",
		"made_to_order": "https://schema.org/PreOrder",
		"sold_out":      "https://schema.org/OutOfStock",
		"discontinued":  "",
		"":              "",
	} {
		if got := availabilityLD(token); got != want {
			t.Errorf("availabilityLD(%q) = %q, want %q", token, got, want)
		}
	}
}

// A row with no name produces nothing rather than an empty Product.
func TestAProductWithNoNameEmitsNoStructuredData(t *testing.T) {
	if got := productLD(listing.Row{"price": float64(100)}, "Shop"); got != "" {
		t.Errorf("an unnamed product was described to crawlers: %s", got)
	}
}
