// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package commerce

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/listing"
)

// A record becomes a UCP product with the machine-readable parts carried
// and the human spellings left where people read them.
func TestARecordBecomesAProduct(t *testing.T) {
	p, problem := FromRow(listing.Row{
		"slug": "notebook", "name": "Linen Notebook", "summary": "A tall notebook",
		"description": "Longer words", "price": float64(2400), "currency": "GBP",
		"sku": "NB-1", "availability": "in_stock",
		"image": "/media/" + strings.Repeat("a", 64), "alt": "A notebook",
		"range": "desk", "material": "linen",
	})
	if problem != "" {
		t.Fatalf("a good record was refused: %s", problem)
	}
	if p.ID != "notebook" || p.Title != "Linen Notebook" {
		t.Errorf("id/title: %q %q", p.ID, p.Title)
	}
	if p.Description.Plain != "A tall notebook" {
		t.Errorf("description prefers %q", p.Description.Plain)
	}
	if p.PriceRange.Min.Amount != 2400 || p.PriceRange.Min.Currency != "GBP" {
		t.Errorf("price: %+v", p.PriceRange.Min)
	}
	if p.Variants[0].SKU != "NB-1" || !p.Variants[0].Availability.Available {
		t.Errorf("variant: %+v", p.Variants[0])
	}
	if len(p.Media) != 1 || p.Media[0].URL != "/media/"+strings.Repeat("a", 64) {
		t.Errorf("media: %+v", p.Media)
	}
	if p.Metadata["range"] != "desk" {
		t.Errorf("metadata: %+v", p.Metadata)
	}
}

// Availability that is not orderable marks the variant unavailable, which
// is what a shopping agent has to know before it carts.
func TestASoldOutRecordIsUnavailable(t *testing.T) {
	p, _ := FromRow(listing.Row{"slug": "pen", "name": "Pen",
		"price": float64(4500), "currency": "GBP", "availability": "sold_out"})
	if p.Variants[0].Availability == nil || p.Variants[0].Availability.Available {
		t.Errorf("sold out is available: %+v", p.Variants[0].Availability)
	}
}

// A record without a price is a problem to report, not a product to serve
// at zero.
func TestARecordWithoutAPriceIsAProblem(t *testing.T) {
	if _, problem := FromRow(listing.Row{"slug": "x", "name": "X"}); problem == "" {
		t.Fatal("a record without a price was shaped")
	}
}

func TestAFractionalPriceIsAProblem(t *testing.T) {
	if _, problem := FromRow(listing.Row{"slug": "x", "name": "X",
		"price": 12.5, "currency": "GBP"}); problem == "" {
		t.Fatal("a fractional price was shaped")
	}
}

func TestAnUnreadableCurrencyIsAProblem(t *testing.T) {
	if _, problem := FromRow(listing.Row{"slug": "x", "name": "X",
		"price": float64(5), "currency": "pounds"}); problem == "" {
		t.Fatal("a currency that is not a code was shaped")
	}
}

// An image that is not one of this site's media ids and not a URL is left
// out: a filename from a record is not a picture this shop serves.
func TestAFilenameImageIsLeftOut(t *testing.T) {
	p, _ := FromRow(listing.Row{"slug": "x", "name": "X",
		"price": float64(5), "currency": "GBP", "image": "picture.jpg"})
	if len(p.Media) != 0 {
		t.Errorf("a filename became media: %+v", p.Media)
	}
}
