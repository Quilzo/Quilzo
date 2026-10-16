// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package ucp serves a site's catalogue to shopping agents over the
// Universal Commerce Protocol (ucp.dev, version 2026-08-25): the discovery
// profile at /.well-known/ucp and the catalog search, lookup and product
// operations of its REST binding.
//
// # What this is, and what it is not
//
// It is the catalogue /catalogue.json already publishes, in the shape the
// shopping agents of 2026 read. It is not a shop till. There are no carts,
// no checkout and no orders: a checkout needs a buyer, somewhere to send the
// goods and a payment provider to take the money, and a program that took
// orders without them would be recording promises nobody could keep. An
// agent that finds something here buys it where a person does, from the
// product's page.
//
// # Why it asks for no credentials
//
// Everything this answers is already public, at /catalogue.json and on the
// product pages, so a key to read it would protect nothing and would turn
// away every agent its operator has never heard of — which is every agent.
// What a public surface does owe is a limit on how much one caller can ask
// for (the rate limit, per address) and a refusal of anything it did not
// define (strict request shapes, bounded bodies). Prices come only from the
// published records, so nothing a request says can change one.
//
// # Why the spec's shapes, exactly
//
// A platform reads this with a parser generated from the published schemas.
// A field in a different place is a field that platform cannot find, and a
// request field the spec defines but this refuses is a platform that gets an
// error for being correct. So requests accept every field the spec defines
// for these operations and nothing else, and responses use the spec's names
// and nesting, the envelope with its version, and its two kinds of failure:
// an HTTP status for a request that could not be processed, and a message
// inside a 200 for an answer the shop gives.
package ucp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/spend"
)

// Version is the protocol version this speaks, and the one every response
// names: an answer that does not say which version produced it is one a
// later agent cannot interpret.
const Version = "2026-08-25"

// MaxAmount bounds a price in minor units. A trillion is ten billion in a
// two-place currency, beyond any price this catalogue could mean, and a
// bound is what keeps a typo from becoming a number other programs multiply.
const MaxAmount = 1_000_000_000_000

// Product is one catalogue item, in the spec's shape.
//
// One variant per product, because a record here is one sellable thing at
// one price. The variant exists at all because UCP prices and stocks
// variants, not products, and an agent reads the price from there.
type Product struct {
	ID          string            `json:"id"`
	Handle      string            `json:"handle,omitempty"`
	Title       string            `json:"title"`
	Description Description       `json:"description"`
	URL         string            `json:"url,omitempty"`
	Categories  []Category        `json:"categories,omitempty"`
	PriceRange  PriceRange        `json:"price_range"`
	Media       []Media           `json:"media,omitempty"`
	Variants    []Variant         `json:"variants"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Description is text in the one format this writes. Plain only: a record's
// summary is text a person typed, and offering it as HTML would ask every
// platform to sanitise what never needed to be markup.
type Description struct {
	Plain string `json:"plain"`
}

// Category is a classification, here the shop's own.
type Category struct {
	Value    string `json:"value"`
	Taxonomy string `json:"taxonomy,omitempty"`
}

// Price is an amount in ISO 4217 minor units, the convention UCP fixes and
// internal/spend uses: an integer and a currency, never a fraction.
type Price struct {
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
}

// PriceRange is the span of a product's variant prices; with one variant,
// one price stated as a range so it is the shape agents read.
type PriceRange struct {
	Min Price `json:"min"`
	Max Price `json:"max"`
}

// Media is one picture, by an absolute URL.
type Media struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	AltText string `json:"alt_text,omitempty"`
}

// Variant is the one purchasable form of a product.
type Variant struct {
	ID           string        `json:"id"`
	SKU          string        `json:"sku,omitempty"`
	Title        string        `json:"title"`
	Description  Description   `json:"description"`
	Price        Price         `json:"price"`
	Availability *Availability `json:"availability,omitempty"`
	// Inputs says which identifiers of a lookup resolved to this variant,
	// and how. Lookup answers only; the spec forbids a variant without one
	// there, and has no use for one anywhere else.
	Inputs []Input `json:"inputs,omitempty"`
}

// Availability is whether a variant can be had now.
type Availability struct {
	Available bool   `json:"available"`
	Status    string `json:"status,omitempty"`
}

// Input is one lookup identifier that resolved to a variant.
type Input struct {
	ID    string `json:"id"`
	Match string `json:"match"`
}

// VariantID is the variant's identifier for a product's.
//
// Distinct from the product's because the spec resolves the two
// differently: a product id names the product and the shop picks its
// featured variant, a variant id names that variant exactly. A colon cannot
// occur in a slug, so no product can have an id that is another's variant.
func VariantID(product string) string { return product + ":default" }

// availability maps the closed tokens a product type uses onto UCP's.
//
// Made to order is available — it can be bought — with no status, because
// none of the spec's well-known values says "made after you order it" and
// borrowing backorder or preorder would tell an agent something untrue. The
// lead time travels in metadata.
var availability = map[string]Availability{
	"in_stock":      {Available: true, Status: "in_stock"},
	"low_stock":     {Available: true, Status: "in_stock"},
	"made_to_order": {Available: true},
	"sold_out":      {Available: false, Status: "out_of_stock"},
	"out_of_stock":  {Available: false, Status: "out_of_stock"},
	"discontinued":  {Available: false, Status: "discontinued"},
}

// FromRow shapes one catalogue row into a product.
//
// base is the site's absolute origin, because every URL in the answer must
// be absolute: an agent reads this away from the site, and a path means
// nothing there. The second return says what is wrong with a record that
// cannot be a product, so the answer can say it rather than quietly showing
// eleven of twelve.
func FromRow(row listing.Row, base string) (Product, string) {
	slug := stringOf(row["slug"])
	if slug == "" {
		slug = stringOf(row["id"])
	}
	name := stringOf(row["name"])
	if name == "" {
		name = stringOf(row["title"])
	}
	if slug == "" || name == "" {
		return Product{}, "a product has no slug or no name"
	}
	price, err := minorOf(row["price"])
	if err != nil {
		return Product{}, fmt.Sprintf("%s: %v", slug, err)
	}
	currency := strings.ToUpper(stringOf(row["currency"]))
	if !spend.ValidCurrency(currency) {
		return Product{}, fmt.Sprintf("%s: its currency %q is not an ISO 4217 code",
			slug, stringOf(row["currency"]))
	}
	desc := stringOf(row["summary"])
	if desc == "" {
		desc = stringOf(row["description"])
	}
	money := Price{Amount: price, Currency: currency}
	p := Product{
		ID: slug, Handle: slug, Title: name,
		Description: Description{Plain: desc},
		PriceRange:  PriceRange{Min: money, Max: money},
		Variants: []Variant{{
			ID: VariantID(slug), SKU: stringOf(row["sku"]), Title: name,
			Description: Description{Plain: desc}, Price: money,
		}},
	}
	if a, ok := availability[stringOf(row["availability"])]; ok {
		a := a
		p.Variants[0].Availability = &a
	}
	if r := stringOf(row["range"]); r != "" {
		p.Categories = []Category{{Value: r, Taxonomy: "merchant"}}
	}
	if u := absolute(stringOf(row["url"]), base); u != "" {
		p.URL = u
	}
	// A picture, when the record names one this site serves or an absolute
	// address. A bare filename is not a URL, and inventing a path for one is
	// how a catalogue advertises pictures it does not have.
	if img := stringOf(row["image"]); img != "" {
		u := ""
		if id, ok := media.IDIn(img); ok {
			u = absolute("/media/"+id, base)
		} else {
			u = absolute(img, base)
		}
		if u != "" {
			p.Media = []Media{{Type: "image", URL: u, AltText: stringOf(row["alt"])}}
		}
	}
	meta := map[string]string{}
	for _, field := range []string{"material", "dimensions", "lead_time"} {
		if v := stringOf(row[field]); v != "" {
			meta[field] = v
		}
	}
	if len(meta) > 0 {
		p.Metadata = meta
	}
	return p, ""
}

// absolute makes a URL absolute against the site's origin, or answers ""
// for anything that is neither an absolute web address nor a path on this
// site. Only http and https, so a record cannot hand an agent a javascript:
// or data: address under this shop's name.
func absolute(v, base string) string {
	switch {
	case v == "":
		return ""
	case strings.HasPrefix(v, "https://"), strings.HasPrefix(v, "http://"):
		return v
	case strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") && base != "":
		return strings.TrimSuffix(base, "/") + v
	}
	return ""
}

// minorOf reads a record's price as minor units.
//
// A fraction is refused rather than rounded, whichever way it is written:
// 12.5 pence is a data-entry mistake for a person to fix, not half a penny,
// and "12.50" read as twelve would be a price nobody set.
func minorOf(v any) (int64, error) {
	var n int64
	switch x := v.(type) {
	case float64:
		if x != float64(int64(x)) {
			return 0, fmt.Errorf("its price %v is not a whole number of minor units", x)
		}
		n = int64(x)
	case int:
		n = int64(x)
	case int64:
		n = x
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("its price %q is not a whole number of minor units", x)
		}
		n = parsed
	default:
		return 0, fmt.Errorf("its price is a %T, not a number", v)
	}
	if n < 0 || n > MaxAmount {
		return 0, fmt.Errorf("its price %d is outside 0 to %d minor units", n, int64(MaxAmount))
	}
	return n, nil
}

// stringOf reads a field that is a string, or nothing.
func stringOf(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}
