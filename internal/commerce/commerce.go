// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package commerce is the merchant half of agentic commerce: a shop's
// products served to shopping agents, and the orders they place.
//
// internal/spend is the other half — an agent of this deployment buying under
// a mandate a person granted it. This package is the shop behind the counter:
// the same catalogue.json already serves a machine-readable feed of what is
// for sale, and this is what happens when an agent wants to buy from it
// rather than read it.
//
// # Why UCP's shape, and not a private API
//
// The Universal Checkout Protocol (ucp.dev, envelope version 2026-08-25) is
// what the shopping agents of 2026 actually speak: search and lookup against
// a catalogue, a cart the merchant prices, checkout sessions, and a discovery
// document at /.well-known/ucp that names what this shop can do. A private
// API would be simpler for this program and useless to every agent that
// arrives, which is the definition of a integration nobody will ever write.
// Where UCP leaves a choice this takes the strict one: every response is
// wrapped in the versioned envelope, errors are the two-layer convention the
// spec fixes (transport faults as HTTP status codes, business outcomes as
// messages inside a 200), and Idempotency-Key is honoured with the spec's
// 409-on-different-body rule.
//
// # Why the agent is identified, not believed
//
// UCP lets a business decide how agents authenticate, and offers reusable
// keys, OAuth, mTLS and RFC 9421 signatures. Only the last one identifies
// anybody: a key in a header is a bearer secret, while an HTTP Message
// Signature proves the request was made by the holder of a named key. Web
// Bot Auth — the IETF work Visa's Trusted Agent Protocol builds on — is that:
// RFC 9421 with Ed25519 keys, covering at least the destination. This
// deployment already verifies it for crawlers (internal/crawl), with the
// operator supplying the keys rather than the verifier fetching whatever URL
// a request names, which is server-side request forgery wearing an
// authentication costume. Shopping agents are verified the same way, with
// their own key list, because trusting an agent is a decision and decisions
// here are made by whoever configured them.
//
// # Why the mandates are checked in code
//
// AP2, the payment layer under UCP, states its threat model plainly: agents
// are potential attackers, and every check happens in deterministic code. A
// mandate is an SD-JWT (RFC 9901 selective disclosure over a signed JWT)
// whose vct names what it authorises — mandate.checkout.1 binds a purchase
// to the merchant's signed checkout through checkout_hash;
// mandate.payment.1 names a payee, an amount and a currency. The merchant's
// duties are to sign the checkout with a non-deterministic signature (ECDSA,
// so the hash cannot be rainbow-tabled), verify the hashes match, and check
// the payee is this shop and the amount is what the checkout says — in code,
// on every presentation, with a used mandate refused a second use. What a
// model was told is not a factor anywhere in this package.
//
// # What this does not pretend to do
//
// It does not capture money. Completing a checkout records an order under
// the verified mandates and the verified identity of the agent that placed
// it; the money moves however the operator has arranged for money to move,
// and an order paid by nobody is a fact the order record states. Prices come
// from the published product records at request time and are recomputed by
// this program on every cart, checkout and completion — a price in a request
// is not read, let alone trusted, so an agent cannot negotiate one and a
// compromised catalogue feed cannot advertise one the records do not carry.
//
// # The NIST spine
//
// The controls here are ordinary ones, stated against the publications they
// come from so a reviewer can check the mapping rather than take it:
// per-request authentication and per-action policy in code, with no
// implicit trust from network reachability (SP 800-207); machine identity
// by approved cryptographic signatures only — Ed25519 for Web Bot Auth,
// ECDSA P-256 for mandates and merchant checkouts, SHA-256 for every
// digest (FIPS 186-5, FIPS 180-4); input validation that refuses what this
// program did not define, and bounded bodies, keys and maps (SP 800-53
// SI-10, SC-5); audit records naming who acted, when and on what, kept in
// the order book rather than a log that outlives the credential (AU-2,
// AU-3, AU-12); and prices changed only through the site's own reviewed
// publishing path, which is configuration management by another name
// (CM-3, CM-5).
package commerce

import (
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/spend"
)

// UCPVersion is the protocol envelope version this surface speaks, from the
// UCP specification dated 2026-08-25. Every response carries it, because a
// response that does not say which version of the protocol answered is a
// response a future agent cannot reason about.
const UCPVersion = "2026-08-25"

// Availability states a product record may carry. A closed set, because the
// type says so and because "Out Of Stock", "sold out!" and "none" are three
// spellings of one machine-readable fact.
var orderable = map[string]bool{
	"in_stock": true, "low_stock": true, "made_to_order": true,
}

// Product is one thing for sale, in the UCP catalogue shape.
//
// A product here has one variant, because a record is one sellable thing
// with one price; the variant exists at all because UCP addresses prices and
// availability per variant, and an id that means different things in the two
// places is an id an agent will eventually send back in the wrong one.
type Product struct {
	ID          string `json:"id"`
	Handle      string `json:"handle,omitempty"`
	Title       string `json:"title"`
	Description *struct {
		Plain string `json:"plain,omitempty"`
	} `json:"description,omitempty"`
	URL        string            `json:"url,omitempty"`
	PriceRange MoneyRange        `json:"price_range"`
	ListPrice  *MoneyRange       `json:"list_price_range,omitempty"`
	Media      []Media           `json:"media,omitempty"`
	Variants   []Variant         `json:"variants"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Money is an amount in ISO 4217 minor units — the same convention
// internal/spend uses on the paying side, and the one UCP and AP2 both fix:
// an integer and a currency code, never a decimal fraction, because a float
// that cannot represent 0.10 has no place in an amount of money.
type Money struct {
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
}

// MoneyRange is one price, as UCP states it: the range a product's variants
// span. One variant, so min and max are the same number, and saying it as a
// range keeps the shape agents read rather than a special case they parse.
type MoneyRange struct {
	Min Money `json:"min"`
	Max Money `json:"max"`
}

// Media is one picture of a product.
type Media struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	AltText string `json:"alt_text,omitempty"`
}

// Variant is the one sellable form of a product.
type Variant struct {
	ID           string `json:"id"`
	SKU          string `json:"sku,omitempty"`
	Title        string `json:"title"`
	Price        Money  `json:"price"`
	Availability *struct {
		Available bool `json:"available"`
	} `json:"availability,omitempty"`
}

// FromRow shapes one product record into the UCP form.
//
// The second return is what is wrong with the record, or empty. A record the
// catalogue listing exposes without a price, a currency or a title is not
// skipped silently — the caller turns each problem into a message on the
// response, because a shop that quietly shows eleven of twelve products and
// an operator who never learns why is the failure mode internal/feed exists
// to prevent, in a catalogue.
func FromRow(row listing.Row) (Product, string) {
	slug := stringOf(row["slug"])
	name := stringOf(row["name"])
	if slug == "" {
		slug = stringOf(row["id"])
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
		return Product{}, fmt.Sprintf("%s: its currency %q is not an ISO 4217 code", slug, stringOf(row["currency"]))
	}
	p := Product{
		ID:     slug,
		Handle: slug,
		Title:  name,
		PriceRange: MoneyRange{Min: Money{price, currency},
			Max: Money{price, currency}},
		Metadata: map[string]string{},
	}
	if s := stringOf(row["summary"]); s != "" {
		p.Description = &struct {
			Plain string `json:"plain,omitempty"`
		}{Plain: s}
	} else if s := stringOf(row["description"]); s != "" {
		p.Description = &struct {
			Plain string `json:"plain,omitempty"`
		}{Plain: s}
	}
	if s := stringOf(row["sku"]); s != "" {
		p.Variants = []Variant{{ID: slug, SKU: s, Title: name, Price: Money{price, currency}}}
	} else {
		p.Variants = []Variant{{ID: slug, Title: name, Price: Money{price, currency}}}
	}
	avail := stringOf(row["availability"])
	if avail != "" {
		available := orderable[avail]
		p.Variants[0].Availability = &struct {
			Available bool `json:"available"`
		}{Available: available}
	}
	// A picture, when the record carries one this program can address. A media
	// reference resolves to this site's /media/ path; anything else is used
	// only when it is already an absolute or root-relative URL, because a
	// filename from a record is not a URL and inventing a path for it is how a
	// catalogue advertises pictures it does not serve.
	if img := stringOf(row["image"]); img != "" {
		if id, ok := media.IDIn(img); ok {
			p.Media = []Media{{Type: "image", URL: "/media/" + id, AltText: stringOf(row["alt"])}}
		} else if strings.HasPrefix(img, "https://") || strings.HasPrefix(img, "http://") ||
			strings.HasPrefix(img, "/") {
			p.Media = []Media{{Type: "image", URL: img, AltText: stringOf(row["alt"])}}
		}
	}
	for _, field := range []string{"range", "material", "availability", "dimensions", "lead_time"} {
		if v := stringOf(row[field]); v != "" {
			p.Metadata[field] = v
		}
	}
	if len(p.Metadata) == 0 {
		p.Metadata = nil
	}
	return p, ""
}

// minorOf reads a record's price as minor units.
//
// The type says the price is a number in minor units and bounded, and what is
// decoded here is what the type allowed through. A fraction is refused rather
// than rounded: a price of 12.5 pence is a data entry error worth a person's
// attention, not half a penny.
func minorOf(v any) (int64, error) {
	switch x := v.(type) {
	case float64:
		if x != float64(int64(x)) || x < 0 || x > 1e12 {
			return 0, fmt.Errorf("its price %v is not a whole number of minor units", x)
		}
		return int64(x), nil
	case int:
		if x < 0 {
			return 0, fmt.Errorf("its price %d is negative", x)
		}
		return int64(x), nil
	case int64:
		if x < 0 {
			return 0, fmt.Errorf("its price %d is negative", x)
		}
		return x, nil
	case string:
		var n int64
		if _, err := fmt.Sscanf(strings.TrimSpace(x), "%d", &n); err != nil || n < 0 {
			return 0, fmt.Errorf("its price %q is not a whole number of minor units", x)
		}
		return n, nil
	}
	return 0, fmt.Errorf("its price is a %T, not a number", v)
}

// stringOf reads a field that is a string, or nothing.
func stringOf(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}
