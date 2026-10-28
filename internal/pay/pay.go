// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package pay sells what a site's catalogue lists, through a payment
// provider's own hosted checkout.
//
// # What it does, and what it never does
//
// For each product the published catalogue offers at a price, the admin
// makes a payment link at the provider, for that product at that price, and
// keeps a book of them (Book). The site shows a Buy button beside a product
// only when the book holds a live link for exactly what the page says:
// the same product, the same name, the same amount in the same currency.
// A price changed on the site and not yet at the provider shows no button,
// never a button that charges the old price.
//
// The provider's checkout takes the card, the address and the receipt.
// Quilzo never sees a card number, and keeps no order: who bought what is
// read from the provider when somebody looks (Orders), shown, and not
// written down here. That keeps a shop's buyers out of this program's
// backups and its audit log, and keeps one copy of an order, at the provider
// that has to keep it anyway.
//
// The site itself holds no credential. The provider's key is read by the
// admin when it makes or retires links, from the sealed secrets or the
// environment, and the site reads only the book: links that are public the
// moment they are on a page.
//
// # Why links rather than sessions made per visitor
//
// A checkout session made per click needs the key in the process that
// answers visitors, which is the process this program confines hardest and
// trusts least. A link per offer is made once, by the admin, after a price
// is published, and every visitor's checkout starts from it at the provider.
// The cost is that a link knows one price, so a new price is a new link and
// the old one is retired; the book does that bookkeeping (Plan).
package pay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/spend"
	"github.com/quilzo/quilzo/internal/ucp"
)

// Offer is one product at one price: what a link sells.
type Offer struct {
	// ID is the product as the catalogue names it: its slug.
	ID string `json:"id"`
	// Title is the name the buyer sees at the checkout.
	Title string `json:"title"`
	// Amount is the price in minor units, and Currency its ISO 4217 code.
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
}

// Terms identifies an offer's terms, for an idempotency key: two requests
// for the same offer are the same request.
func (o Offer) Terms() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", o.ID, o.Title, o.Amount, o.Currency)))
	return hex.EncodeToString(sum[:12])
}

// Price is the offer's price in an unambiguous form, for records and the
// command line: 4.20 GBP.
func (o Offer) Price() string { return spend.Format(o.Amount, o.Currency) }

// Display is the offer's price as a shopper reads it: £4.20, or 4.20 SEK
// for a currency with no symbol everybody agrees on.
func (o Offer) Display() string {
	sym, ok := symbols[o.Currency]
	if !ok {
		return o.Price()
	}
	places := spend.Decimals(o.Currency)
	if places == 0 {
		return sym + strconv.FormatInt(o.Amount, 10)
	}
	unit := int64(math.Pow10(places))
	return fmt.Sprintf("%s%d.%0*d", sym, o.Amount/unit, places, o.Amount%unit)
}

// symbols are the currency signs a shopper reads without a second look.
// A dollar sign alone is the United States': "$4.20" on an Australian shop
// is a price somebody misreads.
var symbols = map[string]string{
	"GBP": "£", "EUR": "€", "USD": "$", "JPY": "¥", "INR": "₹",
	"AUD": "A$", "CAD": "CA$", "NZD": "NZ$", "HKD": "HK$", "SGD": "S$",
}

// OfferOf reads a catalogue row as an offer, the way the catalogue feed and
// shopping agents read it (internal/ucp), so the button and the feed cannot
// disagree about a price. A row that is not for sale is no offer: no price,
// a price of nothing, or a product its availability says cannot be bought.
func OfferOf(row map[string]any) (Offer, bool) {
	p, problem := ucp.FromRow(listing.Row(row), "")
	if problem != "" || len(p.Variants) != 1 {
		return Offer{}, false
	}
	v := p.Variants[0]
	if v.Price.Amount <= 0 || (v.Availability != nil && !v.Availability.Available) {
		return Offer{}, false
	}
	return Offer{ID: p.ID, Title: p.Title, Amount: v.Price.Amount, Currency: v.Price.Currency}, true
}

// Link is a payment link at the provider, for one offer.
type Link struct {
	Offer
	// URL is where a buyer goes to pay.
	URL string `json:"url"`
	// Provider is who holds it, and Ref the provider's own id for it.
	Provider string    `json:"provider"`
	Ref      string    `json:"ref"`
	Made     time.Time `json:"made"`
	// Retired is when it stopped selling; zero while it sells.
	Retired time.Time `json:"retired,omitempty"`
}

// Live reports whether the link still sells.
func (l Link) Live() bool { return l.Retired.IsZero() }

// Book is every link this site has made, live and retired. Retired links
// stay, so an order read from the provider can still be named.
type Book struct {
	Links []Link `json:"links"`
}

// MaxLinks bounds the book: a catalogue of thousands of products, each
// re-priced a few times, and not a file that grows without end.
const MaxLinks = 20000

// Live returns the live link selling exactly this offer.
func (b *Book) Live(o Offer) (Link, bool) {
	if b == nil {
		return Link{}, false
	}
	for _, l := range b.Links {
		if l.Live() && l.Offer == o {
			return l, true
		}
	}
	return Link{}, false
}

// Named returns the link with this provider id, live or retired.
func (b *Book) Named(ref string) (Link, bool) {
	if b == nil {
		return Link{}, false
	}
	for _, l := range b.Links {
		if l.Ref == ref {
			return l, true
		}
	}
	return Link{}, false
}

// Plan says what makes the book match what the catalogue offers: the offers
// no live link sells, and the live links selling something the catalogue no
// longer offers on those terms. An offer named twice is offered once, as
// the first says.
func (b *Book) Plan(offers []Offer) (missing []Offer, retire []Link) {
	want := map[Offer]bool{}
	seen := map[string]bool{}
	for _, o := range offers {
		if seen[o.ID] {
			continue
		}
		seen[o.ID] = true
		want[o] = true
		if _, ok := b.Live(o); !ok {
			missing = append(missing, o)
		}
	}
	if b != nil {
		for _, l := range b.Links {
			if l.Live() && !want[l.Offer] {
				retire = append(retire, l)
			}
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].ID < missing[j].ID })
	sort.Slice(retire, func(i, j int) bool { return retire[i].ID < retire[j].ID })
	return missing, retire
}

// Add puts a newly made link in the book.
func (b *Book) Add(l Link) error {
	if len(b.Links) >= MaxLinks {
		// The oldest retired link goes first: it sells nothing, and only
		// names old orders.
		for i, old := range b.Links {
			if !old.Live() {
				b.Links = append(b.Links[:i], b.Links[i+1:]...)
				break
			}
		}
		if len(b.Links) >= MaxLinks {
			return fmt.Errorf("the book holds %d live links, which is as many as it keeps", MaxLinks)
		}
	}
	b.Links = append(b.Links, l)
	return nil
}

// Retire marks a link as no longer selling.
func (b *Book) Retire(ref string, at time.Time) {
	for i := range b.Links {
		if b.Links[i].Ref == ref && b.Links[i].Live() {
			b.Links[i].Retired = at.UTC()
		}
	}
}

// Buy is where a Buy button for this row goes and the price it charges, or
// nothing when no live link charges exactly what the row says. The button
// says the price because a page may show a price written by hand beside
// the one it sells at, and the button is what is paid. A link whose address
// is not the provider's own https checkout is never offered, whatever the
// book holds.
func (b *Book) Buy(row map[string]any) (href, price string) {
	o, ok := OfferOf(row)
	if !ok {
		return "", ""
	}
	l, ok := b.Live(o)
	if !ok || !Checkout(l.Provider, l.URL) {
		return "", ""
	}
	return l.URL, o.Display()
}

// Checkout reports whether an address is the provider's hosted checkout.
func Checkout(provider, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range checkoutHosts[provider] {
		if host == h {
			return true
		}
	}
	return false
}

// checkoutHosts are where each provider's hosted checkout is served.
var checkoutHosts = map[string][]string{
	ProviderStripe: {"buy.stripe.com"},
}

// ProviderStripe is the one provider this sells through so far.
const ProviderStripe = "stripe"

// Order is a completed checkout, as the provider reports it. Read when
// somebody looks, shown, and not kept.
type Order struct {
	Ref      string    `json:"ref"`
	At       time.Time `json:"at"`
	Amount   int64     `json:"amount"`
	Currency string    `json:"currency"`
	Paid     bool      `json:"paid"`
	// Link is the provider's id for the link it came through, and Offer
	// what that link sold, when the book names it.
	Link  string `json:"link,omitempty"`
	Offer string `json:"offer,omitempty"`
	// The buyer, and where it goes: the shop's to read, not this program's
	// to keep.
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Ship  string `json:"ship,omitempty"`
}

// Total is what the order came to, as a person reads it.
func (o Order) Total() string { return spend.Format(o.Amount, o.Currency) }

// Options are how a shop's links behave at the checkout.
type Options struct {
	// ShipTo are the countries the checkout asks for a delivery address in,
	// as ISO 3166 codes; none means it asks for no address.
	ShipTo []string `json:"ship_to,omitempty"`
	// Done is what the checkout says once somebody has paid.
	Done string `json:"done,omitempty"`
}

// MaxDone bounds the message after paying, as the provider does.
const MaxDone = 500

// Validate checks options before they reach a provider.
func (o Options) Validate() error {
	for _, c := range o.ShipTo {
		if len(c) != 2 || strings.ToUpper(c) != c || strings.Trim(c, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			return fmt.Errorf("%q is not a country code; two capital letters, such as GB", c)
		}
	}
	if len([]rune(o.Done)) > MaxDone {
		return fmt.Errorf("the message after paying is over %d characters", MaxDone)
	}
	return nil
}

// ErrUnreachable is a provider that did not answer at all, as against one
// that answered no: there is no point asking it about the next product.
var ErrUnreachable = errors.New("the payment provider did not answer")

// Provider is a payment provider, as far as this asks it anything.
type Provider interface {
	Name() string
	Make(ctx context.Context, o Offer, opts Options) (Link, error)
	Retire(ctx context.Context, l Link) error
	Orders(ctx context.Context, limit int) ([]Order, error)
}

// Sync makes the book match what the catalogue offers: a link for every
// offer without one, then the links nobody offers any more retired. New
// links come first, so a product whose price changed is never without a
// way to buy it at the price the page shows. What succeeded stays in the
// book when something fails, and the error says what did not.
func Sync(ctx context.Context, p Provider, b *Book, offers []Offer, opts Options, now time.Time) (made, retired []Link, err error) {
	if err := opts.Validate(); err != nil {
		return nil, nil, err
	}
	missing, stale := b.Plan(offers)
	var failed []string
	for _, o := range missing {
		l, merr := p.Make(ctx, o, opts)
		if errors.Is(merr, ErrUnreachable) {
			// Said once, for every product it would have been said for.
			return made, retired, fmt.Errorf("%w, so %d payment link(s) were not made and %d not retired", merr, len(missing)-len(made), len(stale))
		}
		if merr != nil {
			failed = append(failed, fmt.Sprintf("%s at %s: %v", o.ID, o.Price(), merr))
			continue
		}
		if aerr := b.Add(l); aerr != nil {
			return made, retired, aerr
		}
		made = append(made, l)
	}
	for i, l := range stale {
		rerr := p.Retire(ctx, l)
		if errors.Is(rerr, ErrUnreachable) {
			return made, retired, fmt.Errorf("%w, so %d payment link(s) were not retired", rerr, len(stale)-i)
		}
		if rerr != nil {
			failed = append(failed, fmt.Sprintf("retiring %s at %s: %v", l.ID, l.Price(), rerr))
			continue
		}
		b.Retire(l.Ref, now)
		retired = append(retired, l)
	}
	if len(failed) > 0 {
		shown := failed
		if len(shown) > 5 {
			shown = append(shown[:5:5], fmt.Sprintf("and %d more", len(failed)-5))
		}
		return made, retired, fmt.Errorf("%d not done:\n  %s", len(failed), strings.Join(shown, "\n  "))
	}
	return made, retired, nil
}
