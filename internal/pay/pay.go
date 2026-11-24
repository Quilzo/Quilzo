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
	"net/url"
	"slices"
	"sort"
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
	// Interval makes it a subscription, charged every week, month or year;
	// empty is a single payment. Read from the row's "interval".
	Interval string `json:"interval,omitempty"`
}

// Intervals are how often a subscription may be charged.
var Intervals = []string{"week", "month", "year"}

// Terms identifies an offer's terms, for an idempotency key: two requests
// for the same offer are the same request.
func (o Offer) Terms() string {
	terms := fmt.Sprintf("%s\x00%s\x00%d\x00%s", o.ID, o.Title, o.Amount, o.Currency)
	if o.Interval != "" {
		// A subscription's terms include how often: monthly and yearly at
		// one price are two offers.
		terms += "\x00" + o.Interval
	}
	sum := sha256.Sum256([]byte(terms))
	return hex.EncodeToString(sum[:12])
}

// Price is the offer's price in an unambiguous form, for records and the
// command line: 4.20 GBP.
func (o Offer) Price() string { return spend.Format(o.Amount, o.Currency) }

// Display is the offer's price as a shopper reads it: £4.20, or 4.20 SEK
// for a currency with no symbol everybody agrees on. Written by the same
// function that writes the price a catalogue row shows (internal/listing),
// so the page and its button say one price.
func (o Offer) Display() string { return spend.Display(o.Amount, o.Currency, o.Interval) }

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
	out := Offer{ID: p.ID, Title: p.Title, Amount: v.Price.Amount, Currency: v.Price.Currency}
	if iv, _ := row["interval"].(string); iv != "" {
		iv = strings.ToLower(strings.TrimSpace(iv))
		if !slices.Contains(Intervals, iv) {
			// A subscription charged on terms nobody can read is no offer.
			return Offer{}, false
		}
		out.Interval = iv
	}
	return out, true
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
	// Mode is the mode of the key that made it, ModeLive or ModeTest. A
	// link made in test mode takes no real money, and a key of one mode
	// cannot see or retire a link of the other, so a sync has to know
	// which a link is. Empty on a link made before modes were kept; see
	// InMode.
	Mode string `json:"mode,omitempty"`
	// Retired is when it stopped selling; zero while it sells.
	Retired time.Time `json:"retired,omitempty"`
}

// The modes a provider's key, and the links it makes, are in.
const (
	ModeLive = "live"
	ModeTest = "test"
)

// Live reports whether the link still sells.
func (l Link) Live() bool { return l.Retired.IsZero() }

// InMode is the mode the link was made in. A link made before the mode was
// kept says it in its address: Stripe serves a test-mode payment link at
// buy.stripe.com/test_….
func (l Link) InMode() string {
	if l.Mode != "" {
		return l.Mode
	}
	if u, err := url.Parse(l.URL); err == nil && strings.HasPrefix(u.Path, "/test_") {
		return ModeTest
	}
	return ModeLive
}

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

// PlanFor is Plan as a key of this mode sees the book: a live link made in
// the other mode sells nothing that key can sell or stop, so it is to
// retire and its offer to make again. An empty mode is a key nobody can
// read, and plans as Plan does. Sync learns the same from the provider;
// this is how the status says so without asking it.
func (b *Book) PlanFor(offers []Offer, mode string) (missing []Offer, retire []Link) {
	if b == nil || mode == "" {
		return b.Plan(offers)
	}
	keyed := &Book{}
	for _, l := range b.Links {
		if l.Live() && l.InMode() != mode {
			retire = append(retire, l)
			continue
		}
		keyed.Links = append(keyed.Links, l)
	}
	missing, stale := keyed.Plan(offers)
	retire = append(retire, stale...)
	sort.Slice(retire, func(i, j int) bool { return retire[i].ID < retire[j].ID })
	return missing, retire
}

// SellingIn counts the live links a key of this mode sells through; an
// empty mode counts every live link.
func (b *Book) SellingIn(mode string) int {
	n := 0
	if b != nil {
		for _, l := range b.Links {
			if l.Live() && (mode == "" || l.InMode() == mode) {
				n++
			}
		}
	}
	return n
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
	// Mode is the mode of the key it holds, ModeLive or ModeTest.
	Mode() string
	Make(ctx context.Context, o Offer, opts Options) (Link, error)
	// Retire stops a link selling. A link the provider no longer has in
	// the key's mode is retired already, and is no error.
	Retire(ctx context.Context, l Link) error
	// Selling is the ids of the links that sell at the provider for the
	// key it holds: active, in its account and in its mode.
	Selling(ctx context.Context) (map[string]bool, error)
	Orders(ctx context.Context, limit int) ([]Order, error)
}

// Sync makes the book match what the catalogue offers: a link for every
// offer without one, then the links nobody offers any more retired. New
// links come first, so a product whose price changed is never without a
// way to buy it at the price the page shows. What succeeded stays in the
// book when something fails, and the error says what did not.
//
// The book is checked against the provider first. A sync used to plan
// from the book alone, so a link was selling for as long as its price was
// unchanged, whatever the provider said: a shop set up on a test key and
// then given its live key kept every Buy button on test-mode checkout,
// where real cards are refused, while pay sync said the links matched, and
// a link the provider had lost stayed on the page. A link the provider
// does not sell for this key is retired here, and its offer made again
// below.
func Sync(ctx context.Context, p Provider, b *Book, offers []Offer, opts Options, now time.Time) (made, retired []Link, err error) {
	if err := opts.Validate(); err != nil {
		return nil, nil, err
	}
	var failed []string
	if b.SellingIn("") > 0 {
		selling, serr := p.Selling(ctx)
		if serr != nil {
			if errors.Is(serr, ErrUnreachable) {
				return nil, nil, fmt.Errorf("%w, so the payment links were not checked, made or retired", serr)
			}
			return nil, nil, fmt.Errorf("what sells at %s could not be read, so nothing was made or retired: %w", p.Name(), serr)
		}
		mode := p.Mode()
		for _, l := range b.Links {
			if !l.Live() || selling[l.Ref] {
				continue
			}
			b.Retire(l.Ref, now)
			retired = append(retired, l)
			if l.InMode() == ModeLive && mode != ModeLive {
				// Not a link that is gone: one a test key cannot see. It
				// is no longer offered on a shop now testing, and it still
				// takes real money from anybody who kept its address.
				failed = append(failed, fmt.Sprintf("%s at %s was made with a live key and still takes real money at %s; a %s key cannot retire it, so retire it in %s's dashboard",
					l.ID, l.Price(), p.Name(), mode, p.Name()))
			}
		}
	}
	missing, stale := b.Plan(offers)
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
