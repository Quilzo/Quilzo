// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package pay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/egress"
)

// Stripe sells through Stripe Payment Links, over its REST API.
//
// It asks for four things and no more, so the key it is given can be a
// restricted key allowed exactly those: write Prices and Products (a price
// is made with its product), write Payment Links (which reads them too: a
// sync asks which still sell), and read Checkout Sessions. A restricted
// key is what the command line asks for, because a secret key can also
// refund, pay out and read every customer.
//
// The API version is pinned, so a change Stripe makes to a response's shape
// reaches this code when somebody moves the pin, not on a Tuesday.
type Stripe struct {
	Key string
	// Base is the API's address; empty is Stripe's own. Set by tests only.
	Base string
	HTTP *http.Client
}

// StripeVersion is the API version every request names.
const StripeVersion = "2024-06-20"

// ValidStripeKey reports whether a key looks like a Stripe secret or
// restricted key, test or live, without saying anything about it.
func ValidStripeKey(k string) bool {
	for _, p := range []string{"sk_test_", "sk_live_", "rk_test_", "rk_live_"} {
		if strings.HasPrefix(k, p) && len(k) > len(p)+10 && !strings.ContainsAny(k, " \t\r\n") {
			return true
		}
	}
	return false
}

// Live reports whether the key takes real money.
func (s *Stripe) Live() bool {
	return strings.HasPrefix(s.Key, "sk_live_") || strings.HasPrefix(s.Key, "rk_live_")
}

// Mode is the mode of the key: ModeLive when it takes real money.
func (s *Stripe) Mode() string {
	if s.Live() {
		return ModeLive
	}
	return ModeTest
}

func (s *Stripe) base() string {
	if s.Base != "" {
		return strings.TrimSuffix(s.Base, "/")
	}
	return "https://api.stripe.com"
}

func (s *Stripe) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	// Through egress, so an isolated deployment can see this connection
	// and refuse it, and a refusal says what stops working.
	return egress.Client("payments", 30*time.Second)
}

// stripeError is the shape of Stripe's refusals.
type stripeError struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// refusal is an answer Stripe gave that was not a yes: its status, its
// code, and what it said.
type refusal struct {
	status        int
	code, message string
}

func (r *refusal) Error() string {
	if r.message == "" {
		return fmt.Sprintf("Stripe refused it (%d)", r.status)
	}
	return fmt.Sprintf("Stripe refused it (%d): %s", r.status, r.message)
}

// missing reports whether Stripe has no such object for this key: deleted,
// lost with a test account's data, or of the other mode.
func missing(err error) bool {
	var r *refusal
	return errors.As(err, &r) && r.status == http.StatusNotFound && r.code == "resource_missing"
}

// call makes one request. A POST carries an idempotency key, so a request
// retried after a timeout makes nothing twice.
func (s *Stripe) call(ctx context.Context, method, path string, form url.Values, idem string, out any) error {
	if !ValidStripeKey(s.Key) {
		return errors.New("the Stripe key is not a secret or restricted key (sk_… or rk_…)")
	}
	target := s.base() + path
	var body io.Reader
	if method == http.MethodGet && len(form) > 0 {
		target += "?" + form.Encode()
	} else if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Key)
	req.Header.Set("Stripe-Version", StripeVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	res, err := s.client().Do(req)
	if err != nil {
		// The error names the address and never the key, which is in a
		// header and not the URL.
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("Stripe's answer could not be read: %w", err)
	}
	if res.StatusCode/100 != 2 {
		var e stripeError
		_ = json.Unmarshal(raw, &e)
		return &refusal{status: res.StatusCode, code: e.Error.Code, message: e.Error.Message}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("Stripe's answer is not what this version reads: %w", err)
		}
	}
	return nil
}

// Name is the provider's name, as a link records it.
func (s *Stripe) Name() string { return ProviderStripe }

// Make makes a price for the offer, with its product, and a payment link
// that sells one of it.
func (s *Stripe) Make(ctx context.Context, o Offer, opts Options) (Link, error) {
	if err := opts.Validate(); err != nil {
		return Link{}, err
	}
	price := url.Values{
		"currency":                             {strings.ToLower(o.Currency)},
		"unit_amount":                          {strconv.FormatInt(o.Amount, 10)},
		"product_data[name]":                   {o.Title},
		"product_data[metadata][quilzo_offer]": {o.ID},
	}
	if o.Interval != "" {
		// A recurring price: the payment link starts a subscription, which
		// the buyer manages and cancels at Stripe.
		price.Set("recurring[interval]", o.Interval)
	}
	var p struct {
		ID string `json:"id"`
	}
	if err := s.call(ctx, http.MethodPost, "/v1/prices", price, "quilzo-price-"+o.Terms(), &p); err != nil {
		return Link{}, err
	}
	if p.ID == "" {
		return Link{}, errors.New("Stripe made a price and did not say which")
	}
	link := url.Values{
		"line_items[0][price]":    {p.ID},
		"line_items[0][quantity]": {"1"},
		"metadata[quilzo_offer]":  {o.ID},
		"after_completion[type]":  {"hosted_confirmation"},
	}
	if opts.Done != "" {
		link.Set("after_completion[hosted_confirmation][custom_message]", opts.Done)
	}
	for i, c := range opts.ShipTo {
		link.Set(fmt.Sprintf("shipping_address_collection[allowed_countries][%d]", i), c)
	}
	var l struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := s.call(ctx, http.MethodPost, "/v1/payment_links", link, "quilzo-link-"+o.Terms()+"-"+p.ID, &l); err != nil {
		return Link{}, err
	}
	if l.ID == "" || !Checkout(ProviderStripe, l.URL) {
		return Link{}, fmt.Errorf("Stripe's payment link %q is not at its own checkout", l.URL)
	}
	return Link{Offer: o, URL: l.URL, Provider: ProviderStripe, Ref: l.ID, Made: time.Now().UTC(), Mode: s.Mode()}, nil
}

// Retire stops a payment link selling. Its orders stay at Stripe.
//
// A link Stripe has no record of, in this key's mode, is retired already:
// deleted, or lost with a test account's data. That was a refusal, and
// one that could never clear: every sync after ended "Stripe refused it
// (404): No such payment_link", and turning payments off left such links
// in the book as selling. A link of the other mode is a refusal still,
// because this key cannot see it, which says nothing about whether it
// sells.
func (s *Stripe) Retire(ctx context.Context, l Link) error {
	if !strings.HasPrefix(l.Ref, "plink_") || strings.ContainsAny(l.Ref, "/?#") {
		return fmt.Errorf("%q is not a Stripe payment link", l.Ref)
	}
	err := s.call(ctx, http.MethodPost, "/v1/payment_links/"+l.Ref, url.Values{"active": {"false"}}, "", nil)
	if missing(err) && l.InMode() == s.Mode() {
		return nil
	}
	return err
}

// maxSellingPages bounds how far the list of what sells is read: a hundred
// links a page, so a hundred thousand links, well past the most a book
// keeps, with room for links somebody made at Stripe by hand.
const maxSellingPages = 1000

// Selling is the ids of the payment links that sell at Stripe for this key.
//
// One list of every active link, a hundred at a time, rather than a
// question for each link: a sync runs after every publish, and a shop of a
// thousand products would otherwise ask a thousand times. A key sees only
// its own account and mode, so a link the test key made is not on the list
// the live key reads, and is made again.
func (s *Stripe) Selling(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	after := ""
	for range maxSellingPages {
		q := url.Values{"active": {"true"}, "limit": {"100"}}
		if after != "" {
			q.Set("starting_after", after)
		}
		var page struct {
			Data []struct {
				ID     string `json:"id"`
				Active bool   `json:"active"`
			} `json:"data"`
			HasMore bool `json:"has_more"`
		}
		if err := s.call(ctx, http.MethodGet, "/v1/payment_links", q, "", &page); err != nil {
			return nil, err
		}
		for _, d := range page.Data {
			if d.Active {
				out[d.ID] = true
			}
		}
		if !page.HasMore || len(page.Data) == 0 {
			return out, nil
		}
		after = page.Data[len(page.Data)-1].ID
	}
	return nil, fmt.Errorf("more than %d payment links sell at Stripe, which is more than this reads to find its own", maxSellingPages*100)
}

// Orders are the most recent completed checkouts, newest first.
func (s *Stripe) Orders(ctx context.Context, limit int) ([]Order, error) {
	if limit < 1 || limit > 100 {
		limit = 25
	}
	var page struct {
		Data []struct {
			ID              string `json:"id"`
			Created         int64  `json:"created"`
			AmountTotal     int64  `json:"amount_total"`
			Currency        string `json:"currency"`
			PaymentStatus   string `json:"payment_status"`
			PaymentLink     string `json:"payment_link"`
			CustomerDetails *struct {
				Email string `json:"email"`
				Name  string `json:"name"`
			} `json:"customer_details"`
			ShippingDetails *struct {
				Name    string  `json:"name"`
				Address address `json:"address"`
			} `json:"shipping_details"`
		} `json:"data"`
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}, "status": {"complete"}}
	if err := s.call(ctx, http.MethodGet, "/v1/checkout/sessions", q, "", &page); err != nil {
		return nil, err
	}
	out := make([]Order, 0, len(page.Data))
	for _, d := range page.Data {
		o := Order{Ref: d.ID, At: time.Unix(d.Created, 0).UTC(), Amount: d.AmountTotal,
			Currency: strings.ToUpper(d.Currency), Paid: d.PaymentStatus == "paid", Link: d.PaymentLink}
		if d.CustomerDetails != nil {
			o.Name, o.Email = d.CustomerDetails.Name, d.CustomerDetails.Email
		}
		if d.ShippingDetails != nil {
			o.Ship = d.ShippingDetails.Address.line(d.ShippingDetails.Name)
		}
		out = append(out, o)
	}
	return out, nil
}

// address is a delivery address as Stripe sends one.
type address struct {
	Line1      string `json:"line1"`
	Line2      string `json:"line2"`
	City       string `json:"city"`
	State      string `json:"state"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

func (a address) line(name string) string {
	var parts []string
	for _, p := range []string{name, a.Line1, a.Line2, a.City, a.State, a.PostalCode, a.Country} {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ", ")
}
