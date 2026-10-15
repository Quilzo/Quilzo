// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package commerce

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/crawl"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/throttle"
)

// The service: carts, checkout sessions and orders over a shop's records,
// spoken to over UCP's REST binding by agents identified with Web Bot Auth.
//
// # Where the state lives, and why
//
// A cart is a conversation between an agent and a shop about prices that
// are true now, and prices are re-read from the records at every turn — so
// a cart holds ids and quantities and nothing the caller said about money.
// Carts and sessions are memory: a process restart ends them, they expire
// within the hour anyway, and an agent that gets not_found makes a new one.
// Orders are different in kind. An order is a thing that happened, named by
// a record nobody can edit from outside, persisted with the same
// write-under-lock discipline internal/spend's book uses, and load-bearing
// for replay protection: which mandates have been used lives beside them.
//
// # Sizes, and why they are small
//
// Every map here is reachable from the internet with nothing but a valid
// signature, so every one is bounded: carts per agent, lines per cart,
// characters per key, bytes per body. A service that cannot be filled up is
// a service that cannot be asked to fall over (NIST SP 800-53 SC-5), and
// the bounds are the boring kind of control that works.
type Service struct {
	// PayeeName and PayeeWebsite are this shop's identity, as a payment
	// mandate's payee must name it.
	PayeeName, PayeeWebsite string
	// Merchant signs checkouts. Required before a checkout session may be
	// created: without a merchant signature there is nothing to bind a
	// mandate to, and a checkout that cannot be bound to is a checkout that
	// authorises nothing.
	Merchant *MerchantKey
	// Agents are the shopping agents this shop serves, by their Web Bot
	// Auth keys.
	Agents []crawl.Key
	// Issuers are whose mandate signatures this shop accepts.
	Issuers []IssuerKey
	// Rows resolves the products the catalogue listing exposes, fresh. The
	// host wires it to the same listing /catalogue.json serves.
	Rows func() ([]listing.Row, error)
	// Path persists orders. Empty keeps them in memory, which is for tests.
	Path string
	// Limit throttles per agent and source. Nil is unlimited, which is only
	// right in a test.
	Limit *throttle.Limiter
	// Audit records that something happened, without recording a mandate's
	// contents: a mandate is personal data about what a person allows, and
	// the log's job is to name the order and the parties, not to keep a
	// second copy of the credential.
	Audit func(event, detail string)

	// Now is the clock, overridable in tests.
	Now func() time.Time

	mu       sync.Mutex
	carts    map[string]*Cart
	sessions map[string]*Checkout
	byCart   map[string]string
	idem     map[string]idemEntry
	orders   []Order
	used     map[string]string
}

// CartTTL is how long a cart or checkout session lives untouched.
const CartTTL = time.Hour

// The bounds. CartsMaxPerAgent stops one agent filling memory with carts;
// LinesMax bounds a cart's replacement body; OrdersKept is how many order
// records are kept in the file, oldest beyond it dropped — the audit log
// keeps every act, as it does for receipts in internal/spend.
const (
	CartsMaxPerAgent = 8
	LinesMax         = 50
	OrdersKept       = 5000
)

// MaxBody bounds the request bodies this service will read.
const MaxBody = 256 << 10

// Cart is one priced basket.
type Cart struct {
	ID        string
	Currency  string
	Lines     []Line
	ExpiresAt time.Time
	Created   time.Time
	Agent     string
	Cancelled bool
}

// Line is one product at one quantity, priced by this shop.
type Line struct {
	ItemID     string `json:"item_id"`
	Title      string `json:"title"`
	SKU        string `json:"sku,omitempty"`
	UnitAmount int64  `json:"unit_amount"`
	Quantity   int    `json:"quantity"`
	Amount     int64  `json:"amount"`
}

// Total is one named figure of a cart or checkout.
type Total struct {
	Type    string `json:"type"`
	Amount  int64  `json:"amount"`
	Display string `json:"display_text,omitempty"`
}

// Checkout is one session that can become an order.
type Checkout struct {
	ID        string
	CartID    string
	Status    string // ready_for_complete, completed, canceled
	Currency  string
	Lines     []Line
	Totals    []Total
	Total     int64
	JWT       string // the merchant-signed checkout a mandate binds to
	Created   time.Time
	ExpiresAt time.Time
	OrderID   string
	Agent     string
}

// OrderMandate is what the order record keeps about a presented mandate:
// what it was, who signed it, and the digest that identifies the
// presentation. The mandate itself is not kept — an order record that
// accumulated credentials would be a wallet.
type OrderMandate struct {
	Vct           string `json:"vct"`
	Issuer        string `json:"issuer"`
	Digest        string `json:"digest"`
	TransactionID string `json:"transaction_id,omitempty"`
	KeyBound      bool   `json:"key_bound"`
	PayeeName     string `json:"payee_name,omitempty"`
	PayeeWebsite  string `json:"payee_website,omitempty"`
	Instrument    string `json:"instrument,omitempty"`
}

// Order is one order placed by one identified agent.
type Order struct {
	ID         string        `json:"id"`
	At         time.Time     `json:"at"`
	Agent      string        `json:"agent"`
	AgentKey   string        `json:"agent_key,omitempty"`
	Platform   string        `json:"platform,omitempty"`
	CheckoutID string        `json:"checkout_id"`
	Currency   string        `json:"currency"`
	Total      int64         `json:"total"`
	Lines      []Line        `json:"lines"`
	CheckoutM  *OrderMandate `json:"checkout_mandate,omitempty"`
	PaymentM   *OrderMandate `json:"payment_mandate,omitempty"`
	// PaymentState is "authorized" when a payment mandate verified, or
	// "none_presented". Neither captures money: this records what was
	// presented, and the money is the operator's to take.
	PaymentState string `json:"payment_state"`
	Status       string `json:"status"`
}

type orderFile struct {
	Orders []Order           `json:"orders"`
	Used   map[string]string `json:"used"`
}

type idemEntry struct {
	Status  int
	Body    []byte
	Digest  string
	Expires time.Time
}

// Init loads persisted orders and readies the maps. It is where the clock
// and the empty maps are set, so a Service built by hand in a test works
// the same as one the host builds.
func (s *Service) Init() error {
	s.carts = map[string]*Cart{}
	s.sessions = map[string]*Checkout{}
	s.byCart = map[string]string{}
	s.idem = map[string]idemEntry{}
	s.used = map[string]string{}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Path == "" {
		return nil
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // A first run: nothing has been ordered yet.
		}
		return err
	}
	var f orderFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("%s is not an order book: %w", s.Path, err)
	}
	s.orders, s.used = f.Orders, f.Used
	if s.used == nil {
		s.used = map[string]string{}
	}
	return nil
}

// save writes the order book under its lock, the way the spending book is
// written: one writer at a time, the file replaced atomically.
func (s *Service) save() error {
	if s.Path == "" {
		return nil
	}
	data, err := json.MarshalIndent(orderFile{Orders: s.orders, Used: s.used}, "", "  ")
	if err != nil {
		return err
	}
	unlock, err := atomicfile.Lock(s.Path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	return atomicfile.Write(s.Path, data, 0o600)
}

// ordersPath names the file a root's orders live in.
func OrdersPath(root string) string { return root + "/orders.json" }

func randomID(prefix string, n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func (s *Service) now() time.Time { return s.Now().UTC() }

// sweep drops what has expired, so the maps stay the size of the living
// conversation however often agents walk away mid-basket.
func (s *Service) sweep(now time.Time) {
	for id, c := range s.carts {
		if now.After(c.ExpiresAt) {
			if sid, ok := s.byCart[id]; ok {
				delete(s.sessions, sid)
				delete(s.byCart, id)
			}
			delete(s.carts, id)
		}
	}
	for id, cs := range s.sessions {
		if now.After(cs.ExpiresAt) && cs.Status != "completed" {
			delete(s.sessions, id)
		}
	}
	for k, e := range s.idem {
		if now.After(e.Expires) {
			delete(s.idem, k)
		}
	}
}

// products reads and shapes the catalogue, returning the products and the
// problems found in records that could not be shaped.
func (s *Service) products() ([]Product, []string, error) {
	rows, err := s.Rows()
	if err != nil {
		return nil, nil, err
	}
	out := make([]Product, 0, len(rows))
	var problems []string
	for _, row := range rows {
		p, problem := FromRow(row)
		if problem != "" {
			problems = append(problems, problem)
			continue
		}
		out = append(out, p)
	}
	return out, problems, nil
}

// find prices one product by its id, from fresh records.
func (s *Service) find(id string) (Product, bool, error) {
	products, _, err := s.products()
	if err != nil {
		return Product{}, false, err
	}
	for _, p := range products {
		if p.ID == id {
			return p, true, nil
		}
	}
	return Product{}, false, nil
}

// price builds the lines of a cart or session from requested items against
// fresh records: the price is read here or nowhere, availability is checked
// here or the line is refused, and a cart whose items are in two currencies
// is two carts the caller must make separately.
func (s *Service) price(items []lineRequest, when time.Time) ([]Line, string, string) {
	var lines []Line
	currency := ""
	for i, item := range items {
		p, ok, err := s.find(item.Item.ID)
		if err != nil {
			return nil, "", "the catalogue could not be read"
		}
		if !ok {
			return nil, "", fmt.Sprintf("$.line_items[%d]: no product %q", i, item.Item.ID)
		}
		if item.Quantity < 1 || item.Quantity > 999 {
			return nil, "", fmt.Sprintf("$.line_items[%d]: the quantity is not between 1 and 999", i)
		}
		if currency == "" {
			currency = p.PriceRange.Min.Currency
		} else if currency != p.PriceRange.Min.Currency {
			return nil, "", "these items are priced in more than one currency, and a cart is one currency"
		}
		available := true
		if len(p.Variants) > 0 && p.Variants[0].Availability != nil {
			available = p.Variants[0].Availability.Available
		}
		if !available {
			return nil, "", fmt.Sprintf("$.line_items[%d]: %s is sold out", i, p.Title)
		}
		v := p.Variants[0]
		lines = append(lines, Line{
			ItemID: p.ID, Title: p.Title, SKU: v.SKU,
			UnitAmount: v.Price.Amount, Quantity: item.Quantity,
			Amount: v.Price.Amount * int64(item.Quantity),
		})
	}
	return lines, currency, ""
}

// totalsOf states a basket's figures: the subtotal of the lines and the
// total, which are the same number because this shop neither taxes nor
// ships in code. Tax and delivery are real charges a real shop computes
// from a jurisdiction and a carrier; inventing a number here would be the
// one figure in this program no record stands behind.
func totalsOf(currency string, lines []Line) ([]Total, int64) {
	var sum int64
	for _, l := range lines {
		sum += l.Amount
	}
	return []Total{
		{Type: "subtotal", Amount: sum},
		{Type: "total", Amount: sum},
	}, sum
}

// lineRequest is one requested item in a cart's creation or replacement.
type lineRequest struct {
	Item struct {
		ID string `json:"id"`
	} `json:"item"`
	Quantity int `json:"quantity"`
}

// Request shapes, decoded strictly: a field this program did not define,
// sent by a caller this program did not design for, is refused rather than
// guessed at (NIST SP 800-53 SI-10).
type cartRequest struct {
	LineItems []lineRequest `json:"line_items"`
	Context   *struct {
		Currency string `json:"currency"`
	} `json:"context"`
}

type searchRequest struct {
	Query      string `json:"query"`
	Pagination *struct {
		Limit  int    `json:"limit"`
		Cursor string `json:"cursor"`
	} `json:"pagination"`
}

type lookupRequest struct {
	IDs []string `json:"ids"`
}

type productRequest struct {
	ID string `json:"id"`
}

type checkoutRequest struct {
	CartID string `json:"cart_id"`
}

type completeRequest struct {
	CheckoutMandate string `json:"checkout_mandate"`
	PaymentMandate  string `json:"payment_mandate"`
}

// decode reads a bounded JSON body into one of the shapes above.
func decode(w http.ResponseWriter, r *http.Request, into any) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	return nil
}

// writeJSON writes a response with the envelope's version and status.
func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	ucp, _ := body["ucp"].(map[string]any)
	if ucp == nil {
		ucp = map[string]any{}
	}
	ucp["version"] = UCPVersion
	if _, said := ucp["status"]; !said {
		ucp["status"] = "success"
	}
	body["ucp"] = ucp
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// transportError answers with an HTTP status and the UCP error body.
func transportError(w http.ResponseWriter, status int, code, content string) {
	writeJSON(w, status, map[string]any{
		"ucp":   map[string]any{"status": "error"},
		"error": map[string]string{"code": code, "content": content},
	})
}

// businessError answers 200 with a message, the UCP convention for an
// outcome that is the shop's answer rather than the transport's.
func businessError(w http.ResponseWriter, messages ...map[string]any) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ucp":      map[string]any{"status": "error"},
		"messages": messages,
	})
}

// cartJSON is a cart in UCP's shape.
func (c *Cart) cartJSON() map[string]any {
	totals, _ := totalsOf(c.Currency, c.Lines)
	items := make([]map[string]any, 0, len(c.Lines))
	for _, l := range c.Lines {
		item := map[string]any{
			"id": l.ItemID, "title": l.Title,
			"price": map[string]any{"amount": l.UnitAmount, "currency": c.Currency},
		}
		if l.SKU != "" {
			item["sku"] = l.SKU
		}
		items = append(items, map[string]any{
			"item": item, "quantity": l.Quantity,
			"totals": []map[string]any{{"type": "total", "amount": l.Amount}},
		})
	}
	return map[string]any{
		"id": c.ID, "line_items": items, "currency": c.Currency,
		"totals": totals, "expires_at": c.ExpiresAt.Format(time.RFC3339),
	}
}

// checkoutJSON is a checkout session in UCP's shape, with the
// merchant-signed JWT an agent binds its mandates to.
func (c *Checkout) checkoutJSON() map[string]any {
	items := make([]map[string]any, 0, len(c.Lines))
	for _, l := range c.Lines {
		items = append(items, map[string]any{
			"item_id": l.ItemID, "title": l.Title, "sku": l.SKU,
			"quantity": l.Quantity, "unit_amount": l.UnitAmount,
			"amount": l.Amount,
		})
	}
	return map[string]any{
		"id": c.ID, "status": c.Status, "currency": c.Currency,
		"line_items": items, "totals": c.Totals,
		"checkout_jwt": c.JWT, "expires_at": c.ExpiresAt.Format(time.RFC3339),
	}
}

// orderJSON is an order in the shape completion answers with.
func (o *Order) orderJSON() map[string]any {
	return map[string]any{
		"id": o.ID, "status": o.Status, "checkout_id": o.CheckoutID,
		"currency": o.Currency, "total": o.Total,
		"payment_state": o.PaymentState, "at": o.At.Format(time.RFC3339),
	}
}

// Discover serves the public profile at /.well-known/ucp: what this shop
// can do, where to do it, and the key that verifies its checkouts.
func (s *Service) Discover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		transportError(w, http.StatusMethodNotAllowed, "method", "GET only")
		return
	}
	capabilities := map[string]any{
		"dev.ucp.shopping.catalog.search": map[string]any{},
		"dev.ucp.shopping.catalog.lookup": map[string]any{},
		"dev.ucp.shopping.cart":           map[string]any{},
		"dev.ucp.shopping.checkout":       map[string]any{},
	}
	body := map[string]any{
		"name": s.PayeeName, "website": s.PayeeWebsite,
		"rest":         map[string]any{"endpoint": "/ucp"},
		"capabilities": capabilities,
		// What this shop accepts as payment authorisation: an AP2 mandate,
		// checked when presented. It is a list of one because a list of one
		// is honest, and a handler named "card" here would be a promise
		// about a processor this program does not have.
		"payment_handlers": []string{"ap2-mandate"},
		"authentication": map[string]any{
			"scheme": "web-bot-auth",
			"keys":   "/.well-known/http-message-signatures-directory",
		},
	}
	if s.Merchant != nil {
		body["merchant_key"] = s.Merchant.PublicJWK()
	}
	writeJSON(w, http.StatusOK, body)
}

// ServeHTTP dispatches /ucp/ requests.
//
// Every request under this path is identified first: a Web Bot Auth
// signature from a configured agent, or no service at all. The discovery
// document is public because it is an advertisement, not a capability.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/ucp")
	rest = strings.Trim(rest, "/")
	now := s.now()

	identity, code, content := s.identify(r, now)
	if identity == nil {
		transportError(w, http.StatusUnauthorized, code, content)
		return
	}
	// The two headers the REST binding makes mandatory on every request.
	//
	// Request-Id is echoed (bounded) so a caller can follow one request
	// through its own logs; UCP-Agent names the platform's profile, and a
	// request without one is refused rather than served unnamed — the
	// binding says MUST, and a rule the verifier does not enforce is a
	// suggestion, which is not what a protocol's name for its caller is.
	rid := strings.TrimSpace(r.Header.Get("Request-Id"))
	if rid == "" || len(rid) > 128 {
		transportError(w, http.StatusBadRequest, "request_id",
			"every request carries a Request-Id of at most 128 characters")
		return
	}
	w.Header().Set("Request-Id", rid)
	agentHeader := strings.TrimSpace(r.Header.Get("UCP-Agent"))
	if agentHeader == "" || len(agentHeader) > 512 {
		transportError(w, http.StatusBadRequest, "ucp_agent",
			"every request carries a UCP-Agent header naming the platform's "+
				"profile, as an RFC 8941 dictionary")
		return
	}
	// The agent's platform, as it claims it. Recorded on the order beside
	// the verified identity, and never mistaken for it.
	ctx := request{Agent: identity, Platform: profileOf(agentHeader),
		Source: clientSource(r)}

	s.mu.Lock()
	s.sweep(now)
	s.mu.Unlock()

	switch {
	case rest == "catalog/search" && r.Method == http.MethodPost:
		s.handleSearch(w, r)
	case rest == "catalog/lookup" && r.Method == http.MethodPost:
		s.handleLookup(w, r)
	case rest == "catalog/product" && r.Method == http.MethodPost:
		s.handleProduct(w, r)
	case rest == "carts" && r.Method == http.MethodPost:
		s.withIdempotency(w, r, ctx, now, s.createCart)
	case strings.HasPrefix(rest, "carts/") && r.Method == http.MethodGet:
		s.getCart(w, r, ctx, strings.TrimPrefix(rest, "carts/"))
	case strings.HasPrefix(rest, "carts/") && r.Method == http.MethodPut:
		s.withIdempotency(w, r, ctx, now, s.replaceCart)
	case strings.HasPrefix(rest, "carts/") && strings.HasSuffix(rest, "/cancel") &&
		r.Method == http.MethodPost:
		s.withIdempotency(w, r, ctx, now, s.cancelCart)
	case rest == "checkout-sessions" && r.Method == http.MethodPost:
		s.withIdempotency(w, r, ctx, now, s.createCheckout)
	case strings.HasPrefix(rest, "checkout-sessions/") &&
		strings.HasSuffix(rest, "/complete") && r.Method == http.MethodPost:
		s.withIdempotency(w, r, ctx, now, s.completeCheckout)
	case strings.HasPrefix(rest, "checkout-sessions/") &&
		strings.HasSuffix(rest, "/cancel") && r.Method == http.MethodPost:
		s.withIdempotency(w, r, ctx, now, s.cancelCheckout)
	case strings.HasPrefix(rest, "checkout-sessions/") && r.Method == http.MethodGet:
		s.getCheckout(w, r, ctx, strings.TrimPrefix(rest, "checkout-sessions/"))
	default:
		transportError(w, http.StatusNotFound, "not_found",
			"no such operation on this shop's UCP endpoint")
	}
}

// request is what one identified call carries with it.
type request struct {
	Agent    *crawl.Identity
	Platform string
	Source   string
}
