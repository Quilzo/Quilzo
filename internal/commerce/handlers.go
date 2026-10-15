// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package commerce

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/crawl"
	"github.com/quilzo/quilzo/internal/throttle"
)

// The handlers: one per UCP operation, each behind the identity gate and
// the idempotency wrapper, each reading prices from the records and never
// from the request.

// identify verifies the caller's Web Bot Auth signature and applies the
// rate limit.
//
// A request with no signature at all and a request whose signature does not
// verify are both refused, with words that distinguish them because an
// operator reading logs needs to know which is happening (NIST SP 800-207:
// per-request authentication, no implicit trust from reachability). The
// rate limit is per verified identity and source, not per address alone —
// one agent misbehaving should not throttle another's name.
func (s *Service) identify(r *http.Request, now time.Time) (*crawl.Identity, string, string) {
	identity, err := crawl.Verify(r, s.Agents, now)
	if err != nil {
		return nil, "unauthenticated", fmt.Sprintf(
			"this shop serves agents that identify themselves with Web Bot "+
				"Auth, and this signature did not verify: %v", err)
	}
	if identity == nil {
		return nil, "unauthenticated",
			"this shop serves agents that identify themselves with Web Bot " +
				"Auth: sign the request with a key this shop has configured"
	}
	if s.Limit != nil {
		if d := s.Limit.Check(throttle.Subject{
			Principal: "agent:" + identity.Name, Source: clientSource(r)}); !d.Allowed {
			return nil, "rate_limited", "too many requests from this agent; " +
				"retry after the window"
		}
	}
	return identity, "", ""
}

// clientSource is where the request came from, best known.
func clientSource(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// reProfile pulls the profile URL out of a UCP-Agent dictionary value.
//
// RFC 8941 structure, read leniently: the value is recorded on the order as
// a claim the agent made, and a malformed dictionary is a missing claim
// rather than a refused request — the verified identity is what authorises,
// and this is decoration beside it.
func profileOf(v string) string {
	re := regexp.MustCompile(`profile="([^"]*)"`)
	if m := re.FindStringSubmatch(v); m != nil && len(m[1]) <= 512 {
		return m[1]
	}
	return ""
}

// withIdempotency runs a state-changing handler under the UCP rule: the
// same Idempotency-Key with the same body returns the stored answer, the
// same key with a different body is a 409, and the memory of a key outlives
// the request by a day, which is the spec's floor of 24 hours.
func (s *Service) withIdempotency(w http.ResponseWriter, r *http.Request, ctx request,
	now time.Time, fn func(w http.ResponseWriter, r *http.Request, ctx request, body []byte, now time.Time)) {

	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		transportError(w, http.StatusBadRequest, "idempotency_key",
			"state-changing operations need an Idempotency-Key")
		return
	}
	if len(key) > 128 {
		transportError(w, http.StatusBadRequest, "idempotency_key",
			"the Idempotency-Key is longer than 128 characters")
		return
	}
	body, err := readBody(w, r)
	if err != nil {
		transportError(w, http.StatusBadRequest, "body", "the request body could not be read")
		return
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	s.mu.Lock()
	if prior, ok := s.idem[key]; ok {
		if now.After(prior.Expires) {
			delete(s.idem, key)
		} else {
			s.mu.Unlock()
			if prior.Digest != digest {
				transportError(w, http.StatusConflict, "idempotency_key",
					"this Idempotency-Key was used with a different body")
				return
			}
			if prior.Status == 0 {
				// The first request with this key is still running. An
				// answer has not been made yet, so there is nothing to
				// replay: rather than return an empty success for an order
				// that may not exist, say the key is taken and let the
				// caller retry.
				transportError(w, http.StatusConflict, "idempotency_key",
					"this Idempotency-Key is still being processed; retry shortly")
				return
			}
			// The stored answer, replayed as the spec requires: a retried
			// request after a timeout must not place a second order.
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(prior.Status)
			_, _ = w.Write(prior.Body)
			return
		}
	}
	// Reserve the key before running, so a concurrent double-submit finds it
	// held rather than racing through. The entry is completed by remember().
	s.idem[key] = idemEntry{Digest: digest, Expires: now.Add(24 * time.Hour)}
	s.mu.Unlock()

	rec := recorder{ResponseWriter: w}
	fn(&rec, r, ctx, body, now)
	s.remember(key, digest, now, rec.status, rec.buf.Bytes())
}

// remember completes an idempotency reservation with the answer that was
// given, and keeps only answers worth replaying: a transport-level refusal
// before any state changed is not one, so the key stays free for a corrected
// retry.
func (s *Service) remember(key, digest string, now time.Time, status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status < 200 || status >= 500 ||
		(status == http.StatusOK && strings.Contains(string(body), `"status":"error"`)) {
		delete(s.idem, key)
		return
	}
	s.idem[key] = idemEntry{Status: status, Body: append([]byte(nil), body...),
		Digest: digest, Expires: now.Add(24 * time.Hour)}
}

// recorder captures what was written, for idempotent replay.
type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (rec *recorder) WriteHeader(status int) {
	rec.status = status
	rec.ResponseWriter.WriteHeader(status)
}

func (rec *recorder) Write(b []byte) (int, error) {
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	rec.buf.Write(b)
	return rec.ResponseWriter.Write(b)
}

// readBody reads a bounded body.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	return io.ReadAll(r.Body)
}

// handleSearch answers the catalogue, newest knowledge first.
func (s *Service) handleSearch(w http.ResponseWriter, r *http.Request) {
	var req searchRequest
	if err := decode(w, r, &req); err != nil {
		transportError(w, http.StatusBadRequest, "request", "the search request could not be read: "+
			err.Error())
		return
	}
	products, problems, err := s.products()
	if err != nil {
		transportError(w, http.StatusServiceUnavailable, "catalogue",
			"the catalogue could not be read")
		return
	}
	// A query narrows by substring on title and summary: the listing's own
	// parameters remain the deep filtering, and free text here is a
	// convenience read against the same shaped rows.
	if q := strings.ToLower(strings.TrimSpace(req.Query)); q != "" {
		var kept []Product
		for _, p := range products {
			hay := strings.ToLower(p.Title + " ")
			if p.Description != nil {
				hay += p.Description.Plain
			}
			if strings.Contains(hay, q) {
				kept = append(kept, p)
			}
		}
		products = kept
	}
	limit, cursor := 20, 0
	if req.Pagination != nil {
		if req.Pagination.Limit > 0 && req.Pagination.Limit <= 100 {
			limit = req.Pagination.Limit
		}
		if req.Pagination.Cursor != "" {
			// The cursor is the string this shop handed back — an offset
			// into the listing, counted in whole products. A cursor is a
			// position, not a number to trust: bounds-checked, and refused
			// when it is not one of this catalogue's own.
			n, err := strconv.Atoi(req.Pagination.Cursor)
			if err != nil || n < 0 || n > len(products) {
				transportError(w, http.StatusBadRequest, "pagination",
					"the cursor is not a position in this catalogue")
				return
			}
			cursor = n
		}
	}
	end := cursor + limit
	if end > len(products) {
		end = len(products)
	}
	page := products[cursor:end]
	body := map[string]any{"products": page}
	var messages []map[string]any
	for _, p := range problems {
		messages = append(messages, map[string]any{
			"type": "warning", "code": "record_problem", "content": p,
		})
	}
	if len(messages) > 0 {
		body["messages"] = messages
	}
	pg := map[string]any{"total_count": len(products)}
	if end < len(products) {
		pg["cursor"] = fmt.Sprint(end)
		pg["has_next_page"] = true
	}
	body["pagination"] = pg
	writeJSON(w, http.StatusOK, body)
}

// handleLookup answers products by id, with unknown ids as messages rather
// than absence — a batch lookup that silently shrank teaches an agent to
// trust incomplete answers.
func (s *Service) handleLookup(w http.ResponseWriter, r *http.Request) {
	var req lookupRequest
	if err := decode(w, r, &req); err != nil {
		transportError(w, http.StatusBadRequest, "request", "the lookup request could not be read: "+
			err.Error())
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 100 {
		transportError(w, http.StatusBadRequest, "request_too_large",
			"lookup takes between 1 and 100 ids")
		return
	}
	products, _, err := s.products()
	if err != nil {
		transportError(w, http.StatusServiceUnavailable, "catalogue",
			"the catalogue could not be read")
		return
	}
	byID := map[string]Product{}
	for _, p := range products {
		byID[p.ID] = p
	}
	var found []Product
	var messages []map[string]any
	for _, id := range req.IDs {
		if p, ok := byID[id]; ok {
			found = append(found, p)
		} else {
			messages = append(messages, map[string]any{
				"type": "info", "code": "not_found", "content": id,
			})
		}
	}
	body := map[string]any{"products": found}
	if len(messages) > 0 {
		body["messages"] = messages
	}
	writeJSON(w, http.StatusOK, body)
}

// handleProduct answers one product in full.
func (s *Service) handleProduct(w http.ResponseWriter, r *http.Request) {
	var req productRequest
	if err := decode(w, r, &req); err != nil {
		transportError(w, http.StatusBadRequest, "request", "the product request could not be read: "+
			err.Error())
		return
	}
	p, ok, err := s.find(req.ID)
	if err != nil {
		transportError(w, http.StatusServiceUnavailable, "catalogue",
			"the catalogue could not be read")
		return
	}
	if !ok {
		businessError(w, map[string]any{
			"type": "error", "code": "not_found", "content": req.ID,
			"severity": "unrecoverable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"product": p})
}

// createCart prices a new basket.
func (s *Service) createCart(w http.ResponseWriter, r *http.Request, ctx request, body []byte, now time.Time) {
	var req cartRequest
	if err := decodeBytes(body, &req); err != nil {
		transportError(w, http.StatusBadRequest, "request", "the cart could not be read: "+err.Error())
		return
	}
	if len(req.LineItems) == 0 || len(req.LineItems) > LinesMax {
		transportError(w, http.StatusBadRequest, "request",
			fmt.Sprintf("a cart has between 1 and %d line items", LinesMax))
		return
	}
	// A requested context.currency is noted and not used to convert: this
	// shop sells in the currencies its records carry, and a conversion this
	// program invented would be a price no record stands behind.
	lines, currency, problem := s.price(req.LineItems, now)
	if problem != "" {
		businessError(w, map[string]any{
			"type": "error", "code": "line_item", "content": problem,
			"severity": "recoverable",
		})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	live := 0
	for _, c := range s.carts {
		if c.Agent == ctx.Agent.Name && !c.Cancelled {
			live++
		}
	}
	if live >= CartsMaxPerAgent {
		businessError(w, map[string]any{
			"type": "error", "code": "too_many_carts",
			"content":  fmt.Sprintf("this agent has %d live carts; cancel one first", live),
			"severity": "recoverable",
		})
		return
	}
	id, err := randomID("ct_", 16)
	if err != nil {
		transportError(w, http.StatusInternalServerError, "internal", "no entropy for a cart id")
		return
	}
	cart := &Cart{ID: id, Currency: currency, Lines: lines,
		ExpiresAt: now.Add(CartTTL), Created: now, Agent: ctx.Agent.Name}
	s.carts[id] = cart
	if s.Audit != nil {
		s.Audit("cart.created", ctx.Agent.Name+" "+id)
	}
	writeJSON(w, http.StatusCreated, cart.cartJSON())
}

// replaceCart replaces a cart's contents wholesale, the UCP update rule.
func (s *Service) replaceCart(w http.ResponseWriter, r *http.Request, ctx request, body []byte, now time.Time) {
	id := strings.TrimPrefix(r.URL.Path, "/ucp/carts/")
	var req cartRequest
	if err := decodeBytes(body, &req); err != nil {
		transportError(w, http.StatusBadRequest, "request", "the cart could not be read: "+err.Error())
		return
	}
	if len(req.LineItems) == 0 || len(req.LineItems) > LinesMax {
		transportError(w, http.StatusBadRequest, "request",
			fmt.Sprintf("a cart has between 1 and %d line items", LinesMax))
		return
	}
	lines, currency, problem := s.price(req.LineItems, now)
	if problem != "" {
		businessError(w, map[string]any{
			"type": "error", "code": "line_item", "content": problem,
			"severity": "recoverable",
		})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cart, ok := s.ownCart(id, ctx.Agent.Name, now)
	if !ok {
		businessError(w, map[string]any{
			"type": "error", "code": "not_found", "content": id,
			"severity": "unrecoverable",
		})
		return
	}
	// A cart that already became a checkout is not editable: the session was
	// signed, and a mutation after signing is exactly what the signature
	// exists to make detectable.
	if _, session := s.byCart[id]; session {
		businessError(w, map[string]any{
			"type": "error", "code": "checkout_started",
			"content":  "this cart has a checkout session; cancel it to change the basket",
			"severity": "recoverable",
		})
		return
	}
	cart.Lines, cart.Currency = lines, currency
	cart.ExpiresAt = now.Add(CartTTL)
	writeJSON(w, http.StatusOK, cart.cartJSON())
}

// getCart answers a cart.
func (s *Service) getCart(w http.ResponseWriter, r *http.Request, ctx request, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cart, ok := s.ownCart(id, ctx.Agent.Name, s.now())
	if !ok {
		businessError(w, map[string]any{
			"type": "error", "code": "not_found", "content": id,
			"severity": "unrecoverable",
		})
		return
	}
	writeJSON(w, http.StatusOK, cart.cartJSON())
}

// cancelCart answers the cart's state and removes it.
func (s *Service) cancelCart(w http.ResponseWriter, r *http.Request, ctx request, body []byte, now time.Time) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/ucp/carts/"), "/cancel")
	s.mu.Lock()
	defer s.mu.Unlock()
	cart, ok := s.ownCart(id, ctx.Agent.Name, now)
	if !ok {
		businessError(w, map[string]any{
			"type": "error", "code": "not_found", "content": id,
			"severity": "unrecoverable",
		})
		return
	}
	cart.Cancelled = true
	delete(s.carts, id)
	if sid, has := s.byCart[id]; has {
		if cs, there := s.sessions[sid]; there && cs.Status == "ready_for_complete" {
			cs.Status = "canceled"
		}
		delete(s.byCart, id)
	}
	writeJSON(w, http.StatusOK, cart.cartJSON())
}

// liveCart finds a cart that is neither expired nor cancelled.
func (s *Service) liveCart(id string, now time.Time) (*Cart, bool) {
	c, ok := s.carts[id]
	if !ok || c.Cancelled || now.After(c.ExpiresAt) {
		return nil, false
	}
	return c, true
}

// ownCart finds a live cart that belongs to the agent asking. Another
// agent's cart is not_found to this one, not forbidden: a 403 would say
// that the id exists, and the carts of one shop are not each other's
// business. Least privilege is not only about what an agent may do, but
// about what of somebody else's it may even learn is there (SP 800-207).
func (s *Service) ownCart(id, agent string, now time.Time) (*Cart, bool) {
	c, ok := s.liveCart(id, now)
	if !ok || c.Agent != agent {
		return nil, false
	}
	return c, true
}

// ownCheckout finds a live session that belongs to the agent asking.
func (s *Service) ownCheckout(id, agent string, now time.Time) (*Checkout, bool) {
	cs, ok := s.liveCheckout(id, now)
	if !ok || cs.Agent != agent {
		return nil, false
	}
	return cs, true
}

// createCheckout binds a cart into a signed checkout session. Creating from
// the same cart twice returns the same session, per the spec's conversion
// rule — and because a second signature over a changed basket would be a
// second thing for a mandate to be bound to.
func (s *Service) createCheckout(w http.ResponseWriter, r *http.Request, ctx request, body []byte, now time.Time) {
	if s.Merchant == nil {
		transportError(w, http.StatusServiceUnavailable, "merchant_key",
			"this shop has no merchant key, so it cannot sign a checkout")
		return
	}
	var req checkoutRequest
	if err := decodeBytes(body, &req); err != nil {
		transportError(w, http.StatusBadRequest, "request", "the checkout request could not be read: "+
			err.Error())
		return
	}
	if req.CartID == "" {
		transportError(w, http.StatusBadRequest, "request", "cart_id is required")
		return
	}
	s.mu.Lock()
	cart, ok := s.ownCart(req.CartID, ctx.Agent.Name, now)
	if !ok {
		s.mu.Unlock()
		businessError(w, map[string]any{
			"type": "error", "code": "not_found", "content": req.CartID,
			"severity": "unrecoverable",
		})
		return
	}
	if sid, has := s.byCart[cart.ID]; has {
		if cs, there := s.sessions[sid]; there && cs.Status == "ready_for_complete" &&
			now.Before(cs.ExpiresAt) {
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, cs.checkoutJSON())
			return
		}
	}
	// Re-price under the lock, from fresh records: the basket an agent
	// assembled a minute ago is not the basket this shop signs now.
	lines, currency, problem := s.price(lineRequestsOf(cart.Lines), now)
	if problem != "" {
		s.mu.Unlock()
		businessError(w, map[string]any{
			"type": "error", "code": "line_item", "content": problem,
			"severity": "recoverable",
		})
		return
	}
	id, err := randomID("cs_", 12)
	if err != nil {
		s.mu.Unlock()
		transportError(w, http.StatusInternalServerError, "internal", "no entropy for a session id")
		return
	}
	expires := now.Add(CartTTL)
	totals, total := totalsOf(currency, lines)
	cs := &Checkout{ID: id, CartID: cart.ID, Status: "ready_for_complete",
		Currency: currency, Lines: lines, Totals: totals, Total: total,
		Created: now, ExpiresAt: expires, Agent: ctx.Agent.Name}
	jwt, err := s.Merchant.SignCheckout(cs.signedContents(), s.PayeeWebsite, now, expires)
	if err != nil {
		s.mu.Unlock()
		transportError(w, http.StatusInternalServerError, "internal", "the checkout could not be signed")
		return
	}
	cs.JWT = jwt
	s.sessions[id] = cs
	s.byCart[cart.ID] = id
	s.mu.Unlock()
	if s.Audit != nil {
		s.Audit("checkout.created", ctx.Agent.Name+" "+id)
	}
	writeJSON(w, http.StatusCreated, cs.checkoutJSON())
}

// lineRequestsOf rebuilds the request shape from a cart's lines, for
// re-pricing.
func lineRequestsOf(lines []Line) []lineRequest {
	out := make([]lineRequest, 0, len(lines))
	for _, l := range lines {
		var lr lineRequest
		lr.Item.ID = l.ItemID
		lr.Quantity = l.Quantity
		out = append(out, lr)
	}
	return out
}

// signedContents is the checkout object that gets signed.
func (c *Checkout) signedContents() map[string]any {
	items := make([]map[string]any, 0, len(c.Lines))
	for _, l := range c.Lines {
		items = append(items, map[string]any{
			"item_id": l.ItemID, "quantity": l.Quantity,
			"unit_amount": l.UnitAmount, "amount": l.Amount,
		})
	}
	return map[string]any{
		"vct": "checkout.merchant.1", "checkout_id": c.ID,
		"cart_id": c.CartID, "status": c.Status, "currency": c.Currency,
		"line_items": items, "totals": c.Totals, "total": c.Total,
	}
}

// getCheckout answers a session.
func (s *Service) getCheckout(w http.ResponseWriter, r *http.Request, ctx request, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.ownCheckout(id, ctx.Agent.Name, s.now())
	if !ok {
		businessError(w, map[string]any{
			"type": "error", "code": "not_found", "content": id,
			"severity": "unrecoverable",
		})
		return
	}
	writeJSON(w, http.StatusOK, cs.checkoutJSON())
}

// liveCheckout finds a session that is neither expired nor removed.
func (s *Service) liveCheckout(id string, now time.Time) (*Checkout, bool) {
	cs, ok := s.sessions[id]
	if !ok || now.After(cs.ExpiresAt) {
		return nil, false
	}
	return cs, true
}

// cancelCheckout cancels a session.
func (s *Service) cancelCheckout(w http.ResponseWriter, r *http.Request, ctx request, body []byte, now time.Time) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/ucp/checkout-sessions/"), "/cancel")
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.ownCheckout(id, ctx.Agent.Name, now)
	if !ok {
		businessError(w, map[string]any{
			"type": "error", "code": "not_found", "content": id,
			"severity": "unrecoverable",
		})
		return
	}
	if cs.Status != "ready_for_complete" {
		businessError(w, map[string]any{
			"type": "error", "code": "not_cancellable",
			"content":  "this checkout is already " + cs.Status,
			"severity": "unrecoverable",
		})
		return
	}
	cs.Status = "canceled"
	writeJSON(w, http.StatusOK, cs.checkoutJSON())
}

// completeCheckout is where everything converges: the mandates are
// verified, the stock is re-checked, and the order is recorded.
//
// The order of operations is deliberate. Identity and the signature over
// the body come first (a completion whose body was not signed is a
// completion anybody could have posted). The mandates are verified against
// the session's own signed JWT before any state changes. The stock is
// re-read from the records inside the lock, so a product that sold out
// between the agent's search and its completion is refused here rather than
// oversold. Only then is the order written and persisted, and the mandates'
// presentations recorded so a second use is a refusal, not a second order.
func (s *Service) completeCheckout(w http.ResponseWriter, r *http.Request, ctx request, body []byte, now time.Time) {
	if ctx.Agent.KeyID == "" || !ctx.Agent.BodySigned {
		transportError(w, http.StatusUnauthorized, "unauthenticated",
			"completing a checkout needs a Web Bot Auth signature that covers "+
				"the request body (RFC 9421 with a Content-Digest of it)")
		return
	}
	var req completeRequest
	if err := decodeBytes(body, &req); err != nil {
		transportError(w, http.StatusBadRequest, "request", "the completion could not be read: "+
			err.Error())
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/ucp/checkout-sessions/"), "/complete")

	// Whose session this is, before anything about it is verified or said.
	//
	// The order is the whole of a small decision: a mandate is bound to a
	// checkout's contents, and verifying one against a session a foreign
	// agent names would answer "different checkout" to that agent where a
	// stranger deserves "not_found" — an oracle that the id exists, paid for
	// by somebody else's credential. Ownership first, then the cryptography.
	sessionJWT, totals := "", int64(0)
	currency := ""
	{
		s.mu.Lock()
		cs, ok := s.ownCheckout(id, ctx.Agent.Name, now)
		if ok {
			sessionJWT, totals, currency = cs.JWT, cs.Total, cs.Currency
		}
		s.mu.Unlock()
		if !ok {
			businessError(w, map[string]any{
				"type": "error", "code": "not_found", "content": id,
				"severity": "unrecoverable",
			})
			return
		}
	}

	var checkoutFacts *CheckoutFacts
	var paymentFacts *PaymentFacts
	if req.CheckoutMandate != "" {
		f, err := VerifyCheckoutMandate(req.CheckoutMandate, sessionJWT, s.Issuers, now)
		if err != nil {
			businessError(w, map[string]any{
				"type": "error", "code": "checkout_mandate", "content": err.Error(),
				"severity": "unrecoverable",
			})
			return
		}
		checkoutFacts = &f
	}
	if req.PaymentMandate != "" {
		f, err := VerifyPaymentMandate(req.PaymentMandate, s.PayeeName, s.PayeeWebsite,
			totals, currency, s.Issuers, now)
		if err != nil {
			businessError(w, map[string]any{
				"type": "error", "code": "payment_mandate", "content": err.Error(),
				"severity": "unrecoverable",
			})
			return
		}
		paymentFacts = &f
	}

	s.mu.Lock()
	cs, ok := s.ownCheckout(id, ctx.Agent.Name, now)
	if !ok {
		s.mu.Unlock()
		businessError(w, map[string]any{
			"type": "error", "code": "not_found", "content": id,
			"severity": "unrecoverable",
		})
		return
	}
	if cs.Status != "ready_for_complete" {
		s.mu.Unlock()
		businessError(w, map[string]any{
			"type": "error", "code": "not_completable",
			"content":  "this checkout is " + cs.Status,
			"severity": "unrecoverable",
		})
		return
	}
	// Stock, re-read now, inside the lock.
	for _, l := range cs.Lines {
		p, found, err := s.find(l.ItemID)
		if err != nil || !found {
			s.mu.Unlock()
			transportError(w, http.StatusServiceUnavailable, "catalogue",
				"the catalogue could not be read to check this order")
			return
		}
		available := true
		if len(p.Variants) > 0 && p.Variants[0].Availability != nil {
			available = p.Variants[0].Availability.Available
		}
		if !available {
			s.mu.Unlock()
			businessError(w, map[string]any{
				"type": "error", "code": "out_of_stock",
				"content":  fmt.Sprintf("%s is sold out", p.Title),
				"severity": "unrecoverable",
			})
			return
		}
	}
	// A mandate presentation is spent once, and the spending is what a
	// replayed completion runs into.
	var spent []string
	if checkoutFacts != nil {
		if prior, used := s.used[checkoutFacts.Digest]; used {
			s.mu.Unlock()
			businessError(w, map[string]any{
				"type": "error", "code": "mandate_reused",
				"content":  "this checkout mandate already completed order " + prior,
				"severity": "unrecoverable",
			})
			return
		}
		spent = append(spent, checkoutFacts.Digest)
	}
	if paymentFacts != nil {
		if prior, used := s.used[paymentFacts.Digest]; used {
			s.mu.Unlock()
			businessError(w, map[string]any{
				"type": "error", "code": "mandate_reused",
				"content":  "this payment mandate already completed order " + prior,
				"severity": "unrecoverable",
			})
			return
		}
		spent = append(spent, paymentFacts.Digest)
	}
	orderID, err := randomID("od_", 12)
	if err != nil {
		s.mu.Unlock()
		transportError(w, http.StatusInternalServerError, "internal", "no entropy for an order id")
		return
	}
	order := Order{
		ID: orderID, At: now, Agent: ctx.Agent.Name, AgentKey: ctx.Agent.KeyID,
		Platform: ctx.Platform, CheckoutID: cs.ID, Currency: cs.Currency,
		Total: cs.Total, Lines: cs.Lines,
		PaymentState: "none_presented", Status: "placed",
	}
	if checkoutFacts != nil {
		order.CheckoutM = &OrderMandate{
			Vct: checkoutFacts.Vct, Issuer: checkoutFacts.Issuer,
			Digest: checkoutFacts.Digest, TransactionID: checkoutFacts.TransactionID,
			KeyBound: checkoutFacts.KeyBinding,
		}
	}
	if paymentFacts != nil {
		order.PaymentM = &OrderMandate{
			Vct: paymentFacts.Vct, Issuer: paymentFacts.Issuer,
			Digest: paymentFacts.Digest, TransactionID: paymentFacts.TransactionID,
			KeyBound:  paymentFacts.KeyBinding,
			PayeeName: paymentFacts.PayeeName, PayeeWebsite: paymentFacts.PayeeWebsite,
			Instrument: paymentFacts.Instrument,
		}
		order.PaymentState = "authorized"
	}
	cs.Status = "completed"
	cs.OrderID = orderID
	for _, d := range spent {
		s.used[d] = orderID
	}
	s.orders = append(s.orders, order)
	if len(s.orders) > OrdersKept {
		s.orders = s.orders[len(s.orders)-OrdersKept:]
	}
	if err := s.save(); err != nil {
		// The order was placed in memory and could not be persisted. That is
		// a 503 and a session left incomplete rather than an order the
		// record cannot prove: an order that survives a restart in memory
		// only is an order whose mandates cannot be checked as spent.
		cs.Status = "ready_for_complete"
		cs.OrderID = ""
		s.orders = s.orders[:len(s.orders)-1]
		for _, d := range spent {
			delete(s.used, d)
		}
		s.mu.Unlock()
		transportError(w, http.StatusServiceUnavailable, "orders",
			"the order could not be recorded")
		return
	}
	s.mu.Unlock()
	if s.Audit != nil {
		s.Audit("order.placed", ctx.Agent.Name+" "+orderID+" "+cs.Currency+" "+
			fmt.Sprint(cs.Total))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"order": order.orderJSON(),
		"checkout": map[string]any{
			"id": cs.ID, "status": cs.Status, "order_id": orderID,
		},
	})
}

// decodeBytes decodes a body already read, strictly: a field this program
// did not define is refused rather than guessed at.
func decodeBytes(body []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}
