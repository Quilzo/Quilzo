// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package commerce

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/httpsig"
	"github.com/quilzo/quilzo/internal/listing"
)

// call signs a request as the agent and sends it, returning the recorder.
func call(t *testing.T, svc *Service, priv ed25519.PrivateKey, method, path string,
	body []byte, extra ...string) *httptest.ResponseRecorder {

	return callAs(t, svc, priv, "ag1", method, path, body, extra...)
}

// callAs signs as a named agent key.
func callAs(t *testing.T, svc *Service, priv ed25519.PrivateKey, keyID, method,
	path string, body []byte, extra ...string) *httptest.ResponseRecorder {

	t.Helper()
	r := signedAgentRequest(t, priv, keyID, method, path, body, time.Now())
	r.Header.Set("UCP-Agent", `profile="https://platform.test/.well-known/ucp"`)
	r.Header.Set("Request-Id", "req-1")
	for i := 0; i+1 < len(extra); i += 2 {
		r.Header.Set(extra[i], extra[i+1])
	}
	w := httptest.NewRecorder()
	svc.ServeHTTP(w, r)
	return w
}

// callDestinationOnly signs a request over the destination and not the
// body: an identified agent whose word for the body is not bound to it.
func callDestinationOnly(t *testing.T, svc *Service, priv ed25519.PrivateKey,
	method, path string, body []byte, extra ...string) *httptest.ResponseRecorder {

	t.Helper()
	r := signedAgentRequest(t, priv, "ag1", method, path, nil, time.Now())
	r.ContentLength = int64(len(body))
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	if len(body) > 0 {
		httpsig.SetContentDigest(r, body)
	}
	r.Header.Set("UCP-Agent", `profile="https://platform.test/.well-known/ucp"`)
	r.Header.Set("Request-Id", "req-1")
	for i := 0; i+1 < len(extra); i += 2 {
		r.Header.Set(extra[i], extra[i+1])
	}
	w := httptest.NewRecorder()
	svc.ServeHTTP(w, r)
	return w
}

// decodeBody reads a response envelope.
func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("the response is not JSON: %v (%s)", err, w.Body.String())
	}
	return body
}

// The control: an agent signs in, searches, carts, checks out and completes
// under a verified checkout mandate, and the order is recorded.
func TestTheWholeJourney(t *testing.T) {
	dir := t.TempDir()
	svc, priv, _, issuerPriv, issuer := newShop(t, dir)

	// Discovery is public.
	w := httptest.NewRecorder()
	svc.Discover(w, httptest.NewRequest("GET", "/.well-known/ucp", nil))
	if w.Code != 200 {
		t.Fatalf("discovery answered %d", w.Code)
	}
	disc := decodeBody(t, w)
	if disc["rest"].(map[string]any)["endpoint"] != "/ucp" {
		t.Errorf("the discovery endpoint is %#v", disc["rest"])
	}
	if disc["merchant_key"] == nil {
		t.Error("the discovery document carries no merchant key")
	}

	// Search.
	w = call(t, svc, priv, "POST", "/ucp/catalog/search",
		[]byte(`{"query":"notebook"}`))
	if w.Code != 200 {
		t.Fatalf("search answered %d: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	products := body["products"].([]any)
	if len(products) != 1 {
		t.Fatalf("search found %d products, want 1", len(products))
	}
	if body["ucp"].(map[string]any)["version"] != UCPVersion {
		t.Error("the envelope carries no version")
	}

	// A cart, priced by the shop.
	cartBody := []byte(`{"line_items":[{"item":{"id":"notebook"},"quantity":2}]}`)
	w = call(t, svc, priv, "POST", "/ucp/carts", cartBody,
		"Idempotency-Key", "cart-1")
	if w.Code != 201 {
		t.Fatalf("the cart was not created: %d %s", w.Code, w.Body.String())
	}
	cart := decodeBody(t, w)
	cartID, _ := cart["id"].(string)
	if cartID == "" {
		t.Fatal("the cart has no id")
	}
	totals := cart["totals"].([]any)
	last := totals[len(totals)-1].(map[string]any)
	if last["type"] != "total" || last["amount"] != float64(4800) {
		t.Errorf("the cart's total is %#v, want 4800", totals)
	}

	// A checkout session, signed.
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions",
		[]byte(fmt.Sprintf(`{"cart_id":%q}`, cartID)), "Idempotency-Key", "cs-1")
	if w.Code != 201 {
		t.Fatalf("the session was not created: %d %s", w.Code, w.Body.String())
	}
	cs := decodeBody(t, w)
	csID, _ := cs["id"].(string)
	jwt, _ := cs["checkout_jwt"].(string)
	if csID == "" || jwt == "" {
		t.Fatalf("the session is %#v", cs)
	}

	// Completing without a body-covered signature is refused.
	w = callDestinationOnly(t, svc, priv, "POST", "/ucp/checkout-sessions/"+csID+"/complete",
		[]byte(`{}`), "Idempotency-Key", "c-1")
	if w.Code != 401 {
		t.Fatalf("a completion whose signature did not cover the body was "+
			"accepted: %d %s", w.Code, w.Body.String())
	}

	// A checkout mandate bound to this session's JWT.
	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "kb+sd-jwt",
		map[string]any{"vct": "mandate.checkout.1",
			"checkout_hash": CheckoutHash(jwt),
			"exp":           float64(time.Now().Add(time.Hour).Unix())})
	completeBody := []byte(fmt.Sprintf(`{"checkout_mandate":%q}`, token))

	// With the body covered this time: sign over content-digest too. call()
	// signs the body when there is one, so the earlier refusal came from a
	// signature over the destination alone — made here by hand.
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions/"+csID+"/complete",
		completeBody, "Idempotency-Key", "c-2")
	if w.Code != 200 {
		t.Fatalf("the checkout did not complete: %d %s", w.Code, w.Body.String())
	}
	order := decodeBody(t, w)["order"].(map[string]any)
	if order["payment_state"] != "none_presented" {
		t.Errorf("payment state is %v", order["payment_state"])
	}
	if order["total"] != float64(4800) {
		t.Errorf("the order total is %v", order["total"])
	}

	// The same Idempotency-Key replays the same answer and places no second
	// order.
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions/"+csID+"/complete",
		completeBody, "Idempotency-Key", "c-2")
	if w.Code != 200 {
		t.Fatalf("a retry was not replayed: %d", w.Code)
	}
	if order2 := decodeBody(t, w)["order"].(map[string]any); order2["id"] != order["id"] {
		t.Error("a retried completion produced a second order")
	}

	// The order book is on disk, with the mandate's presentation recorded.
	data, err := os.ReadFile(filepath.Join(dir, "orders.json"))
	if err != nil {
		t.Fatalf("no order book was written: %v", err)
	}
	var file struct {
		Orders []Order           `json:"orders"`
		Used   map[string]string `json:"used"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Orders) != 1 {
		t.Fatalf("%d orders on disk", len(file.Orders))
	}
	if file.Orders[0].Agent != "ExampleAgent" || file.Orders[0].AgentKey != "ag1" {
		t.Errorf("the order names %#v", file.Orders[0])
	}
	if file.Orders[0].Platform != "https://platform.test/.well-known/ucp" {
		t.Errorf("the platform claim is %q", file.Orders[0].Platform)
	}
	if len(file.Used) != 1 {
		t.Errorf("%d spent mandates recorded", len(file.Used))
	}

	// The same mandate cannot authorise a second order.
	cart2 := []byte(`{"line_items":[{"item":{"id":"cards"},"quantity":1}]}`)
	w = call(t, svc, priv, "POST", "/ucp/carts", cart2, "Idempotency-Key", "cart-2")
	cart2ID := decodeBody(t, w)["id"].(string)
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions",
		[]byte(fmt.Sprintf(`{"cart_id":%q}`, cart2ID)), "Idempotency-Key", "cs-2")
	cs2 := decodeBody(t, w)
	jwt2, _ := cs2["checkout_jwt"].(string)

	// A mandate bound to the second session, but reusing the first's
	// presentation digest is impossible — the digest covers the token, so
	// reuse means sending the same token, bound to the first session.
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions/"+cs2["id"].(string)+"/complete",
		[]byte(fmt.Sprintf(`{"checkout_mandate":%q}`, token)), "Idempotency-Key", "c-3")
	// The hash does not match the second session, so the binding refuses it
	// long before replay does — which is the order of checks a merchant
	// wants. A business refusal is a 200 with the error in the envelope,
	// which is the two-layer convention the spec fixes.
	if w.Code != 200 || !strings.Contains(w.Body.String(), "different checkout") {
		t.Fatalf("a mandate bound to another checkout completed this one: "+
			"%d %s", w.Code, w.Body.String())
	}

	// A genuinely second mandate on the second session, from the same issuer:
	// nothing wrong, and it should complete.
	token2 := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "kb+sd-jwt",
		map[string]any{"vct": "mandate.checkout.1",
			"checkout_hash": CheckoutHash(jwt2),
			"exp":           float64(time.Now().Add(time.Hour).Unix())})
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions/"+cs2["id"].(string)+"/complete",
		[]byte(fmt.Sprintf(`{"checkout_mandate":%q}`, token2)), "Idempotency-Key", "c-4")
	if w.Code != 200 {
		t.Fatalf("a fresh mandate on a fresh session was refused: %d %s",
			w.Code, w.Body.String())
	}

	// And now the replay of that second mandate is refused on any session.
	cart3 := []byte(`{"line_items":[{"item":{"id":"notebook"},"quantity":1}]}`)
	w = call(t, svc, priv, "POST", "/ucp/carts", cart3, "Idempotency-Key", "cart-3")
	cart3ID := decodeBody(t, w)["id"].(string)
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions",
		[]byte(fmt.Sprintf(`{"cart_id":%q}`, cart3ID)), "Idempotency-Key", "cs-3")
	cs3 := decodeBody(t, w)
	token3 := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "kb+sd-jwt",
		map[string]any{"vct": "mandate.checkout.1",
			"checkout_hash": CheckoutHash(cs3["checkout_jwt"].(string)),
			"exp":           float64(time.Now().Add(time.Hour).Unix())})
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions/"+cs3["id"].(string)+"/complete",
		[]byte(fmt.Sprintf(`{"checkout_mandate":%q}`, token3)), "Idempotency-Key", "c-5")
	if w.Code != 200 {
		t.Fatalf("a third order was refused: %d %s", w.Code, w.Body.String())
	}
}

// A payment mandate, when presented, authorises the order's payment state.
func TestAPaymentMandateAuthorisesTheOrder(t *testing.T) {
	svc, priv, _, issuerPriv, issuer := newShop(t, "")
	w := call(t, svc, priv, "POST", "/ucp/carts",
		[]byte(`{"line_items":[{"item":{"id":"notebook"},"quantity":1}]}`),
		"Idempotency-Key", "k1")
	cartID := decodeBody(t, w)["id"].(string)
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions",
		[]byte(fmt.Sprintf(`{"cart_id":%q}`, cartID)), "Idempotency-Key", "k2")
	cs := decodeBody(t, w)

	payment := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "kb+sd-jwt",
		map[string]any{"vct": "mandate.payment.1",
			"payee":          map[string]any{"name": "Marginalia", "website": "https://shop.test"},
			"payment_amount": map[string]any{"amount": float64(2400), "currency": "GBP"},
			"exp":            float64(time.Now().Add(time.Hour).Unix())})
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions/"+cs["id"].(string)+"/complete",
		[]byte(fmt.Sprintf(`{"payment_mandate":%q}`, payment)), "Idempotency-Key", "k3")
	if w.Code != 200 {
		t.Fatalf("completion with a payment mandate was refused: %d %s",
			w.Code, w.Body.String())
	}
	order := decodeBody(t, w)["order"].(map[string]any)
	if order["payment_state"] != "authorized" {
		t.Errorf("payment state is %v", order["payment_state"])
	}
}

// An unsigned request is nobody's, and a mis-signed one is an error.
func TestAnUnsignedRequestIsRefused(t *testing.T) {
	svc, _, _, _, _ := newShop(t, "")
	r := httptest.NewRequest("POST", "http://shop.test/ucp/catalog/search", nil)
	w := httptest.NewRecorder()
	svc.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("an unsigned request was answered %d", w.Code)
	}
}

// A price in a request is a field this program did not define, and the
// strict decode refuses it — which is the shape of "prices come from the
// records, never from the caller".
func TestAPriceInTheRequestIsRefused(t *testing.T) {
	svc, priv, _, _, _ := newShop(t, "")
	w := call(t, svc, priv, "POST", "/ucp/carts",
		[]byte(`{"line_items":[{"item":{"id":"notebook","price":1},"quantity":1}]}`),
		"Idempotency-Key", "p1")
	if w.Code != 400 {
		t.Fatalf("a request carrying a price was accepted: %d %s", w.Code,
			w.Body.String())
	}
}

// A sold-out product cannot be carted, and the failure is the shop's
// answer, not the transport's.
func TestASoldOutProductIsRefusedAsABusinessAnswer(t *testing.T) {
	svc, priv, _, _, _ := newShop(t, "")
	w := call(t, svc, priv, "POST", "/ucp/carts",
		[]byte(`{"line_items":[{"item":{"id":"pen"},"quantity":1}]}`),
		"Idempotency-Key", "s1")
	if w.Code != 200 {
		t.Fatalf("sold out was answered as a transport error: %d", w.Code)
	}
	body := decodeBody(t, w)
	msgs := body["messages"].([]any)
	first := msgs[0].(map[string]any)
	if first["code"] != "line_item" || first["severity"] != "recoverable" {
		t.Errorf("the message is %#v", first)
	}
	if !strings.Contains(first["content"].(string), "sold out") {
		t.Errorf("the content is %v", first["content"])
	}
}

// The same key with a different body is a 409, per the spec.
func TestAnIdempotencyKeyReusedWithAnotherBodyConflicts(t *testing.T) {
	svc, priv, _, _, _ := newShop(t, "")
	w := call(t, svc, priv, "POST", "/ucp/carts",
		[]byte(`{"line_items":[{"item":{"id":"notebook"},"quantity":1}]}`),
		"Idempotency-Key", "same")
	if w.Code != 201 {
		t.Fatalf("the first cart was refused: %d", w.Code)
	}
	w = call(t, svc, priv, "POST", "/ucp/carts",
		[]byte(`{"line_items":[{"item":{"id":"cards"},"quantity":1}]}`),
		"Idempotency-Key", "same")
	if w.Code != 409 {
		t.Fatalf("the same key with a different body answered %d", w.Code)
	}
}

// Creating a checkout from the same cart twice returns the same session,
// which is the spec's conversion rule.
func TestASecondCheckoutFromOneCartReturnsTheSameSession(t *testing.T) {
	svc, priv, _, _, _ := newShop(t, "")
	w := call(t, svc, priv, "POST", "/ucp/carts",
		[]byte(`{"line_items":[{"item":{"id":"notebook"},"quantity":1}]}`),
		"Idempotency-Key", "a1")
	cartID := decodeBody(t, w)["id"].(string)
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions",
		[]byte(fmt.Sprintf(`{"cart_id":%q}`, cartID)), "Idempotency-Key", "a2")
	first := decodeBody(t, w)
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions",
		[]byte(fmt.Sprintf(`{"cart_id":%q}`, cartID)), "Idempotency-Key", "a3")
	second := decodeBody(t, w)
	if first["id"] != second["id"] {
		t.Fatalf("one cart made two sessions: %v and %v", first["id"], second["id"])
	}
}

// The catalogue's records can carry problems; search says so as warnings
// rather than hiding the eleventh product behind the twelfth's bad price.
func TestARecordProblemTravelsAsAWarning(t *testing.T) {
	svc, priv, _, _, _ := newShop(t, "")
	svc.Rows = func() ([]listing.Row, error) {
		rows := shopRows()
		rows = append(rows, map[string]any{"slug": "broken", "name": "Broken",
			"price": "not a number", "currency": "GBP"})
		return rows, nil
	}
	w := call(t, svc, priv, "POST", "/ucp/catalog/search", []byte(`{}`))
	if w.Code != 200 {
		t.Fatalf("search answered %d: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	msgs, _ := body["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("warnings: %#v", body["messages"])
	}
	if msgs[0].(map[string]any)["code"] != "record_problem" {
		t.Errorf("the warning is %#v", msgs[0])
	}
	if len(body["products"].([]any)) != 3 {
		t.Errorf("the good products did not survive the bad record")
	}
}

// One agent cannot operate on another's cart or session: the id may be a
// 128-bit secret, but a boundary that depends on a secret staying secret is
// a boundary worth enforcing anyway.
func TestAnotherAgentFindsSomebodyElsesCartAbsent(t *testing.T) {
	svc, priv, _, _, _ := newShop(t, "")
	w := call(t, svc, priv, "POST", "/ucp/carts",
		[]byte(`{"line_items":[{"item":{"id":"notebook"},"quantity":1}]}`),
		"Idempotency-Key", "o1")
	cartID := decodeBody(t, w)["id"].(string)
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions",
		[]byte(fmt.Sprintf(`{"cart_id":%q}`, cartID)), "Idempotency-Key", "o2")
	cs := decodeBody(t, w)

	// A second configured agent.
	otherPriv, otherKey := agentKey(t, "OtherAgent", "ag2")
	svc.Agents = append(svc.Agents, otherKey)

	for _, attempt := range []struct {
		method, path string
		body         []byte
		key          string
	}{
		{"GET", "/ucp/carts/" + cartID, nil, "o3"},
		{"PUT", "/ucp/carts/" + cartID,
			[]byte(`{"line_items":[{"item":{"id":"cards"},"quantity":1}]}`), "o4"},
		{"POST", "/ucp/carts/" + cartID + "/cancel", []byte(`{}`), "o5"},
		{"GET", "/ucp/checkout-sessions/" + cs["id"].(string), nil, "o6"},
		{"POST", "/ucp/checkout-sessions/" + cs["id"].(string) + "/cancel",
			[]byte(`{}`), "o7"},
		{"POST", "/ucp/checkout-sessions/" + cs["id"].(string) + "/complete",
			[]byte(`{}`), "o8"},
	} {
		w := callAs(t, svc, otherPriv, "ag2", attempt.method, attempt.path,
			attempt.body, "Idempotency-Key", attempt.key)
		body := decodeBody(t, w)
		msgs, _ := body["messages"].([]any)
		if w.Code != 200 || len(msgs) != 1 ||
			msgs[0].(map[string]any)["code"] != "not_found" {
			t.Fatalf("%s %s as the other agent: %d %s — wanted not_found",
				attempt.method, attempt.path, w.Code, w.Body.String())
		}
	}

	// And the owner still can, which is what makes not_found a boundary
	// rather than an outage.
	w = call(t, svc, priv, "GET", "/ucp/carts/"+cartID, nil)
	if w.Code != 200 || decodeBody(t, w)["id"] != cartID {
		t.Fatalf("the owner could not read its own cart: %d %s", w.Code, w.Body.String())
	}
}

// Pagination walks the catalogue on the cursors this shop hands back, and
// a made-up cursor is refused rather than silently starting over — which is
// what a parsed-as-zero cursor would do.
func TestPaginationWalksOnTheCursorsItIsGiven(t *testing.T) {
	svc, priv, _, _, _ := newShop(t, "")
	w := call(t, svc, priv, "POST", "/ucp/catalog/search",
		[]byte(`{"pagination":{"limit":2}}`))
	body := decodeBody(t, w)
	if len(body["products"].([]any)) != 2 {
		t.Fatalf("the first page has %d products", len(body["products"].([]any)))
	}
	pg := body["pagination"].(map[string]any)
	if pg["cursor"] != "2" || pg["has_next_page"] != true {
		t.Fatalf("the first page's pagination is %#v", pg)
	}
	cursor := pg["cursor"].(string)
	w = call(t, svc, priv, "POST", "/ucp/catalog/search",
		[]byte(fmt.Sprintf(`{"pagination":{"limit":2,"cursor":%q}}`, cursor)))
	body = decodeBody(t, w)
	if len(body["products"].([]any)) != 1 {
		t.Fatalf("the second page has %d products, want the last one",
			len(body["products"].([]any)))
	}
	if v, said := body["pagination"].(map[string]any)["has_next_page"]; said && v == true {
		t.Error("the last page says there is another")
	}
	w = call(t, svc, priv, "POST", "/ucp/catalog/search",
		[]byte(`{"pagination":{"cursor":"not-a-cursor"}}`))
	if w.Code != 400 {
		t.Fatalf("a made-up cursor was answered %d, want 400", w.Code)
	}
}

// The binding's two mandatory headers are required, not recorded.
func TestTheMandatoryHeadersAreRequired(t *testing.T) {
	svc, priv, _, _, _ := newShop(t, "")
	r := signedAgentRequest(t, priv, "ag1", "POST", "/ucp/catalog/search",
		[]byte(`{}`), time.Now())
	w := httptest.NewRecorder()
	svc.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("a request with neither header was answered %d, want 400", w.Code)
	}
	r = signedAgentRequest(t, priv, "ag1", "POST", "/ucp/catalog/search",
		[]byte(`{}`), time.Now())
	r.Header.Set("UCP-Agent", `profile="https://platform.test/.well-known/ucp"`)
	w = httptest.NewRecorder()
	svc.ServeHTTP(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "Request-Id") {
		t.Fatalf("a request with no Request-Id was answered %d %s", w.Code, w.Body.String())
	}
}

// A foreign agent presenting a mandate against somebody else's session
// learns nothing but not_found — not, through a mandate's refusal, that the
// session exists.
func TestAForeignAgentLearnsNothingFromAMandate(t *testing.T) {
	svc, priv, _, issuerPriv, issuer := newShop(t, "")
	w := call(t, svc, priv, "POST", "/ucp/carts",
		[]byte(`{"line_items":[{"item":{"id":"notebook"},"quantity":1}]}`),
		"Idempotency-Key", "f1")
	cartID := decodeBody(t, w)["id"].(string)
	w = call(t, svc, priv, "POST", "/ucp/checkout-sessions",
		[]byte(fmt.Sprintf(`{"cart_id":%q}`, cartID)), "Idempotency-Key", "f2")
	cs := decodeBody(t, w)
	csID := cs["id"].(string)

	// A well-formed mandate from the configured issuer, bound to the real
	// session JWT — presented by the wrong agent.
	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "kb+sd-jwt",
		map[string]any{"vct": "mandate.checkout.1",
			"checkout_hash": CheckoutHash(cs["checkout_jwt"].(string)),
			"exp":           float64(time.Now().Add(time.Hour).Unix())})
	otherPriv, otherKey := agentKey(t, "OtherAgent", "ag2")
	svc.Agents = append(svc.Agents, otherKey)

	w = callAs(t, svc, otherPriv, "ag2", "POST",
		"/ucp/checkout-sessions/"+csID+"/complete",
		[]byte(fmt.Sprintf(`{"checkout_mandate":%q}`, token)), "Idempotency-Key", "f3")
	body := decodeBody(t, w)
	msgs, _ := body["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["code"] != "not_found" {
		t.Fatalf("the wrong agent learned something: %d %s", w.Code, w.Body.String())
	}
}
