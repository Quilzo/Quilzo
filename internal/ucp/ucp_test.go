// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ucp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/rate"
)

const base = "https://shop.example"

// shop is a catalogue of n products, the first few named for searching.
func shop(n int) *Catalog {
	rows := make([]listing.Row, 0, n)
	named := []listing.Row{
		{"slug": "brass-pen", "name": "Brass pen", "price": float64(4800), "currency": "GBP",
			"sku": "BP-1", "range": "desk", "availability": "in_stock",
			"summary": "A pen that outlives you.", "image": "/media/sha256-" + strings.Repeat("a", 64),
			"alt": "A brass pen"},
		{"slug": "linen-notebook", "name": "Linen notebook", "price": float64(1800), "currency": "GBP",
			"range": "correspondence", "availability": "sold_out", "summary": "Lies flat."},
		{"slug": "glass-inkwell", "name": "Glass inkwell", "price": float64(3200), "currency": "GBP",
			"range": "desk", "availability": "made_to_order", "summary": "Holds brass nibs.",
			"lead_time": "three weeks"},
	}
	rows = append(rows, named...)
	for i := len(rows); i < n; i++ {
		rows = append(rows, listing.Row{"slug": fmt.Sprintf("card-%03d", i),
			"name": fmt.Sprintf("Card %03d", i), "price": float64(100 + i), "currency": "GBP",
			"range": "correspondence"})
	}
	return &Catalog{Base: base, Rows: func(max int) ([]listing.Row, int, error) {
		if len(rows) > max {
			return rows[:max], len(rows), nil
		}
		return rows, len(rows), nil
	}}
}

// call sends one catalog request with the binding's required headers.
func call(t *testing.T, c *Catalog, op, body string, mod ...func(*http.Request)) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/ucp/catalog/"+op, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Request-Id", "req-1")
	r.Header.Set("UCP-Agent", `profile="https://platform.example/.well-known/ucp"`)
	for _, m := range mod {
		m(r)
	}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func ids(out map[string]any) []string {
	var got []string
	for _, p := range out["products"].([]any) {
		got = append(got, p.(map[string]any)["id"].(string))
	}
	return got
}

// The profile is the spec's business profile: the REST service at an
// absolute https endpoint built from configuration (never the Host header),
// both catalog capabilities with their schemas, an empty payment registry,
// and cacheable as the spec requires of a profile.
func TestTheProfileIsTheSpecsShape(t *testing.T) {
	c := shop(3)
	r := httptest.NewRequest(http.MethodGet, "/.well-known/ucp", nil)
	r.Host = "attacker.example"
	w := httptest.NewRecorder()
	c.Profile(w, r)
	var p struct {
		UCP struct {
			Version  string `json:"version"`
			Services map[string][]struct {
				Transport, Endpoint, Schema, Spec, Version string
			} `json:"services"`
			Capabilities    map[string][]struct{ Version, Spec, Schema string } `json:"capabilities"`
			PaymentHandlers map[string]any                                      `json:"payment_handlers"`
		} `json:"ucp"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err, w.Body.String())
	}
	svc := p.UCP.Services["dev.ucp.shopping"]
	if p.UCP.Version != Version || len(svc) != 1 || svc[0].Transport != "rest" ||
		svc[0].Endpoint != base+"/ucp" || svc[0].Schema == "" {
		t.Errorf("the service entry is wrong: %+v", p.UCP)
	}
	for _, name := range []string{"dev.ucp.shopping.catalog.search", "dev.ucp.shopping.catalog.lookup"} {
		if e := p.UCP.Capabilities[name]; len(e) != 1 || e[0].Schema == "" || e[0].Version != Version {
			t.Errorf("%s: %+v", name, e)
		}
	}
	if len(p.UCP.Capabilities) != 2 || p.UCP.PaymentHandlers == nil || len(p.UCP.PaymentHandlers) != 0 {
		t.Errorf("it advertises more than the catalogue, or no payment registry: %s", w.Body)
	}
	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "public") || !strings.Contains(cc, "max-age=300") || w.Header().Get("ETag") == "" {
		t.Errorf("the profile is not cacheable as the spec requires: %q", cc)
	}
	if strings.Contains(w.Body.String(), "attacker.example") {
		t.Error("the profile was built from the request's Host header")
	}
	r = httptest.NewRequest(http.MethodGet, "/.well-known/ucp", nil)
	r.Header.Set("If-None-Match", w.Header().Get("ETag"))
	w2 := httptest.NewRecorder()
	c.Profile(w2, r)
	if w2.Code != http.StatusNotModified {
		t.Errorf("revalidation answered %d", w2.Code)
	}
	w3 := httptest.NewRecorder()
	c.Profile(w3, httptest.NewRequest(http.MethodPost, "/.well-known/ucp", nil))
	if w3.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST to the profile answered %d", w3.Code)
	}
}

// Products carry what the spec requires — a description on the product and
// its variant, a price per variant, availability in its vocabulary — and
// absolute URLs only.
func TestAProductIsTheSpecsShape(t *testing.T) {
	_, out := call(t, shop(3), "product", `{"id":"brass-pen"}`)
	p := out["product"].(map[string]any)
	v := p["variants"].([]any)[0].(map[string]any)
	if p["description"].(map[string]any)["plain"] == nil || v["description"] == nil ||
		v["price"].(map[string]any)["amount"].(float64) != 4800 || v["id"] != "brass-pen:default" {
		t.Errorf("%v", p)
	}
	if v["availability"].(map[string]any)["available"] != true {
		t.Errorf("in_stock is not available: %v", v["availability"])
	}
	media := p["media"].([]any)[0].(map[string]any)
	if !strings.HasPrefix(media["url"].(string), base+"/media/") {
		t.Errorf("a media URL is not absolute: %v", media["url"])
	}
	_, out = call(t, shop(3), "product", `{"id":"linen-notebook"}`)
	v = out["product"].(map[string]any)["variants"].([]any)[0].(map[string]any)
	if a := v["availability"].(map[string]any); a["available"] != false || a["status"] != "out_of_stock" {
		t.Errorf("sold_out became %v", a)
	}
}

// A price is a whole number of minor units however it is written, and a
// record that says otherwise is not offered at a price nobody set.
func TestAPriceIsWholeMinorUnits(t *testing.T) {
	for _, bad := range []any{"12.50", 12.5, float64(-1), "1e3", float64(MaxAmount + 1), "", true} {
		if _, err := minorOf(bad); err == nil {
			t.Errorf("%#v was read as a price", bad)
		}
	}
	for in, want := range map[any]int64{"1250": 1250, float64(4800): 4800, 7: 7} {
		if got, err := minorOf(in); err != nil || got != want {
			t.Errorf("%#v: %d %v", in, got, err)
		}
	}
	if _, problem := FromRow(listing.Row{"slug": "x", "name": "X", "price": "12.50", "currency": "GBP"}, base); problem == "" {
		t.Error("a product priced \"12.50\" was offered")
	}
}

// A record cannot hand an agent a script address as a picture or a page.
func TestOnlyWebAddressesAreOffered(t *testing.T) {
	p, _ := FromRow(listing.Row{"slug": "x", "name": "X", "price": float64(1), "currency": "GBP",
		"image": "javascript:alert(1)", "url": "//evil.example/x"}, base)
	if len(p.Media) != 0 || p.URL != "" {
		t.Errorf("%+v", p)
	}
}

// Search reaches every product, not the listing's first page; pages are
// walked with the shop's cursors, and a forged cursor is refused.
func TestSearchReachesTheWholeCatalogue(t *testing.T) {
	c := shop(120)
	seen := map[string]bool{}
	cursor := ""
	for pages := 0; pages < 20; pages++ {
		body := `{"filters":{"categories":["correspondence"]},"pagination":{"limit":50`
		if cursor != "" {
			body += `,"cursor":"` + cursor + `"`
		}
		w, out := call(t, c, "search", body+`}}`)
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		for _, id := range ids(out) {
			if seen[id] {
				t.Fatalf("%s was on two pages", id)
			}
			seen[id] = true
		}
		pg := out["pagination"].(map[string]any)
		if pg["total_count"].(float64) != 118 {
			t.Fatalf("total_count %v", pg["total_count"])
		}
		if pg["has_next_page"] != true {
			break
		}
		cursor = pg["cursor"].(string)
	}
	if len(seen) != 118 || !seen["card-119"] {
		t.Errorf("search found %d of 118 products in the category", len(seen))
	}
	for _, forged := range []string{"999999", "bzotMQ", "b246OTk5OTk5OQ"} {
		if w, _ := call(t, c, "search", `{"query":"card","pagination":{"cursor":"`+forged+`"}}`); w.Code != 400 {
			t.Errorf("cursor %q answered %d", forged, w.Code)
		}
	}
}

// Every query word must appear, a title match ranks first, and the filters
// narrow by category and by price in the context's currency.
func TestSearchMatchesWordsAndFilters(t *testing.T) {
	c := shop(3)
	_, out := call(t, c, "search", `{"query":"brass"}`)
	if got := ids(out); len(got) != 2 || got[0] != "brass-pen" {
		t.Errorf("brass: %v", got)
	}
	_, out = call(t, c, "search", `{"query":"brass pen"}`)
	if got := ids(out); len(got) != 1 || got[0] != "brass-pen" {
		t.Errorf("brass pen: %v", got)
	}
	_, out = call(t, c, "search", `{"filters":{"price":{"max":4000}},"context":{"currency":"GBP"}}`)
	if got := ids(out); len(got) != 2 {
		t.Errorf("under 4000: %v", got)
	}
	_, out = call(t, c, "search", `{"filters":{"price":{"max":4000}},"context":{"currency":"USD"}}`)
	if got := ids(out); len(got) != 0 {
		t.Errorf("a USD price filter matched GBP prices it cannot compare: %v", got)
	}
	_, out = call(t, c, "search", `{"query":"pen","filters":{"colour":"red"}}`)
	msgs, _ := json.Marshal(out["messages"])
	if !strings.Contains(string(msgs), "filter_unsupported") || !strings.Contains(string(msgs), "colour") {
		t.Errorf("a filter this shop does not apply was ignored in silence: %s", msgs)
	}
}

// Requests are what the spec defines: every field it defines is accepted,
// anything else is refused, and so is a request that asks for nothing.
func TestRequestsAreTheSpecsShapesAndNoMore(t *testing.T) {
	c := shop(3)
	full := `{"query":"pen","context":{"address_country":"GB","language":"en"},` +
		`"signals":{"dev.ucp.buyer_ip":"203.0.113.9"},"attribution":{"utm_source":"x"},` +
		`"filters":{"categories":["desk"]},"pagination":{"limit":5}}`
	if w, _ := call(t, c, "search", full); w.Code != 200 {
		t.Errorf("a complete, conforming search was refused: %d %s", w.Code, w.Body)
	}
	if w, _ := call(t, c, "product", `{"id":"brass-pen","selected":[{"name":"Colour","label":"Brass"}],"preferences":["Colour"]}`); w.Code != 200 {
		t.Errorf("a product request with selections was refused: %d %s", w.Code, w.Body)
	}
	for op, body := range map[string]string{
		"search":  `{"query":"pen","price":1}`,
		"lookup":  `{"ids":["brass-pen"],"price":{"amount":1}}`,
		"product": `{"id":"brass-pen","quantity":2}`,
	} {
		if w, _ := call(t, c, op, body); w.Code != 400 {
			t.Errorf("%s with a field the spec does not define answered %d", op, w.Code)
		}
	}
	for _, body := range []string{`{}`, `{"query":"   "}`, `{"query":"pen"}{"query":"x"}`,
		`{"query":"` + strings.Repeat("a", MaxQuery+1) + `"}`, `{"query":"pen","context":"GB"}`,
		`{"query":"pen","pagination":{"limit":0}}`} {
		if w, _ := call(t, c, "search", body); w.Code != 400 {
			t.Errorf("%.40s answered %d", body, w.Code)
		}
	}
	big := `{"query":"` + strings.Repeat("a", MaxBody) + `"}`
	if w, _ := call(t, c, "search", big); w.Code != 400 {
		t.Errorf("a body over the limit answered %d", w.Code)
	}
}

// The headers the binding requires are required.
func TestTheBindingsHeadersAreRequired(t *testing.T) {
	c := shop(3)
	for name, mod := range map[string]func(*http.Request){
		"no Request-Id":       func(r *http.Request) { r.Header.Del("Request-Id") },
		"no UCP-Agent":        func(r *http.Request) { r.Header.Del("UCP-Agent") },
		"a bare UCP-Agent":    func(r *http.Request) { r.Header.Set("UCP-Agent", "https://p.example") },
		"an http profile":     func(r *http.Request) { r.Header.Set("UCP-Agent", `profile="http://p.example/.well-known/ucp"`) },
		"an unquoted profile": func(r *http.Request) { r.Header.Set("UCP-Agent", `profile=https://p.example`) },
		"two UCP-Agents":      func(r *http.Request) { r.Header.Add("UCP-Agent", `profile="https://q.example"`) },
		"a control character": func(r *http.Request) { r.Header.Set("Request-Id", "a\x01b") },
	} {
		if w, _ := call(t, c, "search", `{"query":"pen"}`, mod); w.Code != 400 {
			t.Errorf("%s answered %d", name, w.Code)
		}
	}
	w, _ := call(t, c, "search", `{"query":"pen"}`, func(r *http.Request) {
		r.Header.Set("UCP-Agent", `version="2026-08-25", profile="https://p.example/.well-known/ucp";v=1`)
	})
	if w.Code != 200 || w.Header().Get("Request-Id") != "req-1" {
		t.Errorf("a dictionary with more members was refused, or the id not echoed: %d", w.Code)
	}
	if w, _ := call(t, c, "search", `{"query":"pen"}`, func(r *http.Request) {
		r.Header.Set("Content-Type", "text/plain")
	}); w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("a text body answered %d", w.Code)
	}
}

// Lookup resolves product ids (featured), variant ids and SKUs (exact),
// returns each product once with every id that reached it, says which ids
// matched nothing, and refuses a batch over its limit after deduplicating.
func TestLookupCorrelatesAndDeduplicates(t *testing.T) {
	c := shop(3)
	w, out := call(t, c, "lookup", `{"ids":["brass-pen","BP-1","brass-pen:default","nope","brass-pen"]}`)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	products := out["products"].([]any)
	if len(products) != 1 {
		t.Fatalf("one product, three ways, came back %d times", len(products))
	}
	inputs := products[0].(map[string]any)["variants"].([]any)[0].(map[string]any)["inputs"].([]any)
	got := map[string]string{}
	for _, in := range inputs {
		m := in.(map[string]any)
		got[m["id"].(string)] = m["match"].(string)
	}
	if got["brass-pen"] != "featured" || got["BP-1"] != "exact" || got["brass-pen:default"] != "exact" || len(got) != 3 {
		t.Errorf("inputs %v", got)
	}
	if msgs, _ := json.Marshal(out["messages"]); !strings.Contains(string(msgs), `"content":"nope"`) {
		t.Errorf("an unknown id was not reported: %s", msgs)
	}
	many := make([]string, MaxLookup+1)
	for i := range many {
		many[i] = fmt.Sprintf(`"id-%d"`, i)
	}
	if w, _ := call(t, c, "lookup", `{"ids":[`+strings.Join(many, ",")+`]}`); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "request_too_large") {
		t.Errorf("an oversized batch answered %d %s", w.Code, w.Body)
	}
	repeated := strings.Repeat(`"brass-pen",`, MaxLookup+5) + `"brass-pen"`
	if w, _ := call(t, c, "lookup", `{"ids":[`+repeated+`]}`); w.Code != 200 {
		t.Errorf("a batch that is small once deduplicated was refused: %d", w.Code)
	}
}

// A product that does not exist is the shop's answer, not a transport
// failure: a 200 with an unrecoverable error message.
func TestAMissingProductIsABusinessOutcome(t *testing.T) {
	w, out := call(t, shop(3), "product", `{"id":"nope"}`)
	if w.Code != 200 || out["ucp"].(map[string]any)["status"] != "error" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	m := out["messages"].([]any)[0].(map[string]any)
	if m["code"] != "not_found" || m["severity"] != "unrecoverable" {
		t.Errorf("%v", m)
	}
}

// One address cannot ask without limit, and being refused costs it the
// wait the answer names.
func TestOneAddressIsLimited(t *testing.T) {
	c := shop(3)
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	c.Limit = rate.PerHour(60, 3)
	for i := 0; i < 3; i++ {
		if w, _ := call(t, c, "search", `{"query":"pen"}`); w.Code != 200 {
			t.Fatalf("request %d of the burst answered %d", i+1, w.Code)
		}
	}
	w, _ := call(t, c, "search", `{"query":"pen"}`)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("past the burst answered %d", w.Code)
	}
	other, _ := call(t, c, "search", `{"query":"pen"}`, func(r *http.Request) { r.RemoteAddr = "198.51.100.7:4000" })
	if other.Code != 200 {
		t.Errorf("another address was limited by the first's requests: %d", other.Code)
	}
	now = now.Add(time.Minute)
	if w, _ := call(t, c, "search", `{"query":"pen"}`); w.Code != 200 {
		t.Errorf("a minute later answered %d", w.Code)
	}
}

// Only the three operations, only by POST; nothing else answers.
func TestOnlyTheCatalogOperationsAnswer(t *testing.T) {
	c := shop(3)
	for _, path := range []string{"/ucp/carts", "/ucp/checkout-sessions", "/ucp/catalog/search/x", "/ucp/"} {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ucp/catalog/search", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
		t.Errorf("GET answered %d", w.Code)
	}
}

// A catalogue larger than one answer considers is said to be, not shown as
// if it were the whole.
func TestAPartialCatalogueIsSaid(t *testing.T) {
	c := shop(MaxProducts + 5)
	_, out := call(t, c, "search", `{"query":"card"}`)
	if msgs, _ := json.Marshal(out["messages"]); !strings.Contains(string(msgs), "catalog_truncated") {
		t.Errorf("a truncated catalogue was not said: %s", msgs)
	}
}
