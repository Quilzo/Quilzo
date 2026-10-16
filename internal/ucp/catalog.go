// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ucp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/clientip"
	"github.com/quilzo/quilzo/internal/etag"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/rate"
)

// The bounds on what one request may ask for. Small, because every one is
// reachable from the internet with no credential: a body big enough for any
// real search and no bigger, a batch the spec says to accept at least ten
// of, and pages an agent can use without one request reading the shop.
const (
	MaxBody     = 64 << 10
	MaxLookup   = 50
	MaxID       = 256
	MaxQuery    = 256
	DefaultPage = 10
	MaxPage     = 50
	// MaxProducts is the most of a catalogue one answer will consider. Past
	// it, the answer says it saw only part, rather than presenting a part as
	// the whole.
	MaxProducts = 10000
)

// The capability names this serves, and the spec's documents for each, so
// a platform can fetch the schema it negotiates against.
const (
	capSearch = "dev.ucp.shopping.catalog.search"
	capLookup = "dev.ucp.shopping.catalog.lookup"
	specBase  = "https://ucp.dev/" + Version
)

// Catalog is the UCP surface over one catalogue listing.
type Catalog struct {
	// Base is the site's absolute https origin. The profile's endpoint and
	// every URL in an answer are built from it, never from the request's
	// Host header, which says whatever the caller wants it to.
	Base string
	// Rows reads every row the catalogue listing matches, fresh, and how
	// many matched. Fresh because a price published a minute ago is the
	// price; a copy taken at startup would sell at yesterday's.
	Rows func(max int) ([]listing.Row, int, error)
	// Limit is each address's allowance. Nil is unlimited, for tests.
	Limit *rate.Limiter
	// Now is the clock, replaceable in tests.
	Now func() time.Time
}

func (c *Catalog) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Profile serves /.well-known/ucp: which version this speaks, where its
// REST binding is, and the two capabilities it offers.
//
// Cacheable by anyone for five minutes, as the spec requires of a profile
// (public, at least sixty seconds, never no-store), with a validator so a
// platform revalidating gets a 304 instead of the document again.
func (c *Catalog) Profile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		transportError(w, http.StatusMethodNotAllowed, "method_not_allowed",
			"the profile is read with GET")
		return
	}
	entry := func(name, doc, schema string) []map[string]any {
		return []map[string]any{{"version": Version,
			"spec":   specBase + "/specification/shopping/catalog/" + doc,
			"schema": specBase + "/schemas/shopping/" + schema}}
	}
	body := map[string]any{"ucp": map[string]any{
		"version": Version,
		"services": map[string]any{"dev.ucp.shopping": []map[string]any{{
			"version":   Version,
			"spec":      specBase + "/specification/overview",
			"transport": "rest",
			"schema":    specBase + "/services/shopping/rest.openapi.json",
			"endpoint":  strings.TrimSuffix(c.Base, "/") + "/ucp",
		}}},
		"capabilities": map[string]any{
			capSearch: entry(capSearch, "search", "catalog_search.json"),
			capLookup: entry(capLookup, "lookup", "catalog_lookup.json"),
		},
		// None. This shop takes no payment here, and an empty registry says
		// so in the shape the spec requires rather than by leaving it out.
		"payment_handlers": map[string]any{},
	}}
	data, _ := json.Marshal(body)
	sum := sha256.Sum256(data)
	tag := `"` + hex.EncodeToString(sum[:12]) + `"`
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("ETag", tag)
	if etag.Matches(r.Header.Get("If-None-Match"), tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(data)
}

// ServeHTTP answers the REST binding under /ucp/.
//
// The order of the checks is the cost of each: the allowance first, so a
// caller over it costs nothing more; then the headers the binding makes
// mandatory; then the body, bounded before it is read.
func (c *Catalog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.URL.Path, "/ucp/")
	switch op {
	case "catalog/search", "catalog/lookup", "catalog/product":
	default:
		transportError(w, http.StatusNotFound, "not_found",
			"this shop's UCP endpoint answers catalog/search, catalog/lookup and catalog/product")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		transportError(w, http.StatusMethodNotAllowed, "method_not_allowed",
			"catalog operations are POST requests")
		return
	}
	if c.Limit != nil {
		if ok, wait := c.Limit.Allow(clientip.SourceFrom(r), c.now()); !ok {
			secs := int(math.Ceil(wait.Seconds()))
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ucp": map[string]any{"status": "error"},
				"messages": []message{{Type: "error", Code: "rate_limited",
					Content: fmt.Sprintf("too many requests from this address; "+
						"try again in %d seconds", secs), Severity: "recoverable"}},
			})
			return
		}
	}
	if err := checkHeaders(w, r); err != nil {
		transportError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/json" {
			transportError(w, http.StatusUnsupportedMediaType, "invalid_request",
				"the request body is application/json")
			return
		}
	}
	switch op {
	case "catalog/search":
		c.search(w, r)
	case "catalog/lookup":
		c.lookup(w, r)
	case "catalog/product":
		c.product(w, r)
	}
}

// checkHeaders enforces the two headers the binding requires of every
// request, and echoes the request id so a caller can follow its request.
//
// UCP-Agent is parsed as the RFC 8941 dictionary it is defined as, and its
// profile must be an https URL. It is a claim, used for nothing here,
// because nothing this answers depends on who is asking; it is checked
// because the binding says every request carries one, and a rule nobody
// enforces is a suggestion.
func checkHeaders(w http.ResponseWriter, r *http.Request) error {
	rid := r.Header.Get("Request-Id")
	if rid == "" || len(rid) > 128 || !printable(rid) {
		return errors.New("every request carries a Request-Id header of at most 128 printable characters")
	}
	w.Header().Set("Request-Id", rid)
	if _, err := agentProfile(r.Header.Values("UCP-Agent")); err != nil {
		return fmt.Errorf("the UCP-Agent header %v; it is an RFC 8941 dictionary with a "+
			`profile member naming the platform's https profile, as profile="https://platform.example/.well-known/ucp"`, err)
	}
	return nil
}

// agentProfile reads the profile member of a UCP-Agent dictionary.
//
// Only as much of RFC 8941 as this needs: members separated by commas, a
// member a key, "=" and a value with optional ";" parameters, the profile's
// value an sf-string. A header that is not that is refused rather than
// guessed at.
func agentProfile(values []string) (string, error) {
	if len(values) != 1 || len(values[0]) > 1024 {
		return "", errors.New("is missing, repeated or too long")
	}
	for _, member := range splitOutsideQuotes(values[0], ',') {
		key, value, found := strings.Cut(strings.TrimSpace(member), "=")
		if !found || key != "profile" {
			continue
		}
		s, rest, ok := sfString(value)
		if !ok || (rest != "" && rest[0] != ';') {
			return "", errors.New("has a profile that is not a quoted string")
		}
		if !strings.HasPrefix(s, "https://") || len(s) > 512 {
			return "", errors.New("names a profile that is not an https URL")
		}
		return s, nil
	}
	return "", errors.New("has no profile member")
}

// sfString reads an RFC 8941 sf-string from the start of s: a double quote,
// visible ASCII with \" and \\ as the only escapes, a closing quote. It
// answers the string and what follows it.
func sfString(s string) (string, string, bool) {
	if s == "" || s[0] != '"' {
		return "", "", false
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			if i+1 == len(s) || (s[i+1] != '"' && s[i+1] != '\\') {
				return "", "", false
			}
			i++
			b.WriteByte(s[i])
		case c == '"':
			return b.String(), s[i+1:], true
		case c < 0x20 || c > 0x7e:
			return "", "", false
		default:
			b.WriteByte(c)
		}
	}
	return "", "", false
}

// splitOutsideQuotes splits on sep where it is not inside a quoted string.
func splitOutsideQuotes(s string, sep byte) []string {
	var out []string
	quoted, escaped, start := false, false, 0
	for i := 0; i < len(s); i++ {
		switch {
		case escaped:
			escaped = false
		case s[i] == '\\' && quoted:
			escaped = true
		case s[i] == '"':
			quoted = !quoted
		case s[i] == sep && !quoted:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// printable is visible ASCII and spaces, which is what a header value that
// will be echoed back or logged may hold.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// The request shapes. Every field the spec defines for these operations is
// accepted, so a conforming platform is never refused for being complete;
// anything else is refused (NIST SP 800-53 SI-10). Context, signals and
// attribution are hints for personalising and measuring, which this does
// neither of, so they are read as JSON objects and not used.
type searchRequest struct {
	Query       *string         `json:"query"`
	Context     json.RawMessage `json:"context"`
	Signals     json.RawMessage `json:"signals"`
	Attribution json.RawMessage `json:"attribution"`
	Filters     json.RawMessage `json:"filters"`
	Pagination  *struct {
		Cursor string `json:"cursor"`
		Limit  *int   `json:"limit"`
	} `json:"pagination"`
}

type lookupRequest struct {
	IDs         []string        `json:"ids"`
	Filters     json.RawMessage `json:"filters"`
	Context     json.RawMessage `json:"context"`
	Signals     json.RawMessage `json:"signals"`
	Attribution json.RawMessage `json:"attribution"`
}

type productRequest struct {
	ID       string `json:"id"`
	Selected []struct {
		Name  string `json:"name"`
		ID    string `json:"id"`
		Label string `json:"label"`
	} `json:"selected"`
	Preferences []string        `json:"preferences"`
	Filters     json.RawMessage `json:"filters"`
	Context     json.RawMessage `json:"context"`
	Signals     json.RawMessage `json:"signals"`
	Attribution json.RawMessage `json:"attribution"`
}

// filters is what the spec's filters object narrows by: categories (any
// of), and a price range in minor units of the context's currency.
type filters struct {
	categories []string
	min, max   *int64
	currency   string
	// unknown are filter names this shop does not apply. The spec lets a
	// shop define its own; one it has not is said, not silently ignored,
	// because an answer that ignored a filter looks exactly like one that
	// applied it.
	unknown []string
}

// decode reads a bounded body strictly into one of the request shapes.
func decode(w http.ResponseWriter, r *http.Request, into any) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		return fmt.Errorf("the body is over %d bytes or could not be read", MaxBody)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("the body is not a request this operation defines: %v", err)
	}
	if dec.More() {
		return errors.New("the body holds more than one JSON value")
	}
	return nil
}

// objectOrAbsent checks that a hint the spec defines as an object is one.
func objectOrAbsent(name string, raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%s is not an object", name)
	}
	return nil
}

// hints checks the three hint objects every catalog request may carry, and
// reads the one this uses: the currency a price filter is stated in.
func hints(context, signals, attribution json.RawMessage) (string, error) {
	for name, raw := range map[string]json.RawMessage{
		"context": context, "signals": signals, "attribution": attribution} {
		if err := objectOrAbsent(name, raw); err != nil {
			return "", err
		}
	}
	if len(context) == 0 || string(context) == "null" {
		return "", nil
	}
	var ctx struct {
		Currency string `json:"currency"`
	}
	_ = json.Unmarshal(context, &ctx)
	return strings.ToUpper(strings.TrimSpace(ctx.Currency)), nil
}

// readFilters parses the filters object.
func readFilters(raw json.RawMessage, currency string) (*filters, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, errors.New("filters is not an object")
	}
	f := &filters{currency: currency}
	for name, v := range all {
		switch name {
		case "categories":
			if err := json.Unmarshal(v, &f.categories); err != nil {
				return nil, errors.New("filters.categories is not a list of strings")
			}
		case "price":
			var p struct {
				Min *int64 `json:"min"`
				Max *int64 `json:"max"`
			}
			dec := json.NewDecoder(bytes.NewReader(v))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil {
				return nil, errors.New("filters.price is not {min, max} in minor units")
			}
			if (p.Min != nil && *p.Min < 0) || (p.Max != nil && *p.Max < 0) {
				return nil, errors.New("filters.price is negative")
			}
			f.min, f.max = p.Min, p.Max
		default:
			f.unknown = append(f.unknown, name)
		}
	}
	sort.Strings(f.unknown)
	return f, nil
}

// keeps reports whether a product passes the filters.
func (f *filters) keeps(p Product) bool {
	if f == nil {
		return true
	}
	if len(f.categories) > 0 {
		in := false
		for _, want := range f.categories {
			for _, have := range p.Categories {
				if strings.EqualFold(want, have.Value) {
					in = true
				}
			}
		}
		if !in {
			return false
		}
	}
	if f.min != nil || f.max != nil {
		price := p.Variants[0].Price
		// A price filter is stated in the context's currency. This shop
		// converts nothing, so a product priced in another currency is not
		// one the filter can say is in range.
		if f.currency != "" && f.currency != price.Currency {
			return false
		}
		if (f.min != nil && price.Amount < *f.min) || (f.max != nil && price.Amount > *f.max) {
			return false
		}
	}
	return true
}

// unsupported is the warning for filters this shop does not apply.
func (f *filters) unsupported() []message {
	if f == nil || len(f.unknown) == 0 {
		return nil
	}
	return []message{{Type: "warning", Code: "filter_unsupported",
		Content: "this shop does not filter by " + strings.Join(f.unknown, ", ") +
			"; those filters did not narrow these results"}}
}

// products reads the catalogue, shaping each row. Rows that are not a
// valid product are left out; a partial read is said in a message.
func (c *Catalog) products() ([]Product, []message, error) {
	rows, total, err := c.Rows(MaxProducts)
	if err != nil {
		return nil, nil, err
	}
	out := make([]Product, 0, len(rows))
	for _, row := range rows {
		if p, problem := FromRow(row, c.Base); problem == "" {
			out = append(out, p)
		}
	}
	var notes []message
	if total > len(rows) {
		notes = append(notes, message{Type: "warning", Code: "catalog_truncated",
			Content: fmt.Sprintf("this answer considered the first %d of %d products",
				len(rows), total)})
	}
	return out, notes, nil
}

// search answers POST /ucp/catalog/search.
func (c *Catalog) search(w http.ResponseWriter, r *http.Request) {
	var req searchRequest
	if err := decode(w, r, &req); err != nil {
		transportError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	currency, err := hints(req.Context, req.Signals, req.Attribution)
	if err != nil {
		transportError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	f, err := readFilters(req.Filters, currency)
	if err != nil {
		transportError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	query := ""
	if req.Query != nil {
		query = strings.TrimSpace(*req.Query)
	}
	// At least one input, as the spec requires: a request with neither a
	// query nor a filter asks for nothing in particular, and the answer to
	// that is not the whole catalogue a page at a time.
	if query == "" && f == nil {
		transportError(w, http.StatusBadRequest, "invalid_request",
			"a search carries a query, filters, or both")
		return
	}
	if len(query) > MaxQuery {
		transportError(w, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("the query is over %d bytes", MaxQuery))
		return
	}
	limit, offset := DefaultPage, 0
	if req.Pagination != nil {
		if req.Pagination.Limit != nil {
			if *req.Pagination.Limit < 1 {
				transportError(w, http.StatusBadRequest, "invalid_request",
					"pagination.limit is at least 1")
				return
			}
			limit = min(*req.Pagination.Limit, MaxPage)
		}
		if req.Pagination.Cursor != "" {
			n, ok := readCursor(req.Pagination.Cursor)
			if !ok {
				transportError(w, http.StatusBadRequest, "invalid_cursor",
					"the cursor is not one this shop issued")
				return
			}
			offset = n
		}
	}
	all, notes, err := c.products()
	if err != nil {
		transportError(w, http.StatusServiceUnavailable, "unavailable",
			"the catalogue could not be read; try again shortly")
		return
	}
	matched := match(all, query, f)
	if offset > len(matched) {
		offset = len(matched)
	}
	end := min(offset+limit, len(matched))
	page := map[string]any{"has_next_page": end < len(matched), "total_count": len(matched)}
	if end < len(matched) {
		page["cursor"] = writeCursor(end)
	}
	body := map[string]any{
		"ucp":        envelope(capSearch, ""),
		"products":   nonNil(matched[offset:end]),
		"pagination": page,
	}
	if msgs := append(notes, f.unsupported()...); len(msgs) > 0 {
		body["messages"] = msgs
	}
	writeJSON(w, http.StatusOK, body)
}

// match keeps the products every query word appears in and the filters
// pass, with those whose title has the whole query first.
//
// Plain word matching over what the product says about itself — title,
// description, SKU, category and the shop's metadata — in the catalogue
// listing's own order. Predictable is the point: an agent that searched for
// "brass pen" can be told exactly why each result is there.
func match(all []Product, query string, f *filters) []Product {
	words := strings.Fields(strings.ToLower(query))
	whole := strings.ToLower(query)
	var first, rest []Product
	for _, p := range all {
		if !f.keeps(p) {
			continue
		}
		hay := strings.ToLower(searchable(p))
		in := true
		for _, word := range words {
			if !strings.Contains(hay, word) {
				in = false
				break
			}
		}
		if !in {
			continue
		}
		if whole != "" && strings.Contains(strings.ToLower(p.Title), whole) {
			first = append(first, p)
		} else {
			rest = append(rest, p)
		}
	}
	return append(first, rest...)
}

// searchable is the text a product is found by.
func searchable(p Product) string {
	parts := []string{p.Title, p.Description.Plain, p.Variants[0].SKU}
	for _, cat := range p.Categories {
		parts = append(parts, cat.Value)
	}
	keys := make([]string, 0, len(p.Metadata))
	for k := range p.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, p.Metadata[k])
	}
	return strings.Join(parts, "\n")
}

// lookup answers POST /ucp/catalog/lookup.
func (c *Catalog) lookup(w http.ResponseWriter, r *http.Request) {
	var req lookupRequest
	if err := decode(w, r, &req); err != nil {
		transportError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	currency, err := hints(req.Context, req.Signals, req.Attribution)
	if err != nil {
		transportError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	f, err := readFilters(req.Filters, currency)
	if err != nil {
		transportError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if len(req.IDs) == 0 {
		transportError(w, http.StatusBadRequest, "invalid_request", "ids names at least one identifier")
		return
	}
	// Deduplicated before the limit is applied, as the spec says to, so a
	// platform repeating an id is not refused for a batch it did not send.
	var ids []string
	seen := map[string]bool{}
	for _, id := range req.IDs {
		if len(id) > MaxID {
			transportError(w, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("an identifier is over %d bytes", MaxID))
			return
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) > MaxLookup {
		transportError(w, http.StatusBadRequest, "request_too_large",
			fmt.Sprintf("a lookup names at most %d identifiers", MaxLookup))
		return
	}
	all, notes, err := c.products()
	if err != nil {
		transportError(w, http.StatusServiceUnavailable, "unavailable",
			"the catalogue could not be read; try again shortly")
		return
	}
	idx := indexOf(all)
	var order []string
	found := map[string]*Product{}
	var msgs []message
	for _, id := range ids {
		p, how, ok := idx.resolve(id)
		if !ok || !f.keeps(*p) {
			msgs = append(msgs, message{Type: "info", Code: "not_found", Content: id})
			continue
		}
		got, already := found[p.ID]
		if !already {
			cp := *p
			cp.Variants = []Variant{p.Variants[0]}
			got = &cp
			found[p.ID] = got
			order = append(order, p.ID)
		}
		got.Variants[0].Inputs = append(got.Variants[0].Inputs, Input{ID: id, Match: how})
	}
	products := make([]Product, 0, len(order))
	for _, id := range order {
		products = append(products, *found[id])
	}
	body := map[string]any{"ucp": envelope(capLookup, ""), "products": products}
	if said := append(append(notes, msgs...), f.unsupported()...); len(said) > 0 {
		body["messages"] = said
	}
	writeJSON(w, http.StatusOK, body)
}

// product answers POST /ucp/catalog/product.
func (c *Catalog) product(w http.ResponseWriter, r *http.Request) {
	var req productRequest
	if err := decode(w, r, &req); err != nil {
		transportError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	currency, err := hints(req.Context, req.Signals, req.Attribution)
	if err != nil {
		transportError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	f, err := readFilters(req.Filters, currency)
	if err != nil {
		transportError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.ID == "" || len(req.ID) > MaxID {
		transportError(w, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("id names one product or variant, in at most %d bytes", MaxID))
		return
	}
	all, notes, err := c.products()
	if err != nil {
		transportError(w, http.StatusServiceUnavailable, "unavailable",
			"the catalogue could not be read; try again shortly")
		return
	}
	p, _, ok := indexOf(all).resolve(req.ID)
	if !ok || !f.keeps(*p) {
		// Not a transport failure: the request was fine and the shop's
		// answer is that it has no such product. Unrecoverable, so an agent
		// does not ask again for the same id.
		writeJSON(w, http.StatusOK, map[string]any{
			"ucp": envelope(capLookup, "error"),
			"messages": []message{{Type: "error", Code: "not_found",
				Content: "no product " + req.ID, Severity: "unrecoverable"}},
		})
		return
	}
	// No options to select among: every product here is one variant, so a
	// selection narrows nothing and the product is answered as it is.
	body := map[string]any{"ucp": envelope(capLookup, ""), "product": p}
	if said := append(notes, f.unsupported()...); len(said) > 0 {
		body["messages"] = said
	}
	writeJSON(w, http.StatusOK, body)
}

// index finds products by the identifiers lookup must support (product and
// variant ids) and those it may (handle, SKU).
type index struct {
	byProduct, byVariant map[string]*Product
}

func indexOf(all []Product) index {
	ix := index{byProduct: map[string]*Product{}, byVariant: map[string]*Product{}}
	for i := range all {
		p := &all[i]
		ix.byProduct[p.ID] = p
		ix.byVariant[p.Variants[0].ID] = p
		if sku := p.Variants[0].SKU; sku != "" {
			if _, taken := ix.byVariant[sku]; !taken {
				ix.byVariant[sku] = p
			}
		}
	}
	return ix
}

// resolve answers the product an identifier names, and whether it named
// the product (the shop chose the variant: "featured") or the variant
// itself ("exact").
func (ix index) resolve(id string) (*Product, string, bool) {
	if p, ok := ix.byVariant[id]; ok {
		return p, "exact", true
	}
	if p, ok := ix.byProduct[id]; ok {
		return p, "featured", true
	}
	return nil, "", false
}

// message is one entry of a response's messages.
type message struct {
	Type     string `json:"type"`
	Code     string `json:"code"`
	Content  string `json:"content"`
	Severity string `json:"severity,omitempty"`
}

// envelope is the response's ucp member: the version, the capability that
// answered, and a status when it is not success.
func envelope(capability, status string) map[string]any {
	e := map[string]any{"version": Version,
		"capabilities": map[string]any{capability: []map[string]any{{"version": Version}}}}
	if status != "" {
		e["status"] = status
	}
	return e
}

// writeJSON writes an answer. Never cached: a price is true when it is
// read, and a search a shared cache kept would be selling at its price.
func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	if e, ok := body["ucp"].(map[string]any); ok {
		e["version"] = Version
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// transportError is a request that could not be processed: an HTTP status,
// and the spec's error body saying why.
func transportError(w http.ResponseWriter, status int, code, content string) {
	writeJSON(w, status, map[string]any{
		"ucp": map[string]any{"status": "error"},
		"messages": []message{{Type: "error", Code: code, Content: content,
			Severity: "unrecoverable"}},
	})
}

// Cursors are opaque to the caller and positions to this shop: an offset,
// encoded so nobody mistakes it for a number to do arithmetic on, and
// checked on the way back in.
func writeCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte("o:" + strconv.Itoa(offset)))
}

func readCursor(s string) (int, bool) {
	if len(s) > 32 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || !strings.HasPrefix(string(raw), "o:") {
		return 0, false
	}
	n, err := strconv.Atoi(string(raw[2:]))
	if err != nil || n < 0 || n > MaxProducts {
		return 0, false
	}
	return n, true
}

// nonNil keeps an empty page an empty list rather than null, which the
// spec's required products array cannot be.
func nonNil(p []Product) []Product {
	if p == nil {
		return []Product{}
	}
	return p
}
