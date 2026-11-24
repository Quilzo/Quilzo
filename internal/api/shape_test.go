// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/vector"
)

// The shape of the API: what each route answers, to which methods, in which
// form, and what its own description says of it.

// shapeServer is a server with everything a server can have turned on: the
// pages, a collection of three records and a vector index. Every route then
// answers as it does somewhere, rather than as the half one host serves.
// The rate limit is set out of the way, because these tests make many
// requests and a 429 halfway through would read as a wrong answer.
func shapeServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	s, readTok, _ := setup(t)
	s.Limits = Limits{PerMinute: 60000, Burst: 10000}
	tree := ""
	for _, c := range "abc" {
		next, _, err := collection.Put(s.Store, tree, "samples", collection.Record{
			ID: strings.Repeat(string(c), 32), Fields: map[string]any{"name": "sample " + string(c)}},
			time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		tree = next
	}
	s.Records = &Records{Tree: func() (string, error) { return tree, nil }}
	live := s.Store.GetRef(site.RefLive)
	pages, err := site.PagesAt(s.Store, live)
	if err != nil {
		t.Fatal(err)
	}
	idx := vector.Build(live, pages, strings.Fields)
	s.Vectors = func() *vector.Index { return idx }
	s.Tokenise = strings.Fields
	return s, readTok, strings.Repeat("a", 32)
}

// description is the openapi.json a server serves, as far as these tests
// read it.
type description struct {
	Paths map[string]map[string]struct {
		Responses map[string]struct {
			Content map[string]struct {
				Schema map[string]any `json:"schema"`
			} `json:"content"`
		} `json:"responses"`
	} `json:"paths"`
	Components struct {
		Schemas map[string]map[string]any `json:"schemas"`
	} `json:"components"`
}

func describedBy(t *testing.T, s *Server) description {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("openapi.json: %d %s", w.Code, w.Body)
	}
	var d description
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// HEAD is answered wherever GET is, as RFC 9110 asks of a server that
// answers GET.
//
// The pages and the description took it and the seven other reads did not:
// collections, a collection's records and one record, similar pages, a search
// by meaning and a replica's ref and object all answered 405 to the HEAD a
// monitor or a cache sends to ask whether something is there.
func TestHEADIsAnsweredWhereGETIs(t *testing.T) {
	s, tok, id := shapeServer(t)
	live := s.Store.GetRef(site.RefLive)
	for _, p := range []string{
		"/api/v1/openapi.json", "/api/v1/pages", "/api/v1/pages/index",
		"/api/v1/collections", "/api/v1/records/samples", "/api/v1/records/samples/" + id,
		"/api/v1/similar/index", "/api/v1/search/vector?q=welcome",
		"/api/v1/replica/ref/live", "/api/v1/replica/object/" + live,
	} {
		get := req(t, s, "GET", p, tok, nil, nil)
		if get.Code != http.StatusOK {
			t.Errorf("GET %s: %d %s", p, get.Code, get.Body)
			continue
		}
		if head := req(t, s, "HEAD", p, tok, nil, nil); head.Code != get.Code {
			t.Errorf("HEAD %s answered %d where GET answers %d", p, head.Code, get.Code)
		}
	}
}

// A 405 says which methods the resource does take, in Allow, as RFC 9110
// requires of every 405, and names only methods that are not refused too.
//
// Only a page's own address set Allow, and there it named PUT whether or not
// the server took writes, while the read-only PUT itself answered 405 with
// no Allow at all. Every other route, the description among them, answered
// 405 with nothing to say what would have worked.
func TestEveryRefusedMethodIsToldWhatIsAllowed(t *testing.T) {
	s, tok, id := shapeServer(t)
	live := s.Store.GetRef(site.RefLive)
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/openapi.json"},
		{"POST", "/api/v1/pages"},
		{"PUT", "/api/v1/pages/index"},
		{"DELETE", "/api/v1/pages/index"},
		{"OPTIONS", "/api/v1/pages/index"},
		{"POST", "/api/v1/collections"},
		{"POST", "/api/v1/records/samples"},
		{"PATCH", "/api/v1/records/samples"},
		{"PUT", "/api/v1/records/samples/" + id},
		{"DELETE", "/api/v1/records/samples/" + id},
		{"POST", "/api/v1/similar/index"},
		{"POST", "/api/v1/search/vector"},
		{"POST", "/api/v1/replica/ref/live"},
		{"POST", "/api/v1/replica/object/" + live},
	} {
		w := req(t, s, c.method, c.path, tok, nil, nil)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s answered %d, not 405", c.method, c.path, w.Code)
			continue
		}
		allow := w.Header().Get("Allow")
		if allow == "" {
			t.Errorf("%s %s answered 405 with no Allow header", c.method, c.path)
			continue
		}
		for _, m := range strings.Split(allow, ",") {
			m = strings.TrimSpace(m)
			if m == c.method {
				t.Errorf("%s %s was refused, and Allow names it: %q", c.method, c.path, allow)
				continue
			}
			if got := req(t, s, m, c.path, tok, nil, nil); got.Code == http.StatusMethodNotAllowed {
				t.Errorf("%s %s: Allow names %s, and that is refused too", c.method, c.path, m)
			}
		}
	}

	// And a server that takes writes says so.
	s.Writable, s.Records.Writable = true, true
	for path, want := range map[string]string{
		"/api/v1/pages/index":           "PUT",
		"/api/v1/records/samples":       "POST",
		"/api/v1/records/samples/" + id: "DELETE",
	} {
		w := req(t, s, "PATCH", path, tok, nil, nil)
		if allow := w.Header().Get("Allow"); !strings.Contains(allow, want) {
			t.Errorf("PATCH %s on a writable server: Allow is %q, without %s", path, allow, want)
		}
	}
}

// Nothing under /api/ answers in anything but JSON.
//
// The API's own router answered what it had no route for: /api/v1 with a
// redirect and an HTML body, and /api/ or /api/v2/pages with a plain-text
// "404 page not found", so a client parsing every answer as JSON failed on
// exactly the answers that were meant to tell it it had the address wrong.
func TestEveryAnswerUnderTheAPIIsJSON(t *testing.T) {
	s, tok, _ := setup(t)
	for _, p := range []string{"/api/v1", "/api/", "/api/v2/pages", "/api/v1x"} {
		w := req(t, s, "GET", p, tok, nil, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s answered %d, not 404", p, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("GET %s answered %s: %q", p, ct, w.Body.String())
			continue
		}
		var e Error
		if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.Error == "" {
			t.Errorf("GET %s is not an error the API writes: %v %q", p, err, w.Body.String())
		}
	}
}

// A listing a token sees only part of is paged through that part: each page
// is as full as the limit allows, next goes on only while there is more of
// what the total counts, and walking it takes total over limit requests.
//
// The total counted what the caller could see, while offset, limit and next
// walked every page in the store. A token limited to some types was handed
// pages with nothing on them where the hidden pages fell, a next link past
// the end of what it could see, and no way to tell an empty page from the
// last one.
func TestAScopedListingPagesThroughWhatItCanSee(t *testing.T) {
	s, scoped := scopedSetup(t, auth.Scope{Types: []string{"article"}})
	// About is bound to a type the token is not limited to, so the token sees
	// index and pricing, which are bound to nothing.
	s.Types = func() (*schema.Store, error) {
		return &schema.Store{Registry: schema.NewRegistry(), Bound: map[string]string{"about": "policy"}}, nil
	}
	next, seen, asked := "/api/v1/pages?limit=1", []string{}, 0
	for next != "" {
		if asked++; asked > 5 {
			t.Fatalf("next never ended: %v", seen)
		}
		w := req(t, s, "GET", next, scoped, nil, nil)
		var l Listing
		if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil {
			t.Fatalf("%s: %d %v", next, w.Code, err)
		}
		if l.Total != 2 {
			t.Errorf("%s: total %d, and the token sees 2", next, l.Total)
		}
		if len(l.Pages) != 1 {
			t.Errorf("%s: a page of a listing one at a time held %d", next, len(l.Pages))
		}
		for _, p := range l.Pages {
			seen = append(seen, p.Name)
		}
		next = l.Next
	}
	if strings.Join(seen, ",") != "index,pricing" || asked != 2 {
		t.Errorf("walking the listing took %d requests and saw %v; want 2 and [index pricing]", asked, seen)
	}
}

// The records listing refuses what the pages listing refuses, and what it
// cannot read as a filter, rather than answering as if it had not been sent.
//
// offset=-5 and offset=abc were taken as 0, order=sideways sorted ascending,
// and a where or contains with no colon filtered nothing, so a client with a
// typo in its query was answered everything, and believed it had asked for
// that.
func TestTheRecordsListingRefusesWhatItCannotRead(t *testing.T) {
	s, tok, _ := shapeServer(t)
	for _, q := range []string{"offset=-5", "offset=abc", "limit=0", "limit=abc",
		"order=sideways", "where=name", "where=:x", "contains=name", "contains=:x"} {
		w := req(t, s, "GET", "/api/v1/records/samples?"+q, tok, nil, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("records ?%s answered %d, not 400: %s", q, w.Code, w.Body)
		}
	}
	for _, q := range []string{"offset=-5", "offset=abc", "limit=0", "limit=abc"} {
		if w := req(t, s, "GET", "/api/v1/pages?"+q, tok, nil, nil); w.Code != http.StatusBadRequest {
			t.Errorf("pages ?%s answered %d, not 400", q, w.Code)
		}
	}
	// And what it can read is still answered.
	for _, q := range []string{"", "offset=0", "offset=2", "limit=1", "order=asc", "order=desc",
		"sort=name&order=desc", "where=name:sample%20a", "contains=name:sam"} {
		if w := req(t, s, "GET", "/api/v1/records/samples?"+q, tok, nil, nil); w.Code != http.StatusOK {
			t.Errorf("records ?%s answered %d: %s", q, w.Code, w.Body)
		}
	}
}

// api.page.max, "the largest page size a listing will answer", bounds every
// listing: the records, similar pages and a search by meaning as well as the
// pages, a limit above it refused and none given answering no more than it.
//
// It bounded only the pages. Set to 10, the records listing still answered a
// limit of 1000, and 50 with none given; similar pages and a search by
// meaning answered 100.
func TestThePageMaximumBoundsEveryListing(t *testing.T) {
	s, tok, _ := shapeServer(t)
	s.MaxPage = 2
	for _, p := range []string{"/api/v1/pages", "/api/v1/records/samples",
		"/api/v1/similar/index", "/api/v1/search/vector?q=welcome"} {
		sep := "?"
		if strings.Contains(p, "?") {
			sep = "&"
		}
		if w := req(t, s, "GET", p+sep+"limit=3", tok, nil, nil); w.Code != http.StatusBadRequest {
			t.Errorf("%s with a limit of 3 against a maximum of 2 answered %d", p, w.Code)
		}
		if w := req(t, s, "GET", p+sep+"limit=2", tok, nil, nil); w.Code != http.StatusOK {
			t.Errorf("%s with a limit of 2 against a maximum of 2 answered %d: %s", p, w.Code, w.Body)
		}
	}
	w := req(t, s, "GET", "/api/v1/records/samples", tok, nil, nil)
	var got struct {
		Records []collection.Record `json:"records"`
		Limit   int                 `json:"limit"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Records) > 2 || got.Limit != 2 {
		t.Errorf("a records listing with no limit against a maximum of 2 answered %d "+
			"records and said its limit was %d", len(got.Records), got.Limit)
	}
}

// A conditional request that answers 304 is not counted against the rate
// limit, as the limiter and the 429 both say.
//
// It was counted: the bucket was spent before the handler ran, so a client
// polling with If-None-Match ran out exactly as fast as one polling without
// it, and was then told in the 429 that it should have used If-None-Match.
func TestA304IsNotCountedAgainstTheRateLimit(t *testing.T) {
	s, tok, _ := setup(t)
	at := time.Now()
	s.Now = func() time.Time { return at }
	s.Limits = Limits{PerMinute: 60, Burst: 3}

	for _, p := range []string{"/api/v1/pages/index", "/api/v1/pages"} {
		first := req(t, s, "GET", p, tok, nil, nil)
		etag, left := first.Header().Get("ETag"), first.Header().Get("RateLimit-Remaining")
		for i := range 10 {
			w := req(t, s, "GET", p, tok, nil, map[string]string{"If-None-Match": etag})
			if w.Code != http.StatusNotModified {
				t.Fatalf("%s: conditional request %d answered %d: %s", p, i+1, w.Code, w.Body)
			}
			if got := w.Header().Get("RateLimit-Remaining"); got != left {
				t.Fatalf("%s: a 304 left %s remaining, where %s were before it", p, got, left)
			}
		}
	}
	// And an answer that is not a 304 is still counted: the third of three.
	if w := req(t, s, "GET", "/api/v1/pages/about", tok, nil, nil); w.Code != http.StatusOK ||
		w.Header().Get("RateLimit-Remaining") != "0" {
		t.Errorf("the third full answer of three: %d, %s remaining", w.Code,
			w.Header().Get("RateLimit-Remaining"))
	}
	if w := req(t, s, "GET", "/api/v1/pages/about", tok, nil, nil); w.Code != http.StatusTooManyRequests {
		t.Errorf("a fourth full answer of three: %d", w.Code)
	}
}

// RateLimit-Reset is never 0 while the limit stands in the way, and a
// refusal's RateLimit-Reset and Retry-After agree.
//
// Both were whole seconds rounded down from different clocks, so at two
// requests a second a refusal said "RateLimit-Reset: 0", the limit resets
// now, beside "Retry-After: 1", and an answer that had spent the last of the
// allowance said the allowance was back already.
func TestARefusalNeverSaysTheLimitResetsNow(t *testing.T) {
	s, tok, _ := setup(t)
	at := time.Now()
	s.Now = func() time.Time { return at }
	s.Limits = Limits{PerMinute: 120, Burst: 1}

	w := req(t, s, "GET", "/api/v1/pages/index", tok, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("%d", w.Code)
	}
	if got := w.Header().Get("RateLimit-Reset"); got == "0" {
		t.Errorf("an answer that spent the whole allowance says it resets now: "+
			"RateLimit-Remaining %s, RateLimit-Reset %s", w.Header().Get("RateLimit-Remaining"), got)
	}
	w = req(t, s, "GET", "/api/v1/pages/index", tok, nil, nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("a second request of a burst of one answered %d", w.Code)
	}
	reset, retry := w.Header().Get("RateLimit-Reset"), w.Header().Get("Retry-After")
	if n, err := strconv.Atoi(reset); err != nil || n < 1 || reset != retry {
		t.Errorf("a refusal said RateLimit-Reset %q and Retry-After %q", reset, retry)
	}
}

// A write refused by its content type is told where the type can be read,
// and the place it names exists.
//
// Both write paths said "GET /api/v1/types to see what the type requires",
// and there is no /api/v1/types: it answered 404 "no such endpoint".
func TestATypeRefusalNamesWhereTheTypeIsRead(t *testing.T) {
	s, tok, _ := shapeServer(t)
	st := &schema.Store{Registry: schema.NewRegistry(),
		Bound:       map[string]string{"index": "priced"},
		Collections: map[string]string{"samples": "priced"}}
	if err := st.Registry.Add(schema.Type{Name: "priced", Fields: []schema.Field{
		{Name: "price", Kind: schema.Number, Required: true}}}); err != nil {
		t.Fatal(err)
	}
	s.Types = func() (*schema.Store, error) { return st, nil }
	s.Writable, s.Records.Writable = true, true
	s.Records.Commit = func(string, string, string) error { return nil }
	writer := writerOf(t, s)

	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/records/samples"},
		{"PUT", "/api/v1/pages/index"},
	} {
		w := req(t, s, c.method, c.path, writer, map[string]any{"name": "no price"},
			map[string]string{"If-Match": "*"})
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s %s: %d, not 422: %s", c.method, c.path, w.Code, w.Body)
			continue
		}
		var e Error
		_ = json.Unmarshal(w.Body.Bytes(), &e)
		if !strings.Contains(e.Fix, "quilzo type show priced") {
			t.Errorf("%s %s: the fix does not name the type to read: %q", c.method, c.path, e.Fix)
		}
		if strings.HasPrefix(e.Fix, "GET /") {
			named := strings.Fields(e.Fix)[1]
			if got := req(t, s, "GET", named, tok, nil, nil); got.Code == http.StatusNotFound {
				t.Errorf("%s %s: the fix names %s, which answers 404", c.method, c.path, named)
			}
		}
	}
}

// writerOf is a token that may write the pages and the samples collection.
func writerOf(t *testing.T, s *Server) string {
	t.Helper()
	for _, res := range []string{"/", auth.DataResource("samples")} {
		if err := s.Policy.Grant(auth.Binding{Principal: "editor", Role: auth.RoleAuthor, Resource: res}); err != nil {
			t.Fatal(err)
		}
	}
	tok, _, err := s.Tokens.Issue("editor", "editor", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// The description a server serves is of what that server serves: every read
// it describes answers.
//
// It was the same for every server, and each served half of it: the site,
// with no records, answered 404 "this server does not serve records" for the
// collections and records it described, and the admin, with no vector index,
// 404 "no vector index" for similar pages and a search by meaning.
func TestEachServerDescribesWhatItServes(t *testing.T) {
	siteLike, siteTok, _ := shapeServer(t)
	siteLike.Records = nil
	adminLike, adminTok, id := shapeServer(t)
	adminLike.Vectors, adminLike.Tokenise = nil, nil
	for name, c := range map[string]struct {
		s   *Server
		tok string
	}{"the site": {siteLike, siteTok}, "the admin": {adminLike, adminTok}} {
		live := c.s.Store.GetRef(site.RefLive)
		for p, ops := range describedBy(t, c.s).Paths {
			if _, ok := ops["get"]; !ok {
				continue
			}
			path := strings.NewReplacer("{name}", "index", "{collection}", "samples",
				"{ref}", "live").Replace(p)
			tok := c.tok
			// A module's route is tried as its own test file says, with a
			// token that may read it (moduleExamples).
			if moduleRoute(strings.SplitN(p, "{", 2)[0]) {
				ex, ok := moduleExamples[p]
				if !ok {
					t.Errorf("%s is a module's and no test file of the module says how to try it", p)
					continue
				}
				path, tok = ex(t, c.s)
				if w := req(t, c.s, "GET", path, tok, nil, nil); w.Code != http.StatusOK {
					t.Errorf("%s describes %s, and GET %s answers %d: %s", name, p, path, w.Code, w.Body)
				}
				continue
			}
			switch {
			case strings.HasPrefix(path, "/api/v1/replica/object/"):
				path = strings.Replace(path, "{id}", live, 1)
			case strings.HasPrefix(path, "/api/v1/search/vector"):
				path += "?q=welcome"
			default:
				path = strings.Replace(path, "{id}", id, 1)
			}
			if w := req(t, c.s, "GET", path, c.tok, nil, nil); w.Code != http.StatusOK {
				t.Errorf("%s describes %s, and GET %s answers %d: %s", name, p, path, w.Code, w.Body)
			}
		}
	}
	// And a server with everything describes everything.
	all, _, _ := shapeServer(t)
	if got, want := len(describedBy(t, all).Paths), len(OpenAPI()["paths"].(map[string]any)); got != want {
		t.Errorf("a server serving every route describes %d of %d paths", got, want)
	}
}

// The description lists the answers each operation gives: the 304 of a
// listing, the 405 of a write a read-only server refuses, the 413 of a body
// or a query too large, the 422 of content its type refuses, the 503 of an
// API turned off for a while, and the replica's object as the JSON envelope
// it is, not as raw bytes.
func TestTheDescriptionListsTheAnswersOperationsGive(t *testing.T) {
	s, tok, _ := shapeServer(t)
	st := &schema.Store{Registry: schema.NewRegistry(),
		Bound:       map[string]string{"index": "priced"},
		Collections: map[string]string{"samples": "priced"}}
	if err := st.Registry.Add(schema.Type{Name: "priced", Fields: []schema.Field{
		{Name: "price", Kind: schema.Number, Required: true}}}); err != nil {
		t.Fatal(err)
	}
	s.Types = func() (*schema.Store, error) { return st, nil }
	s.Records.Commit = func(string, string, string) error { return nil }
	writer := writerOf(t, s)
	d := describedBy(t, s)
	listed := func(method, tmpl string, w *httptest.ResponseRecorder) {
		t.Helper()
		code := strconv.Itoa(w.Code)
		if _, ok := d.Paths[tmpl][method].Responses[code]; !ok {
			t.Errorf("%s %s answers %s (%s), which its description does not list",
				method, tmpl, code, strings.TrimSpace(w.Body.String()))
		}
	}

	etag := req(t, s, "GET", "/api/v1/pages", tok, nil, nil).Header().Get("ETag")
	listed("get", "/api/v1/pages", req(t, s, "GET", "/api/v1/pages", tok, nil,
		map[string]string{"If-None-Match": etag}))
	listed("put", "/api/v1/pages/{name}", req(t, s, "PUT", "/api/v1/pages/index", writer,
		map[string]any{"title": "x"}, map[string]string{"If-Match": "*"}))
	listed("post", "/api/v1/records/{collection}", req(t, s, "POST", "/api/v1/records/samples", writer,
		map[string]any{"price": 1}, nil))
	listed("get", "/api/v1/search/vector", req(t, s, "GET",
		"/api/v1/search/vector?q="+strings.Repeat("a", 2001), tok, nil, nil))

	s.Writable, s.Records.Writable = true, true
	listed("put", "/api/v1/pages/{name}", req(t, s, "PUT", "/api/v1/pages/index", writer,
		map[string]any{"title": "no price"}, map[string]string{"If-Match": "*"}))
	listed("post", "/api/v1/records/{collection}", req(t, s, "POST", "/api/v1/records/samples", writer,
		map[string]any{"name": "no price"}, nil))
	s.MaxBody = 16
	listed("put", "/api/v1/pages/{name}", req(t, s, "PUT", "/api/v1/pages/index", writer,
		map[string]any{"title": strings.Repeat("x", 32)}, map[string]string{"If-Match": "*"}))
	listed("post", "/api/v1/records/{collection}", req(t, s, "POST", "/api/v1/records/samples", writer,
		map[string]any{"name": strings.Repeat("x", 32)}, nil))

	s.Shield = func() (time.Time, bool) { return time.Now().Add(time.Minute), true }
	listed("get", "/api/v1/pages", req(t, s, "GET", "/api/v1/pages", tok, nil, nil))

	object := d.Paths["/api/v1/replica/object/{id}"]["get"].Responses["200"].Content["application/json"].Schema
	if ref, ok := object["$ref"].(string); ok {
		object = d.Components.Schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
	}
	if props, _ := object["properties"].(map[string]any); props["payload"] == nil || props["kind"] == nil {
		t.Errorf("the replica's object is described as %v, not as the JSON envelope it is", object)
	}
}
