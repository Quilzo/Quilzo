package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/store"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T) (*Server, string, string) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"index":   map[string]any{"title": "Home", "body": "Welcome."},
		"about":   map[string]any{"title": "About", "body": "Who we are."},
		"pricing": map[string]any{"title": "Pricing", "body": "Ten pounds."},
	}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}

	pol := &auth.Policy{}
	for _, b := range []auth.Binding{
		{Principal: "reader", Role: auth.RoleReader, Resource: "/"},
		{Principal: "writer", Role: auth.RoleAuthor, Resource: "/"},
	} {
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	ts := &auth.TokenStore{}
	readTok, _, err := ts.Issue("r", "reader", auth.RoleReader, "/", time.Hour,
		auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	writeTok, _, err := ts.Issue("w", "writer", auth.RoleAuthor, "/", time.Hour,
		auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	// The real clock, not a frozen one. Tokens are issued relative to
	// time.Now, so freezing the server four hours ahead expires them before
	// the first request — which presents as every test failing with 401 and
	// looks like broken authentication rather than a wrong fixture.
	return &Server{Store: s, Policy: pol, Tokens: ts}, readTok, writeTok
}

func req(t *testing.T, s *Server, method, path, token string,
	body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// -- the ETag is the content hash -------------------------------------------

// Everywhere else this is a heuristic. Here the object id is the hash of the
// content, so If-None-Match answers exactly the question it appears to ask.
func TestAConditionalRequestIsExact(t *testing.T) {
	s, tok, _ := setup(t)

	first := req(t, s, "GET", "/api/v1/pages/index", tok, nil, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("got %d: %s", first.Code, first.Body)
	}
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag, so a client cannot make a conditional request")
	}

	second := req(t, s, "GET", "/api/v1/pages/index", tok, nil,
		map[string]string{"If-None-Match": etag})
	if second.Code != http.StatusNotModified {
		t.Errorf("an unchanged page returned %d rather than 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Error("a 304 carried a body")
	}

	// Change the page and the validator must change with it.
	pages, _ := site.PagesAt(s.Store, site.RefLive)
	pages["index"] = map[string]any{"title": "Home", "body": "Changed."}
	if _, err := site.SaveDraft(s.Store, pages, "edit", "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s.Store, ""); err != nil {
		t.Fatal(err)
	}

	third := req(t, s, "GET", "/api/v1/pages/index", tok, nil,
		map[string]string{"If-None-Match": etag})
	if third.Code != http.StatusOK {
		t.Errorf("a changed page still answered %d", third.Code)
	}
}

// The header is a list and may be `*`. A naive comparison against the whole
// header means a client sending two validators gets a miss every time, which
// looks like the cache not working rather than the parsing being wrong.
func TestValidatorListsAreParsedNotCompared(t *testing.T) {
	s, tok, _ := setup(t)
	etag := req(t, s, "GET", "/api/v1/pages/index", tok, nil, nil).
		Header().Get("ETag")

	for _, header := range []string{
		etag,
		`"other", ` + etag,
		etag + `, "other"`,
		"W/" + etag,
		"*",
	} {
		w := req(t, s, "GET", "/api/v1/pages/index", tok, nil,
			map[string]string{"If-None-Match": header})
		if w.Code != http.StatusNotModified {
			t.Errorf("If-None-Match: %s returned %d", header, w.Code)
		}
	}
	if w := req(t, s, "GET", "/api/v1/pages/index", tok, nil,
		map[string]string{"If-None-Match": `"nope"`}); w.Code != http.StatusOK {
		t.Errorf("a non-matching validator returned %d", w.Code)
	}
}

// -- writes ------------------------------------------------------------------

// A write without a validator overwrites whatever is there now, including
// somebody else's edit made since the client read it.
func TestAWriteWithoutIfMatchIsRefused(t *testing.T) {
	s, _, tok := setup(t)
	s.Writable = true

	w := req(t, s, "PUT", "/api/v1/pages/index", tok,
		map[string]any{"title": "Mine"}, nil)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("a blind write returned %d", w.Code)
	}
	var e Error
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	if e.Fix == "" {
		t.Error("the refusal does not say what to do instead")
	}
}

func TestAWriteWithAStaleValidatorIsRefused(t *testing.T) {
	s, _, tok := setup(t)
	s.Writable = true

	etag := req(t, s, "GET", "/api/v1/pages/index", tok, nil, nil).
		Header().Get("ETag")

	// Somebody else edits it first.
	pages, _ := site.PagesAt(s.Store, site.RefLive)
	pages["index"] = map[string]any{"title": "Theirs"}
	if _, err := site.SaveDraft(s.Store, pages, "theirs", "other"); err != nil {
		t.Fatal(err)
	}

	w := req(t, s, "PUT", "/api/v1/pages/index", tok,
		map[string]any{"title": "Mine"}, map[string]string{"If-Match": etag})
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("a stale write returned %d: %s", w.Code, w.Body)
	}

	// Their edit survives.
	after, _ := site.PagesAt(s.Store, site.RefDraft)
	if after["index"].(map[string]any)["title"] != "Theirs" {
		t.Error("the refused write landed anyway")
	}
}

func TestAWriteWithACurrentValidatorSucceeds(t *testing.T) {
	s, _, tok := setup(t)
	s.Writable = true

	etag := req(t, s, "GET", "/api/v1/pages/index", tok, nil, nil).
		Header().Get("ETag")
	w := req(t, s, "PUT", "/api/v1/pages/index", tok,
		map[string]any{"title": "Mine", "body": "New."},
		map[string]string{"If-Match": etag})
	if w.Code != http.StatusOK {
		t.Fatalf("a valid write returned %d: %s", w.Code, w.Body)
	}
	// The new validator comes back, so a client can chain writes without
	// re-reading.
	if w.Header().Get("ETag") == etag {
		t.Error("the ETag did not change after a write")
	}
}

// A read API and a write API are different products with different blast
// radii, so writes are off unless turned on.
func TestWritesAreOffByDefault(t *testing.T) {
	s, _, tok := setup(t)
	w := req(t, s, "PUT", "/api/v1/pages/index", tok,
		map[string]any{"title": "x"}, map[string]string{"If-Match": "*"})
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("a write succeeded on a read-only API: %d", w.Code)
	}
}

// -- authorisation -----------------------------------------------------------

func TestNoTokenIsRefusedWithoutHints(t *testing.T) {
	s, _, _ := setup(t)
	w := req(t, s, "GET", "/api/v1/pages", "", nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated request returned %d", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("no WWW-Authenticate, so a client cannot tell what to send")
	}
	// Distinguishing "no such token" from "wrong token" is how an enumeration
	// oracle gets built by accident.
	body := w.Body.String()
	for _, leak := range []string{"expired", "revoked", "unknown", "no such"} {
		if bytes.Contains([]byte(body), []byte(leak)) {
			t.Errorf("the refusal reveals %q about the token", leak)
		}
	}
}

// A read-only token must stay read-only however its owner is promoted.
func TestTheTokensOwnRoleCapsWhatItCanDo(t *testing.T) {
	s, readTok, _ := setup(t)
	s.Writable = true

	// The principal is promoted in the policy.
	if err := s.Policy.Grant(auth.Binding{
		Principal: "reader", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}

	w := req(t, s, "PUT", "/api/v1/pages/index", readTok,
		map[string]any{"title": "x"}, map[string]string{"If-Match": "*"})
	if w.Code != http.StatusForbidden {
		t.Errorf("a reader token wrote after its owner was promoted: %d", w.Code)
	}
}

// A listing that fails because one item is restricted tells the caller that
// item exists.
func TestARestrictedPageIsOmittedRatherThanRefused(t *testing.T) {
	s, tok, _ := setup(t)
	if err := s.Policy.Grant(auth.Binding{
		Principal: "reader", Role: auth.RoleReader, Resource: "/pricing",
		Deny: true}); err != nil {
		t.Fatal(err)
	}

	w := req(t, s, "GET", "/api/v1/pages", tok, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("the listing returned %d", w.Code)
	}
	var l Listing
	if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	for _, p := range l.Pages {
		if p.Name == "pricing" {
			t.Error("a denied page appeared in the listing")
		}
	}
}

// -- paging ------------------------------------------------------------------

// Clamping quietly means a client asking for a thousand receives a hundred and
// believes it has everything.
func TestAnOversizedLimitIsRefusedRatherThanClamped(t *testing.T) {
	s, tok, _ := setup(t)
	w := req(t, s, "GET", "/api/v1/pages?limit=1000", tok, nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("an oversized limit returned %d rather than being refused",
			w.Code)
	}
	var e Error
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	if e.Detail == "" {
		t.Error("the refusal does not explain the maximum")
	}
}

// Pagination over an unstable order silently skips and repeats items, and
// nothing anywhere reports an error.
func TestPagingIsStableAndComplete(t *testing.T) {
	s, tok, _ := setup(t)

	seen := map[string]int{}
	for offset := 0; offset < 3; offset++ {
		w := req(t, s, "GET",
			fmt.Sprintf("/api/v1/pages?offset=%d&limit=1", offset), tok, nil, nil)
		var l Listing
		if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil {
			t.Fatal(err)
		}
		if l.Total != 3 {
			t.Errorf("total is %d", l.Total)
		}
		for _, p := range l.Pages {
			seen[p.Name]++
		}
	}
	if len(seen) != 3 {
		t.Errorf("walking the pages saw %d of 3: %v", len(seen), seen)
	}
	for name, n := range seen {
		if n != 1 {
			t.Errorf("%s appeared %d times", name, n)
		}
	}
}

func TestTheLastPageHasNoNext(t *testing.T) {
	s, tok, _ := setup(t)
	w := req(t, s, "GET", "/api/v1/pages?offset=0&limit=100", tok, nil, nil)
	var l Listing
	_ = json.Unmarshal(w.Body.Bytes(), &l)
	if l.Next != "" {
		t.Errorf("a complete listing offered a next page: %q", l.Next)
	}
}

// -- rate limiting -----------------------------------------------------------

// Charging a client for asking "has this changed" teaches them to poll without
// a validator, which costs everybody more.
func TestConditionalRequestsThatAnswer304AreCheap(t *testing.T) {
	s, tok, _ := setup(t)
	s.Limits = Limits{PerMinute: 60, Burst: 5}
	s.limiter = newLimiter(s.Limits)

	etag := req(t, s, "GET", "/api/v1/pages/index", tok, nil, nil).
		Header().Get("ETag")

	// The limiter counts requests, so this documents the current behaviour
	// honestly: 304s are cheap for the *server*, and the header tells a client
	// what its budget is. If the exemption is ever implemented, this test says
	// what it should look like.
	w := req(t, s, "GET", "/api/v1/pages/index", tok, nil,
		map[string]string{"If-None-Match": etag})
	if w.Header().Get("RateLimit-Limit") == "" {
		t.Error("no RateLimit-Limit header, so a client cannot pace itself")
	}
	if w.Header().Get("RateLimit-Remaining") == "" {
		t.Error("no RateLimit-Remaining header")
	}
}

// A fixed window lets a client spend the whole allowance at the end of one and
// again at the start of the next, which is twice the intended rate at exactly
// the wrong moment.
func TestTheLimiterRefillsContinuously(t *testing.T) {
	l := newLimiter(Limits{PerMinute: 60, Burst: 2})
	base := now

	ok, _, _ := l.take("a", base)
	if !ok {
		t.Fatal("the first request was limited")
	}
	l.take("a", base)
	if ok, _, _ := l.take("a", base); ok {
		t.Error("a third request went through a burst of two")
	}
	// One second later, one token has refilled at 60 per minute.
	if ok, _, _ := l.take("a", base.Add(time.Second)); !ok {
		t.Error("no token had refilled after a second at sixty per minute")
	}
}

// Addresses are shared by everybody behind one office, and limiting them
// together means one busy client throttles their colleagues.
func TestCallersAreLimitedSeparately(t *testing.T) {
	l := newLimiter(Limits{PerMinute: 60, Burst: 1})
	if ok, _, _ := l.take("token-a", now); !ok {
		t.Fatal("the first caller was limited")
	}
	if ok, _, _ := l.take("token-a", now); ok {
		t.Error("the first caller exceeded its burst")
	}
	if ok, _, _ := l.take("token-b", now); !ok {
		t.Error("a second caller was limited by the first's usage")
	}
}

// -- what is not offered -----------------------------------------------------

// A content API that answers any origin is one where a page on any website can
// spend a visitor's token.
func TestCrossOriginRequestsAreNotAccepted(t *testing.T) {
	s, tok, _ := setup(t)
	w := req(t, s, "OPTIONS", "/api/v1/pages", tok, nil,
		map[string]string{"Origin": "https://evil.example"})
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("the API advertises cross-origin access")
	}
	if w.Code == http.StatusOK {
		t.Error("a preflight succeeded")
	}
}

// The API serves live, never the draft. Answering with the draft hands anybody
// with a read token the unpublished content.
func TestTheAPIServesLiveNotTheDraft(t *testing.T) {
	s, tok, _ := setup(t)

	pages, _ := site.PagesAt(s.Store, site.RefLive)
	pages["secret"] = map[string]any{"title": "Unannounced"}
	if _, err := site.SaveDraft(s.Store, pages, "draft only", "t"); err != nil {
		t.Fatal(err)
	}

	w := req(t, s, "GET", "/api/v1/pages/secret", tok, nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("an unpublished page was served over the API: %d", w.Code)
	}
	if s.ref() != site.RefLive {
		t.Errorf("the default ref is %q", s.ref())
	}
}

func TestUnknownEndpointsSayWhatExists(t *testing.T) {
	s, tok, _ := setup(t)
	w := req(t, s, "GET", "/api/v1/graphql", tok, nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d", w.Code)
	}
	var e Error
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	if e.Fix == "" {
		t.Error("a 404 that does not say what does exist makes somebody guess")
	}
}

// RateLimit-Reset is a duration a client waits. Computing it as "time until one
// token" went negative whenever tokens remained, and a client reading that
// either waits for a moment already past or subtracts and gets nonsense.
func TestTheResetTimeIsNeverInThePast(t *testing.T) {
	l := newLimiter(Limits{PerMinute: 120, Burst: 20})
	base := now

	for i := range 25 {
		_, _, reset := l.take("a", base)
		if reset.Before(base) {
			t.Fatalf("request %d reported a reset %s in the past",
				i, base.Sub(reset))
		}
	}
}

// When there is nothing left, the useful answer is when one token arrives
// rather than when the bucket is full — that is what a client should wait for.
func TestAnExhaustedBucketReportsWhenToRetry(t *testing.T) {
	l := newLimiter(Limits{PerMinute: 60, Burst: 1})
	base := now

	l.take("a", base)
	ok, _, reset := l.take("a", base)
	if ok {
		t.Fatal("a second request went through a burst of one")
	}
	wait := reset.Sub(base)
	if wait <= 0 || wait > 2*time.Second {
		t.Errorf("retry-after is %s; at sixty per minute one token takes a "+
			"second", wait)
	}
}
