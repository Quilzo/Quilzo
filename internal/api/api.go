// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package api is the HTTP content API.
//
// # REST, and why not GraphQL
//
// GraphQL exists so a client can traverse a graph and choose which fields come
// back. There is no graph here. Content types in this program are flat by
// design — no nesting, no references, no recursion — because those are the
// three keywords that make schema validators exploitable, and removing them was
// a deliberate decision rather than a limitation.
//
// So GraphQL would be a query language for a shape that does not exist, and it
// would arrive with an attack surface that has to be closed off one control at
// a time: introspection disclosing the schema, field suggestions disclosing it
// anyway once introspection is off, query depth turning one request into
// exponential work, aliasing multiplying the cost of one expensive field two
// hundred times inside a single operation, and batching slipping past any rate
// limiter that counts HTTP requests. Each of those is a knob somebody has to
// set correctly forever.
//
// REST over a flat collection needs none of them. The cost of a request is
// bounded by its path.
//
// # The ETag is the content hash, so a conditional request is exact
//
// Everywhere else this uses heuristics — a modification time, a version column,
// a hash of the serialised response. Here the object id *is* the hash of the
// content, so `If-None-Match` answers exactly the question it appears to ask:
// are these the bytes you already have. There is no window where the content
// changed and the validator did not.
//
// The same identity does concurrency control. `If-Match` on a write is
// compare-and-swap, and it maps onto the store's own mechanism rather than
// being a second one bolted alongside — a client that writes without it is
// writing blind, and a client that writes with a stale one is refused.
//
// # What this deliberately does not do
//
// No cross-origin access by default. A content API that answers any origin is
// one where a page on any website can spend a visitor's token, and "it is only
// reads" stops being true the first time somebody enables writes.
//
// No wildcard field selection, no filter expressions, no sort parameters
// evaluated from a query string. Those are a query language arriving through
// the back door, and the reasoning that removed regular expressions from
// content types applies unchanged.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	tag "github.com/quilzo/quilzo/internal/etag"
)

// MaxPageSize bounds a listing.
//
// A limit rather than a preference: without one, a client asking for everything
// decides how much memory a response takes, and the client asking is not always
// the one paying.
const MaxPageSize = 100

// DefaultPageSize is what a request without a size gets.
const DefaultPageSize = 25

// MaxBodyBytes bounds a write.
const MaxBodyBytes = 2 << 20

// Error is what a failure looks like on the wire.
//
// One shape for every error, because a client writing error handling against an
// API that returns three shapes writes handling for the one it saw.
type Error struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
	// Fix names what to do, where there is something to do. An API that reports
	// a problem without saying what would resolve it produces support tickets.
	Fix string `json:"fix,omitempty"`
}

// Page is one page as the API presents it.
type Page struct {
	Name   string         `json:"name"`
	Fields map[string]any `json:"fields"`
	// ETag is the object id, which is the hash of the content. Returned in the
	// body as well as the header so a client that stores a listing keeps the
	// validator alongside each item rather than only for the listing.
	ETag string `json:"etag"`
	// Type is the content type this page is bound to, if any.
	Type string `json:"type,omitempty"`
}

// Listing is a page of pages.
type Listing struct {
	Pages []Page `json:"pages"`
	// Total is how many exist, so a client can tell a short page from the last
	// one without another request.
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
	// Next is the URL of the following page, absent on the last. A cursor a
	// client builds itself is a cursor that breaks when the shape changes.
	Next string `json:"next,omitempty"`
	// Commit is the state this listing describes, so a client can tell whether
	// two requests saw the same site.
	Commit string `json:"commit"`
}

// Limits is the rate limit for one caller.
type Limits struct {
	// PerMinute is how many requests are allowed.
	PerMinute int
	// Burst allows a short spike, because a client fetching a listing and then
	// its items in parallel is behaving normally.
	Burst int
}

func (l Limits) withDefaults() Limits {
	if l.PerMinute <= 0 {
		l.PerMinute = 120
	}
	if l.Burst <= 0 {
		l.Burst = 20
	}
	return l
}

// limiter is a token bucket per caller.
//
// Conditional requests that answer 304 are not counted, which is the behaviour
// GitHub's API has and the reason is worth stating: charging a client for
// asking "has this changed" teaches them to poll without a validator, which
// costs everybody more. The cheap path has to be the cheap path.
//
// Not counted by giving the token back (give) once the answer is known to be
// a 304, rather than by letting a conditional request past the bucket. The
// token is taken before the handler runs, so an empty bucket still refuses
// everything and the limit still bounds the work a caller can ask for; a
// header naming a validator is not a way round it. Nothing gave it back at
// first, so a client polling with If-None-Match ran out as fast as one
// polling without, and the 429 then told it to use If-None-Match.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limits  Limits
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(l Limits) *limiter {
	return &limiter{buckets: map[string]*bucket{}, limits: l.withDefaults()}
}

// take consumes a token, returning whether the request may proceed and how many
// remain.
func (l *limiter) take(key string, now time.Time) (bool, int, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: float64(l.limits.Burst), last: now}
		l.buckets[key] = b
	}
	// Refill continuously rather than in windows. A fixed window lets a client
	// spend the whole allowance at the end of one and again at the start of the
	// next, which is twice the intended rate at exactly the wrong moment.
	rate := float64(l.limits.PerMinute) / 60
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > float64(l.limits.Burst) {
		b.tokens = float64(l.limits.Burst)
	}
	b.last = now

	if b.tokens < 1 {
		// When there is nothing left, the useful answer is when one token
		// arrives rather than when the bucket is full — that is what a client
		// should wait for before retrying.
		return false, 0, now.Add(time.Duration((1 - b.tokens) / rate * float64(time.Second)))
	}
	b.tokens--
	// Full again counting the token just spent. Counted before it was, an
	// answer that spent the last of a burst of one said the bucket was full
	// already.
	return true, int(b.tokens), l.full(b, now)
}

// full is when a bucket is full again, which is what RateLimit-Reset means
// and is never in the past. Computing it as "time until one token" gave a
// negative value whenever tokens remained — a client reading that as a
// duration waits for a moment that has already passed, or subtracts and gets
// nonsense.
func (l *limiter) full(b *bucket, now time.Time) time.Time {
	rate := float64(l.limits.PerMinute) / 60
	full := (float64(l.limits.Burst) - b.tokens) / rate
	if full < 0 {
		full = 0
	}
	return now.Add(time.Duration(full * float64(time.Second)))
}

// give returns the token a request took, for an answer that is not counted
// (a 304), and reports what then remains and when the bucket is full, for
// that answer's headers.
func (l *limiter) give(key string, now time.Time) (int, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		// Forgotten in between by a sweep, which leaves the caller a full
		// bucket on its next request: there is nothing to give back to.
		return l.limits.Burst, now
	}
	b.tokens++
	if b.tokens > float64(l.limits.Burst) {
		b.tokens = float64(l.limits.Burst)
	}
	return int(b.tokens), l.full(b, now)
}

// secondsUntil is how long from now until t, in whole seconds rounded up, for
// RateLimit-Reset and Retry-After.
//
// Rounded up, and from the one clock the limiter was asked with. Both headers
// were rounded down, from the real clock rather than the server's, and one of
// them had a second added: at two requests a second a refusal said
// "RateLimit-Reset: 0", the limit resets now, beside "Retry-After: 1", and an
// answer that had spent the last of the allowance said it was back already.
func secondsUntil(t, now time.Time) int {
	d := t.Sub(now)
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}

// forget drops buckets nobody has used, so the map does not grow with every
// caller that ever appeared.
func (l *limiter) forget(before time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.last.Before(before) {
			delete(l.buckets, k)
		}
	}
}

// writeJSON sends a response with the headers a client needs.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// A content API is not a website and must never be interpreted as one.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, e Error) {
	writeJSON(w, status, e)
}

// parsePaging reads offset and limit, refusing what is out of range rather than
// silently clamping.
//
// Clamping quietly means a client asking for a thousand receives a hundred and
// believes it has everything. Refusing means they find out now.
func parsePaging(q map[string][]string, max int) (offset, limit int, err error) {
	if max <= 0 {
		max = MaxPageSize
	}
	limit = DefaultPageSize
	if limit > max {
		// A configured maximum below the default is an operator asking for
		// small pages, not a contradiction to refuse.
		limit = max
	}
	if v := first(q, "limit"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 {
			return 0, 0, fmt.Errorf("limit must be a positive number")
		}
		if n > max {
			return 0, 0, fmt.Errorf(
				"limit is %d and the maximum is %d. Returning fewer than asked "+
					"for without saying so is how a client comes to believe it "+
					"has everything", n, max)
		}
		limit = n
	}
	if v := first(q, "offset"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 0 {
			return 0, 0, fmt.Errorf("offset must be zero or more")
		}
		offset = n
	}
	return offset, limit, nil
}

func first(q map[string][]string, key string) string {
	if v := q[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// matches reports whether an If-None-Match or If-Match header covers an etag.
//
// The parsing lives in internal/etag, because the public server had three
// copies of a naive `match == etag` comparison while this correct one sat in
// here. One implementation is the whole point; this stays as a name because
// the call sites read better for it.
func matches(header, etag string) bool { return tag.Matches(header, etag) }

// quote formats an object id as a strong entity tag.
func quote(etag string) string { return `"` + etag + `"` }

// sortedNames returns page names in a stable order.
//
// Stable, because pagination over an unstable order silently skips and repeats
// items — a client walking offsets sees page three twice and never sees page
// four, and nothing anywhere reports an error.
func sortedNames(pages map[string]any) []string {
	out := make([]string, 0, len(pages))
	for n := range pages {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
