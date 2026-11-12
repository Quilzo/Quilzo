// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/fetch"
)

// flaky answers the given statuses in turn, then the last one forever.
func flaky(statuses ...int) (*Client, *[]sent) {
	var calls []sent
	return &Client{
		Secrets: func(string) (string, error) { return "s3cret", nil },
		Wait:    func(int, string) time.Duration { return 0 },
		DoMethod: func(_ context.Context, method, url string, body []byte, headers map[string]string) (*fetch.Result, error) {
			calls = append(calls, sent{method, url, string(body), headers})
			st := statuses[min(len(calls)-1, len(statuses)-1)]
			if st == 0 {
				return nil, errors.New("connection reset")
			}
			return &fetch.Result{Status: st, Body: []byte(`{"ok":true}`), Header: http.Header{"Retry-After": {"1"}}}, nil
		},
	}, &calls
}

// A write named by its step carries its key, and is tried again when the
// far side was busy; a write with no key is never repeated; a read is.
func TestAWriteIsRepeatedOnlyWithItsKey(t *testing.T) {
	in := billing()
	keyed := WithIdempotencyKey(context.Background(), "qz-abc")
	c, calls := flaky(503, 0, 201)
	if _, err := c.Call(keyed, in, "createInvoice", map[string]any{"body": map[string]any{"amount": 5}}); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 3 {
		t.Fatalf("tried %d times", len(*calls))
	}
	for _, s := range *calls {
		if s.headers["Idempotency-Key"] != "qz-abc" {
			t.Fatalf("a repeat without its key: %v", s.headers)
		}
	}
	c, calls = flaky(503, 201)
	if _, err := c.Call(context.Background(), in, "createInvoice", map[string]any{"body": map[string]any{"amount": 5}}); err == nil || len(*calls) != 1 {
		t.Fatalf("a write with no key repeated: %d %v", len(*calls), err)
	}
	if _, ok := (*calls)[0].headers["Idempotency-Key"]; ok {
		t.Fatal("a key made up")
	}
	c, calls = flaky(429, 200)
	if _, err := c.Call(context.Background(), in, "getInvoice", map[string]any{"id": "7"}); err != nil || len(*calls) != 2 {
		t.Fatalf("a read not tried again: %d %v", len(*calls), err)
	}
	if _, ok := (*calls)[0].headers["Idempotency-Key"]; ok {
		t.Fatal("a read carries a key")
	}
	c, calls = flaky(503)
	if _, err := c.Call(keyed, in, "createInvoice", map[string]any{"body": map[string]any{"amount": 5}}); err == nil || len(*calls) != MaxAttempts {
		t.Fatalf("%d tries, %v", len(*calls), err)
	}
	c, calls = flaky(400, 201)
	if _, err := c.Call(keyed, in, "createInvoice", map[string]any{"body": map[string]any{"amount": 5}}); err == nil || len(*calls) != 1 {
		t.Fatal("a refusal tried again")
	}
}

// answering answers with the given results in turn, then the last one
// forever, by a clock that stands still at now.
func answering(now time.Time, results ...fetch.Result) (*Client, *[]sent) {
	var calls []sent
	return &Client{
		Secrets: func(string) (string, error) { return "s3cret", nil },
		Wait:    func(int, string) time.Duration { return 0 },
		Now:     func() time.Time { return now },
		DoMethod: func(_ context.Context, method, url string, body []byte, headers map[string]string) (*fetch.Result, error) {
			calls = append(calls, sent{method, url, string(body), headers})
			r := results[min(len(calls)-1, len(results)-1)]
			return &r, nil
		},
	}, &calls
}

// Retry-After may be a date as well as a number of seconds (RFC 9110
// 10.2.3). Read only as seconds, a 429 that said when to come back was
// tried again a second later, before that time, and failed.
func TestARetryAfterDateIsHonoured(t *testing.T) {
	// A date has whole seconds, so three seconds ahead is a little over
	// two from now.
	date := func(d time.Duration) string { return time.Now().Add(d).UTC().Format(http.TimeFormat) }
	if got := RetryAfter(1, date(3*time.Second)); got <= 2*time.Second-100*time.Millisecond || got > 3*time.Second {
		t.Fatalf("a date three seconds ahead waits %s", got)
	}
	if got := RetryAfter(1, date(-time.Minute)); got != 0 {
		t.Fatalf("a date gone by waits %s", got)
	}
	// Through a call, waiting as the client does by itself: the second
	// attempt is not made before the date the far side named.
	at := time.Now().Truncate(time.Second)
	c, calls := answering(at,
		fetch.Result{Status: 429, Body: []byte(`{}`), Header: http.Header{"Retry-After": {at.Add(2 * time.Second).Format(http.TimeFormat)}}},
		fetch.Result{Status: 200, Body: []byte(`{"ok":true}`)})
	c.Wait = nil
	began := time.Now()
	if _, err := c.Call(context.Background(), billing(), "getInvoice", map[string]any{"id": "7"}); err != nil || len(*calls) != 2 {
		t.Fatalf("%d calls, %v", len(*calls), err)
	}
	if waited := time.Since(began); waited < 1900*time.Millisecond {
		t.Fatalf("tried again after %s, before the date it was given", waited)
	}
}

// With no Retry-After, the wait is drawn at random up to a ceiling that
// doubles each attempt (full jitter). A fixed one second and then two
// sent every caller the same busy service turned away at once back in
// the same instant, to be turned away together again.
func TestABackoffHasJitter(t *testing.T) {
	seen := map[time.Duration]bool{}
	over := false
	for range 200 {
		first, second := RetryAfter(1, ""), RetryAfter(2, "garbled")
		if first < 0 || first > time.Second || second < 0 || second > 2*time.Second {
			t.Fatalf("waits %s and %s", first, second)
		}
		seen[first] = true
		over = over || second > time.Second
	}
	if len(seen) < 100 || !over {
		t.Fatalf("%d different first waits in 200, and the second's ceiling grew: %v", len(seen), over)
	}
	if RetryAfter(1, "120") != 10*time.Second || RetryAfter(1, "3") != 3*time.Second {
		t.Fatal("a wait the far side asked for")
	}
}

// TikTok answers a rate limit as a 400 with rate_limit_exceeded, and
// YouTube (Google's APIs) as a 403 with quotaExceeded or
// rateLimitExceeded. Read by status alone they were refusals, and a read
// that waiting would have let through failed at once; a 400 or 403 that
// is not one is still final.
func TestTikTokAndYouTubeRateLimitsAreRateLimits(t *testing.T) {
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	ok := fetch.Result{Status: 200, Body: []byte(`{"ok":true}`)}
	for _, tc := range []struct {
		name   string
		status int
		body   string
		calls  int
	}{
		{"TikTok", 400, `{"data":{},"error":{"code":"rate_limit_exceeded","message":"Too many requests","log_id":"x"}}`, 2},
		{"YouTube quota", 403, `{"error":{"code":403,"message":"quota","errors":[{"domain":"youtube.quota","reason":"quotaExceeded"}]}}`, 2},
		{"Google rate", 403, `{"error":{"code":403,"errors":[{"domain":"usageLimits","reason":"userRateLimitExceeded"}]}}`, 2},
		{"a bad request", 400, `{"error":{"code":"invalid_params","message":"no"}}`, 1},
		{"forbidden", 403, `{"error":{"code":403,"errors":[{"reason":"forbidden"}]}}`, 1},
		{"a code in the wrong status", 403, `{"error":{"code":"rate_limit_exceeded"}}`, 1},
		{"not JSON", 400, `rate_limit_exceeded`, 1},
	} {
		c, calls := answering(now, fetch.Result{Status: tc.status, Body: []byte(tc.body)}, ok)
		_, err := c.Call(context.Background(), billing(), "getInvoice", map[string]any{"id": "7"})
		if len(*calls) != tc.calls || (tc.calls == 2) != (err == nil) {
			t.Errorf("%s: %d calls, %v", tc.name, len(*calls), err)
		}
	}
	// A write is repeated for one only when it carries its key, as for a 429.
	c, calls := answering(now, fetch.Result{Status: 400, Body: []byte(`{"error":{"code":"rate_limit_exceeded"}}`)}, ok)
	if _, err := c.Call(context.Background(), billing(), "createInvoice", map[string]any{"body": map[string]any{"amount": 5}}); err == nil || len(*calls) != 1 {
		t.Fatalf("a write with no key repeated: %d %v", len(*calls), err)
	}
}

// A wait longer than a run waits in place (ten seconds) is not slept on
// and not cut short: the call fails saying when the far side will take it
// again, so a person or a later step can come back then. Cut to ten
// seconds, a 429 that said an hour was tried again twice within seconds,
// failed, and said nothing of when.
func TestAWaitAboveTheCapFailsSayingWhenToRetry(t *testing.T) {
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	for _, after := range []string{"3600", now.Add(time.Hour).Format(http.TimeFormat)} {
		c, calls := answering(now, fetch.Result{Status: 429, Body: []byte(`{"error":"slow down"}`),
			Header: http.Header{"Retry-After": {after}}}, fetch.Result{Status: 200, Body: []byte(`{}`)})
		_, err := c.Call(context.Background(), billing(), "getInvoice", map[string]any{"id": "7"})
		if err == nil || len(*calls) != 1 || !strings.Contains(err.Error(), "after 2026-11-11T11:00:00Z") ||
			!strings.Contains(err.Error(), "429") {
			t.Fatalf("Retry-After %s: %d calls, %v", after, len(*calls), err)
		}
	}
	// Within the cap it is waited for, and when the tries run out the
	// error still says when.
	c, calls := answering(now, fetch.Result{Status: 503, Body: []byte(`busy`), Header: http.Header{"Retry-After": {"5"}}})
	if _, err := c.Call(context.Background(), billing(), "getInvoice", map[string]any{"id": "7"}); err == nil ||
		len(*calls) != MaxAttempts || !strings.Contains(err.Error(), "after 2026-11-11T10:00:05Z") {
		t.Fatalf("%d calls, %v", len(*calls), err)
	}
}
