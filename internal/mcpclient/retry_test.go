// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"context"
	"errors"
	"net/http"
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
	if RetryAfter(1, "120") != 10*time.Second || RetryAfter(2, "") != 2*time.Second || RetryAfter(1, "3") != 3*time.Second {
		t.Fatal("waits")
	}
}
