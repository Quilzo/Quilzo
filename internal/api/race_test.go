package api

import (
	"net/http/httptest"
	"sync"
	"testing"
)

// The suite exercises the handler one request at a time, which is not how it
// runs. The rate limiter carries a map of buckets and the store is shared, so
// the interesting question is whether concurrent requests corrupt either.
func TestTheHandlerSurvivesConcurrentRequests(t *testing.T) {
	s, readTok, writeTok := setup(t)
	h := s.Handler()

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		for _, path := range []string{
			"/api/v1/pages", "/api/v1/pages/about", "/api/v1/pages/nope",
			"/api/v1/pages?limit=2", "/api/v1/pages/../x",
		} {
			for _, tok := range []string{readTok, writeTok, "bad"} {
				wg.Add(1)
				go func(path, tok string) {
					defer wg.Done()
					r := httptest.NewRequest("GET", "http://h"+path, nil)
					r.Header.Set("Authorization", "Bearer "+tok)
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code >= 500 {
						t.Errorf("%s gave %d", path, w.Code)
					}
				}(path, tok)
			}
		}
	}
	wg.Wait()
}

// Two clients writing the same page at once must not both succeed against the
// same base. That is the whole point of If-Match, and a race in the read that
// backs it would make compare-and-swap into compare-and-hope.
func TestConcurrentWritesToOnePageDoNotBothSucceed(t *testing.T) {
	s, _, writeTok := setup(t)
	s.Writable = true

	w := req(t, s, "GET", "/api/v1/pages/about", writeTok, nil, nil)
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag to write against")
	}

	var mu sync.Mutex
	var ok, stale, other int
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := req(t, s, "PUT", "/api/v1/pages/about", writeTok,
				map[string]any{"title": "About", "body": "edit"},
				map[string]string{"If-Match": etag})
			mu.Lock()
			defer mu.Unlock()
			switch rec.Code {
			case 200, 201:
				ok++
			case 412:
				stale++
			default:
				other++
				t.Logf("write %d gave %d: %s", i, rec.Code, rec.Body.String())
			}
		}(i)
	}
	wg.Wait()

	if ok != 1 {
		t.Errorf("%d of 16 concurrent writes against the same base succeeded; "+
			"exactly one should, or If-Match is not compare-and-swap", ok)
	}
	if other != 0 {
		t.Errorf("%d writes failed for a reason that is neither success nor "+
			"a stale validator", other)
	}
}
