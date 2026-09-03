package public

import (
	"fmt"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/activitypub"
)

// countingSite is an inbox whose outbound fetches can be counted.
func countingSite(now *time.Time, out *int64, targets *[]string) *Site {
	return &Site{Federation: &Federation{
		Actor:     activitypub.Actor{ID: "https://marginalia.example/@"},
		Followers: activitypub.NewFollowers(),
		Fetch: func(url string) ([]byte, error) {
			atomic.AddInt64(out, 1)
			if targets != nil {
				*targets = append(*targets, url)
			}
			return nil, fmt.Errorf("unreachable")
		},
		Now: func() time.Time { return *now },
	}}
}

func followFrom(actor string, i int) string {
	return fmt.Sprintf(`{"id":"https://a.example/%d","type":"Follow",`+
		`"actor":%q,"object":"https://marginalia.example/@"}`, i, actor)
}

// The vector this closed.
//
// Verifying an activity means fetching the sender's key from their server, so
// an unbounded inbox lets anybody make this server issue requests to a host
// they name. Two hundred POSTs produced two hundred outbound requests to a
// named victim before the limit existed — reflection, with this server's
// address on the traffic arriving at somebody else.
func TestAFloodCannotTurnTheInboxIntoAWayToReachAThirdParty(t *testing.T) {
	now := time.Unix(1787000000, 0)
	var outbound int64
	var targets []string
	st := countingSite(&now, &outbound, &targets)

	const attempts = 500
	for i := 0; i < attempts; i++ {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/@/inbox",
			stringReader(followFrom(fmt.Sprintf("https://victim.example/u%d", i), i)))
		r.RemoteAddr = "203.0.113.7:40000"
		st.inbox(rec, r)
	}

	if outbound >= attempts {
		t.Fatalf("%d POSTs produced %d outbound requests; the inbox is a "+
			"reflection vector", attempts, outbound)
	}
	if outbound > InboxRate {
		t.Errorf("%d outbound requests from one source in a minute, and the "+
			"limit is %d", outbound, InboxRate)
	}
	t.Logf("%d POSTs from one source produced %d outbound requests",
		attempts, outbound)
}

// The limit is per source and per minute, so a legitimate server that hits it
// is not blocked for ever.
func TestTheLimitLiftsAfterTheWindow(t *testing.T) {
	now := time.Unix(1787000000, 0)
	var outbound int64
	st := countingSite(&now, &outbound, nil)

	send := func() int {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/@/inbox",
			stringReader(followFrom("https://r.example/users/dana", 1)))
		r.RemoteAddr = "203.0.113.7:40000"
		st.inbox(rec, r)
		return rec.Code
	}

	for i := 0; i < InboxRate; i++ {
		send()
	}
	if code := send(); code != 429 {
		t.Fatalf("the %dth request in a minute returned %d, want 429",
			InboxRate+1, code)
	}

	now = now.Add(2 * time.Minute)
	if code := send(); code == 429 {
		t.Error("a source is still limited two minutes later; a legitimate " +
			"server that hit the limit would never recover")
	}
}

// One noisy source must not silence everybody else.
func TestOneFloodingSourceDoesNotBlockOthers(t *testing.T) {
	now := time.Unix(1787000000, 0)
	var outbound int64
	st := countingSite(&now, &outbound, nil)

	for i := 0; i < InboxRate+50; i++ {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/@/inbox",
			stringReader(followFrom("https://r.example/users/dana", i)))
		r.RemoteAddr = "203.0.113.7:40000"
		st.inbox(rec, r)
	}

	rec := httptest.NewRecorder()
	other := httptest.NewRequest("POST", "/@/inbox",
		stringReader(followFrom("https://r.example/users/dana", 1)))
	other.RemoteAddr = "198.51.100.4:40000"
	st.inbox(rec, other)
	if rec.Code == 429 {
		t.Fatal("a second source was refused because a first one flooded; " +
			"the limit is global rather than per source")
	}
}

// A server delivering several posts is fetched once, not once per activity.
// Without the cache the ordinary case is the expensive one.
func TestTheSameActorIsFetchedOnce(t *testing.T) {
	now := time.Unix(1787000000, 0)
	var outbound int64
	st := &Site{Federation: &Federation{
		Actor:     activitypub.Actor{ID: "https://marginalia.example/@"},
		Followers: activitypub.NewFollowers(),
		Fetch: func(string) ([]byte, error) {
			atomic.AddInt64(&outbound, 1)
			return []byte(`{"id":"https://r.example/users/dana",
				"inbox":"https://r.example/inbox",
				"publicKey":{"id":"k","owner":"https://r.example/users/dana",
				"publicKeyPem":"not a key"}}`), nil
		},
		Now: func() time.Time { return now },
	}}

	for i := 0; i < 20; i++ {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/@/inbox",
			stringReader(followFrom("https://r.example/users/dana", i)))
		r.RemoteAddr = "203.0.113.7:40000"
		st.inbox(rec, r)
	}
	if outbound != 1 {
		t.Errorf("20 activities from one actor caused %d fetches, want 1",
			outbound)
	}

	// And the cache expires, because it holds a public key and a rotation
	// should take effect in minutes.
	now = now.Add(ActorCacheFor + time.Minute)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/@/inbox",
		stringReader(followFrom("https://r.example/users/dana", 99)))
	r.RemoteAddr = "198.51.100.9:40000"
	st.inbox(rec, r)
	if outbound != 2 {
		t.Errorf("the actor was not refetched after the cache expired "+
			"(%d fetches); a key rotation would not take effect", outbound)
	}
}

// The cache is filled by strangers naming hosts, so it cannot grow without
// limit.
func TestTheActorCacheIsBounded(t *testing.T) {
	var g inboxGuard
	now := time.Unix(1787000000, 0)

	for i := 0; i < MaxActorCache+100; i++ {
		g.remember(fmt.Sprintf("https://h%d.example/actor", i),
			[]byte("{}"), now)
	}

	g.mu.Lock()
	held := len(g.cache)
	g.mu.Unlock()
	if held > MaxActorCache {
		t.Fatalf("the cache holds %d entries and the ceiling is %d",
			held, MaxActorCache)
	}
}

// A burst spread across many sources is what a per-source limit cannot see.
func TestConcurrentFetchesAreBounded(t *testing.T) {
	var g inboxGuard
	taken := 0
	for i := 0; i < MaxConcurrentFetches+10; i++ {
		if g.acquire() {
			taken++
		}
	}
	if taken != MaxConcurrentFetches {
		t.Fatalf("%d slots were taken and the ceiling is %d",
			taken, MaxConcurrentFetches)
	}
	// And released slots are reusable, or the inbox stops working after the
	// first burst.
	g.release()
	if !g.acquire() {
		t.Error("a released slot could not be taken again")
	}
}
