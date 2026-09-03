package public

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Bounding what a stranger can make this server do.
//
// # The problem the protocol creates
//
// Verifying an inbound activity means checking its signature against the
// sending actor's key, and that key lives on their server. So the inbox has to
// make an outbound request before it knows anything about the caller — which
// means anybody who can POST here can make this server issue a request to a
// host of their choosing.
//
// Measured before this existed: two hundred unauthenticated POSTs produced two
// hundred outbound requests to a named victim. That is reflection, and it is
// worse than the load on this server, because the traffic arrives at somebody
// else with this server's address on it.
//
// The fetch cannot be avoided — it is how the protocol works, and every
// implementation has this shape. What can be bounded is how much of it one
// caller gets.
//
// # Three bounds, because one is not enough
//
// A rate limit per source stops one host driving the loop. A cache means the
// same actor is fetched once rather than once per activity, which is the
// ordinary case for a server delivering several posts. And a ceiling on
// concurrent fetches stops a burst from many sources becoming many
// simultaneous outbound connections, which is the case a per-source limit
// cannot see.

// InboxRate is how many activities one source may send per minute.
//
// Generous for a real server: a busy instance delivering a backlog sends a
// handful a second at most, and a legitimate one that hits this retries. Tight
// enough that a single host cannot drive the fetch loop.
const InboxRate = 120

// ActorCacheFor is how long a fetched actor document is reused.
//
// Short, because it holds a public key and a key rotation should take effect
// in minutes rather than hours. Long enough that a server delivering a burst
// of posts is fetched once.
const ActorCacheFor = 10 * time.Minute

// MaxActorCache bounds the cache.
//
// Entries are created by strangers naming hosts, so an unbounded map is a
// memory leak anybody can drive. At the ceiling the cache stops accepting new
// entries rather than evicting: evicting under attack would push out the
// entries that are actually being used, which is the opposite of what a cache
// is for.
const MaxActorCache = 2048

// MaxConcurrentFetches bounds outbound requests in flight.
//
// A per-source rate limit cannot see a burst spread across many sources. This
// can: it is the number of connections this server will hold open to remote
// hosts on behalf of unverified callers, and past it an inbox request waits
// rather than adding another.
const MaxConcurrentFetches = 8

// inboxGuard holds the bounds. Zero value is usable.
type inboxGuard struct {
	mu    sync.Mutex
	seen  map[string]*window
	cache map[string]cachedActor
	slots chan struct{}
	once  sync.Once
}

type window struct {
	count int
	until time.Time
}

type cachedActor struct {
	body  []byte
	until time.Time
}

func (g *inboxGuard) init() {
	g.once.Do(func() {
		g.seen = map[string]*window{}
		g.cache = map[string]cachedActor{}
		g.slots = make(chan struct{}, MaxConcurrentFetches)
	})
}

// allow reports whether this source may send another activity now.
func (g *inboxGuard) allow(source string, now time.Time) bool {
	g.init()
	g.mu.Lock()
	defer g.mu.Unlock()

	// Sweep on write rather than on a timer, so an idle process holds nothing
	// and this needs no goroutine.
	for key, w := range g.seen {
		if now.After(w.until) {
			delete(g.seen, key)
		}
	}

	w, there := g.seen[source]
	if !there || now.After(w.until) {
		g.seen[source] = &window{count: 1, until: now.Add(time.Minute)}
		return true
	}
	if w.count >= InboxRate {
		return false
	}
	w.count++
	return true
}

func (g *inboxGuard) cached(url string, now time.Time) ([]byte, bool) {
	g.init()
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, there := g.cache[url]
	if !there || now.After(entry.until) {
		return nil, false
	}
	return entry.body, true
}

// remember stores a fetched actor document.
func (g *inboxGuard) remember(url string, body []byte, now time.Time) {
	g.init()
	g.mu.Lock()
	defer g.mu.Unlock()

	for key, entry := range g.cache {
		if now.After(entry.until) {
			delete(g.cache, key)
		}
	}
	if len(g.cache) >= MaxActorCache {
		// Refuse rather than evict. Evicting under a flood would push out the
		// entries actually in use, turning the cache into extra work at the
		// moment it is most needed.
		return
	}
	g.cache[url] = cachedActor{body: body, until: now.Add(ActorCacheFor)}
}

// acquire takes a concurrency slot, or reports that too many are in flight.
func (g *inboxGuard) acquire() bool {
	g.init()
	// Non-blocking. A blocking send would make the inbox wait for a slot
	// rather than refuse, which turns a burst into a pile of held connections
	// and, with nothing releasing, a hang — a sabotage that removed the select
	// did exactly that and took the test run with it.
	select {
	case g.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *inboxGuard) release() { <-g.slots }

// The caller is identified by sourceOf, in forms.go, which already resolves a
// request to its connecting address and explains why a forwarded header is not
// used. One answer to that question rather than two that can disagree.

func tooMany(w http.ResponseWriter, retryAfter int, why string) {
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	http.Error(w, why, http.StatusTooManyRequests)
}
