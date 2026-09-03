package activitypub

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Getting a post to the people who followed.
//
// # Why this is a queue and not a loop
//
// Delivery happens while somebody is waiting for a publish to finish, and it
// talks to servers this one does not control. A loop that posted to each
// follower in turn would make publishing take as long as the slowest remote
// host, and fail it when one is down — which is the wrong failure: the page is
// published either way, and delivery is what has not happened yet.
//
// So publishing enqueues and returns. What is queued is durable enough to
// survive the request and no longer: a restart loses pending deliveries, and
// the honest description of that is below rather than a promise of at-least-
// once semantics nothing here implements.
//
// # Why retries stop
//
// A server that is down comes back; one that has closed does not. Retrying
// forever turns a dead host into a permanent outbound load and this program
// into something that looks like an attacker. So attempts are bounded and
// spaced, and a delivery that exhausts them is dropped with a record rather
// than kept for ever.
//
// # What is deliberately not here
//
// No proof of delivery, no read receipts, and no ordering guarantee between
// two posts. ActivityPub offers none of those and a queue that implied them
// would be lying about what the network does.

// Attempts is how many times one delivery is tried.
const Attempts = 5

// Backoff is the wait before each retry, indexed by attempt.
//
// Written out rather than computed, because the shape matters more than the
// formula: quick twice for a server that hiccuped, then long enough that a
// server down for maintenance is not being hit every few seconds while it
// recovers.
var Backoff = []time.Duration{
	0,
	30 * time.Second,
	2 * time.Minute,
	10 * time.Minute,
	1 * time.Hour,
}

// MaxQueue bounds how much is waiting.
//
// A queue that grows without limit is a memory leak with a publish button. At
// the ceiling, new deliveries are refused rather than old ones dropped:
// dropping the oldest would silently lose the post somebody published first,
// which is the one they are most likely to be looking for.
const MaxQueue = 10_000

// Delivery is one activity bound for one inbox.
type Delivery struct {
	Inbox    string
	Activity map[string]any
	// Attempt counts what has been tried, starting at zero.
	Attempt int
	// Due is when to try next.
	Due time.Time
}

// Sender posts a signed activity to an inbox.
//
// An interface rather than a client, because signing needs the site's key and
// the request has to go through the same address checks as every other
// outbound call. A queue that built its own HTTP client would be a second
// place for those to be forgotten.
type Sender interface {
	Send(inbox string, activity map[string]any) error
}

// Queue holds deliveries that have not succeeded yet.
type Queue struct {
	mu      sync.Mutex
	pending []Delivery
	// Now is the clock, injectable so retry timing is testable without
	// sleeping.
	Now func() time.Time
	// Dropped counts deliveries abandoned after exhausting their attempts,
	// for a status screen. A number nobody can see is a failure nobody knows
	// about.
	Dropped int
}

// NewQueue returns an empty queue.
func NewQueue() *Queue { return &Queue{} }

func (q *Queue) now() time.Time {
	if q.Now != nil {
		return q.Now()
	}
	return time.Now()
}

// Enqueue adds one activity for each inbox.
func (q *Queue) Enqueue(inboxes []string, activity map[string]any) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.pending)+len(inboxes) > MaxQueue {
		return fmt.Errorf(
			"the delivery queue holds %d and the ceiling is %d. Refusing new "+
				"deliveries rather than dropping waiting ones: dropping the "+
				"oldest would lose the post published first, which is the one "+
				"somebody is most likely looking for",
			len(q.pending), MaxQueue)
	}
	now := q.now()
	for _, inbox := range inboxes {
		q.pending = append(q.pending, Delivery{
			Inbox: inbox, Activity: activity, Due: now,
		})
	}
	return nil
}

// Due returns the deliveries ready to attempt, and removes them from the
// queue.
//
// Removed rather than marked, so a delivery in flight cannot also be picked up
// by a second run. A failed one is put back by Retry with its next due time.
func (q *Queue) Due() []Delivery {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := q.now()
	var ready, keep []Delivery
	for _, d := range q.pending {
		if !d.Due.After(now) {
			ready = append(ready, d)
		} else {
			keep = append(keep, d)
		}
	}
	q.pending = keep
	sort.SliceStable(ready, func(i, j int) bool {
		return ready[i].Inbox < ready[j].Inbox
	})
	return ready
}

// Retry puts a failed delivery back, or drops it.
//
// Reports whether it will be tried again, so a caller can say which happened
// rather than logging "delivery failed" for both the recoverable case and the
// final one.
func (q *Queue) Retry(d Delivery) bool {
	d.Attempt++
	if d.Attempt >= Attempts {
		q.mu.Lock()
		q.Dropped++
		q.mu.Unlock()
		return false
	}
	wait := Backoff[len(Backoff)-1]
	if d.Attempt < len(Backoff) {
		wait = Backoff[d.Attempt]
	}
	d.Due = q.now().Add(wait)

	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending = append(q.pending, d)
	return true
}

// Len is how many deliveries are waiting.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

// Run attempts every due delivery once.
//
// One pass rather than a loop, so the caller decides the cadence and a test
// can drive it deterministically. Returns how many succeeded and how many were
// given up on.
func (q *Queue) Run(s Sender, onError func(Delivery, error)) (sent, dropped int) {
	for _, d := range q.Due() {
		if err := s.Send(d.Inbox, d.Activity); err != nil {
			if !q.Retry(d) {
				dropped++
			}
			if onError != nil {
				onError(d, err)
			}
			continue
		}
		sent++
	}
	return sent, dropped
}
