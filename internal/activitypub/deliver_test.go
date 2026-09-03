package activitypub_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/activitypub"
)

type sender struct {
	mu       sync.Mutex
	sent     []string
	failWith error
	failFor  map[string]bool
}

func (s *sender) Send(inbox string, _ map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failFor != nil && s.failFor[inbox] {
		return s.failWith
	}
	if s.failWith != nil && s.failFor == nil {
		return s.failWith
	}
	s.sent = append(s.sent, inbox)
	return nil
}

func clockedQueue(now *time.Time) *activitypub.Queue {
	q := activitypub.NewQueue()
	q.Now = func() time.Time { return *now }
	return q
}

func TestEveryFollowerGetsThePost(t *testing.T) {
	now := at()
	q := clockedQueue(&now)
	inboxes := []string{"https://a.example/inbox", "https://b.example/inbox"}
	if err := q.Enqueue(inboxes, note().Create()); err != nil {
		t.Fatal(err)
	}

	s := &sender{}
	sent, dropped := q.Run(s, nil)
	if sent != 2 || dropped != 0 {
		t.Fatalf("sent %d, dropped %d", sent, dropped)
	}
	if q.Len() != 0 {
		t.Errorf("%d deliveries still queued after success", q.Len())
	}
}

// A server that is down comes back. Failing once must not lose the post.
func TestAFailedDeliveryIsRetriedLater(t *testing.T) {
	now := at()
	q := clockedQueue(&now)
	if err := q.Enqueue([]string{"https://a.example/inbox"}, note().Create()); err != nil {
		t.Fatal(err)
	}

	down := &sender{failWith: fmt.Errorf("connection refused")}
	if sent, dropped := q.Run(down, nil); sent != 0 || dropped != 0 {
		t.Fatalf("sent %d, dropped %d on a failure", sent, dropped)
	}
	if q.Len() != 1 {
		t.Fatalf("%d queued after a failure, want 1", q.Len())
	}

	// Not due yet, so a second pass right away does nothing.
	//
	// Retried with a *working* sender on purpose. Using the failing one again
	// cannot tell "not due" from "due and failed again" — both report zero
	// sent — and a version of this test that did exactly that passed with the
	// backoff removed entirely.
	if sent, _ := q.Run(&sender{}, nil); sent != 0 {
		t.Fatal("a failed delivery was retried immediately, with no backoff. " +
			"A server that is briefly down would be hit as fast as this loop " +
			"runs.")
	}
	if q.Len() != 1 {
		t.Fatalf("%d queued after the too-early pass", q.Len())
	}

	// Once the backoff has passed and the server is up.
	now = now.Add(2 * time.Minute)
	up := &sender{}
	if sent, _ := q.Run(up, nil); sent != 1 {
		t.Fatalf("the retry did not go out after the backoff")
	}
	if q.Len() != 0 {
		t.Errorf("%d queued after a successful retry", q.Len())
	}
}

// A server that has closed does not come back. Retrying forever turns a dead
// host into permanent outbound load and this program into something that looks
// like an attacker.
func TestRetriesStopAndAreCounted(t *testing.T) {
	now := at()
	q := clockedQueue(&now)
	if err := q.Enqueue([]string{"https://gone.example/inbox"}, note().Create()); err != nil {
		t.Fatal(err)
	}

	dead := &sender{failWith: fmt.Errorf("no such host")}
	attempts := 0
	for i := 0; i < 20 && q.Len() > 0; i++ {
		sent, _ := q.Run(dead, nil)
		attempts += sent
		now = now.Add(2 * time.Hour)
	}

	if q.Len() != 0 {
		t.Fatalf("%d deliveries still queued for a host that never answers", q.Len())
	}
	if q.Dropped != 1 {
		t.Errorf("Dropped is %d, want 1 — a delivery given up on has to be "+
			"countable, or it is a failure nobody knows about", q.Dropped)
	}
}

// One failing server must not hold up the others.
func TestOneDeadServerDoesNotBlockTheRest(t *testing.T) {
	now := at()
	q := clockedQueue(&now)
	if err := q.Enqueue([]string{
		"https://good.example/inbox", "https://dead.example/inbox",
		"https://alsogood.example/inbox",
	}, note().Create()); err != nil {
		t.Fatal(err)
	}

	s := &sender{
		failWith: fmt.Errorf("timeout"),
		failFor:  map[string]bool{"https://dead.example/inbox": true},
	}
	sent, _ := q.Run(s, nil)
	if sent != 2 {
		t.Fatalf("%d of 2 healthy servers received the post", sent)
	}
	if q.Len() != 1 {
		t.Errorf("%d queued, want only the failing one", q.Len())
	}
}

// A queue that grows without limit is a memory leak with a publish button.
// Refusing new work is visible; dropping waiting work loses the post somebody
// published first.
func TestTheQueueIsBoundedAndRefusesRatherThanDropping(t *testing.T) {
	now := at()
	q := clockedQueue(&now)

	big := make([]string, activitypub.MaxQueue)
	for i := range big {
		big[i] = fmt.Sprintf("https://s%d.example/inbox", i)
	}
	if err := q.Enqueue(big, note().Create()); err != nil {
		t.Fatal(err)
	}
	if q.Len() != activitypub.MaxQueue {
		t.Fatalf("%d queued", q.Len())
	}

	err := q.Enqueue([]string{"https://one-more.example/inbox"}, note().Create())
	if err == nil {
		t.Fatal("the queue accepted work past its ceiling")
	}
	// And nothing waiting was thrown away to make room.
	if q.Len() != activitypub.MaxQueue {
		t.Errorf("%d queued after a refusal; waiting deliveries were dropped",
			q.Len())
	}
}

// A delivery taken for an attempt must not also be picked up by a second run,
// or one failure becomes two requests to a server already struggling.
func TestADeliveryInFlightIsNotPickedUpTwice(t *testing.T) {
	now := at()
	q := clockedQueue(&now)
	if err := q.Enqueue([]string{"https://a.example/inbox"}, note().Create()); err != nil {
		t.Fatal(err)
	}

	first := q.Due()
	second := q.Due()
	if len(first) != 1 {
		t.Fatalf("the first pass took %d", len(first))
	}
	if len(second) != 0 {
		t.Errorf("the second pass took %d deliveries that were already in "+
			"flight", len(second))
	}
}

// The error is reported with the delivery it belongs to, or a log says
// "delivery failed" without saying to whom.
func TestAFailureNamesTheInboxAndTheReason(t *testing.T) {
	now := at()
	q := clockedQueue(&now)
	if err := q.Enqueue([]string{"https://a.example/inbox"}, note().Create()); err != nil {
		t.Fatal(err)
	}

	var gotInbox string
	var gotErr error
	q.Run(&sender{failWith: fmt.Errorf("connection refused")},
		func(d activitypub.Delivery, err error) {
			gotInbox, gotErr = d.Inbox, err
		})

	if gotInbox != "https://a.example/inbox" {
		t.Errorf("the failure named %q", gotInbox)
	}
	if gotErr == nil {
		t.Error("the failure carried no reason")
	}
}

// Enqueueing from several goroutines must not lose a delivery.
func TestTheQueueIsSafeUnderConcurrentPublishes(t *testing.T) {
	now := at()
	q := clockedQueue(&now)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := q.Enqueue(
				[]string{fmt.Sprintf("https://s%d.example/inbox", i)},
				note().Create()); err != nil {
				t.Errorf("enqueue %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if q.Len() != 32 {
		t.Fatalf("%d queued after 32 concurrent publishes", q.Len())
	}
}
