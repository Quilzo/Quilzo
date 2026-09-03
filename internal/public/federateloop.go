package public

import (
	"context"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/activitypub"
	"github.com/quilzo/quilzo/internal/site"
)

// Noticing a publish, and getting it out.
//
// # Why this is a loop and not a callback
//
// Publishing happens in the admin or the command line; serving happens in a
// different process. There is no event between them, by design — the two share
// a store directory and nothing else, which is what lets the public process
// have no write surface at all.
//
// So the serving process watches the ref it already reads on every request.
// When it moves, the pages that changed between the two commits are announced.
// That needs no coordination, no socket, and no shared secret, and it keeps
// working if somebody publishes from a third process or by moving the ref by
// hand.
//
// # Only what changed
//
// A publish usually touches one page. Announcing the whole site on every
// publish would put a site's entire catalogue into every follower's timeline
// each time a typo is fixed, which is the difference between a feed and a
// flood — and the fastest way to be defederated.
//
// # Where it starts from
//
// The last commit announced is written down. Without that, a restart looks
// like every page changing at once, and the first thing a redeployed server
// would do is repost everything.
//
// A server that has never announced anything starts from the current commit
// rather than from the beginning of history. The alternative — announcing the
// entire back catalogue the moment federation is switched on — is the same
// flood arriving on day one.

// FederatePoll is how often the ref is checked.
//
// Cheap: reading a ref is a file read, and the loop does nothing else when it
// has not moved. Frequent enough that a post appears in a timeline while
// somebody is still looking at the publish they just made.
const FederatePoll = 15 * time.Second

// DeliverEvery is how often the queue is drained.
//
// Separate from the poll because they answer different questions: one asks
// whether there is anything new, the other whether anything owed is due. A
// retry scheduled an hour out needs the second loop to run even when nothing
// is published.
const DeliverEvery = 30 * time.Second

// Federate watches for publishes and delivers them, until the context ends.
//
// Blocking, so a caller decides whether it runs in a goroutine. Returns when
// the context is done, which is what makes it testable without waiting.
func (st *Site) Federate(ctx context.Context, sender interface {
	Send(inbox string, activity map[string]any) error
}, onError func(error)) {

	if st.Federation == nil || st.Federation.Queue == nil {
		return
	}
	report := func(err error) {
		if err != nil && onError != nil {
			onError(err)
		}
	}

	drain := func() {
		st.Federation.Queue.Run(sender, func(d activitypub.Delivery, err error) {
			report(fmt.Errorf("delivery to %s: %w", d.Inbox, err))
		})
	}

	// One pass immediately, before the first tick.
	//
	// A restart is the moment a queue left over from the last run needs
	// sending and anything published while the process was down needs
	// announcing. Waiting a full tick to do either would make every deploy a
	// visible delay in delivery, and would make this loop untestable without
	// waiting that tick in a test.
	report(st.announceNewPublishes())
	drain()

	poll := time.NewTicker(FederatePoll)
	defer poll.Stop()
	deliver := time.NewTicker(DeliverEvery)
	defer deliver.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			report(st.announceNewPublishes())
		case <-deliver.C:
			drain()
		}
	}
}

// announceNewPublishes queues whatever changed since the last announcement.
func (st *Site) announceNewPublishes() error {
	f := st.Federation
	live := st.Store.GetRef(st.ref())
	if live == "" {
		return nil
	}

	last := f.lastAnnounced()
	if last == live {
		return nil
	}
	if last == "" {
		// Nothing announced yet. Start from here rather than from the
		// beginning of history: announcing the whole back catalogue the moment
		// federation is switched on is a flood on day one.
		return f.rememberAnnounced(live)
	}

	changes, err := site.Diff(st.Store, last, live)
	if err != nil {
		// A last commit that cannot be read — history rewritten, store
		// restored from elsewhere — is not a reason to announce everything.
		// Move the marker and carry on.
		return f.rememberAnnounced(live)
	}
	if len(changes) == 0 {
		return f.rememberAnnounced(live)
	}

	if _, err := st.announceChanges(changes); err != nil {
		// The marker is not moved, so the next pass tries again. A publish
		// that failed to queue is worth retrying; one recorded as announced
		// would be lost silently.
		return fmt.Errorf("announcing %d change(s): %w", len(changes), err)
	}
	return f.rememberAnnounced(live)
}
