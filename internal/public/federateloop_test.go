package public

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/activitypub"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// fedLoopSite builds a store-backed, following site with a marker held in
// memory, and returns it plus the store so a test can publish into it.
func fedLoopSite(t *testing.T) (*Site, *store.Store) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := New(s, render.OneLayout("{{ page.body }}"))
	st.BaseURL = "https://marginalia.example"
	st.Index = "index"

	followers := activitypub.NewFollowers()
	if _, err := followers.Add(activitypub.Follower{
		Actor: "https://a.example/users/x", Inbox: "https://a.example/inbox",
	}); err != nil {
		t.Fatal(err)
	}
	st.Federation = &Federation{
		Actor:     activitypub.Actor{ID: "https://marginalia.example/@"},
		Followers: followers,
		Queue:     activitypub.NewQueue(),
		Now:       func() time.Time { return time.Unix(1787000000, 0) },
	}
	return st, s
}

func publish(t *testing.T, s *store.Store, pages map[string]any) {
	t.Helper()
	if _, err := site.SaveDraft(s, pages, "edit", "dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, s.GetRef(site.RefDraft)); err != nil {
		t.Fatal(err)
	}
}

// The first time the loop runs it has no marker, so it must NOT treat the whole
// site as freshly published. Switching federation on should not repost the back
// catalogue into every follower's timeline.
func TestAFirstPollAnnouncesTheBackCatalogueToNobody(t *testing.T) {
	st, s := fedLoopSite(t)
	publish(t, s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "<p>Hi.</p>"},
		"about": map[string]any{"title": "About", "body": "<p>Us.</p>"},
	})

	if err := st.announceNewPublishes(); err != nil {
		t.Fatal(err)
	}
	if n := st.Federation.Queue.Len(); n != 0 {
		t.Fatalf("first poll queued %d activities; it must announce nothing "+
			"and only remember where it started", n)
	}
	if got := st.Federation.lastAnnounced(); got != s.GetRef(st.ref()) {
		t.Fatalf("marker is %q, not the live commit", got)
	}
}

// An edit must reach followers, and must go out as an Update: a Create for an
// id a server already holds is deduplicated, so announcing an edit as a Create
// delivers nothing the reader can see while looking like it worked.
func TestAnEditIsAnnouncedAsAnUpdate(t *testing.T) {
	st, s := fedLoopSite(t)
	publish(t, s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "<p>Hi.</p>"},
		"about": map[string]any{"title": "About", "body": "<p>v1.</p>"},
	})
	if err := st.announceNewPublishes(); err != nil { // records the marker
		t.Fatal(err)
	}

	publish(t, s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "<p>Hi.</p>"},
		"about": map[string]any{"title": "About", "body": "<p>v2 edited.</p>"},
	})
	if err := st.announceNewPublishes(); err != nil {
		t.Fatal(err)
	}

	due := st.Federation.Queue.Due()
	if len(due) != 1 {
		t.Fatalf("editing one page queued %d deliveries (1 page, 1 follower), "+
			"want 1", len(due))
	}
	act := due[0].Activity
	if act["type"] != "Update" {
		t.Errorf("an edit was announced as %v, not an Update; receivers will "+
			"deduplicate it and the edit will be invisible", act["type"])
	}
	obj, _ := act["object"].(map[string]any)
	if id, _ := obj["id"].(string); id != "https://marginalia.example/about" {
		t.Errorf("the queued activity is for %q, not the page that changed", id)
	}
	if due[0].Inbox != "https://a.example/inbox" {
		t.Errorf("delivered to %q, not the follower", due[0].Inbox)
	}
}

// The unchanged page must not be re-announced. This is the load-bearing join
// between site.Diff's tree-key path space and the page name pageOf reconstructs
// from a note id; if they ever drift, this queues the wrong pages or none.
func TestAnUnchangedPageIsNotReannounced(t *testing.T) {
	st, s := fedLoopSite(t)
	publish(t, s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "<p>Hi.</p>"},
		"about": map[string]any{"title": "About", "body": "<p>v1.</p>"},
	})
	if err := st.announceNewPublishes(); err != nil {
		t.Fatal(err)
	}
	publish(t, s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "<p>Hi.</p>"},  // unchanged
		"about": map[string]any{"title": "About", "body": "<p>v2.</p>"}, // edited
	})
	if err := st.announceNewPublishes(); err != nil {
		t.Fatal(err)
	}
	for _, d := range st.Federation.Queue.Due() {
		obj, _ := d.Activity["object"].(map[string]any)
		if id, _ := obj["id"].(string); id == "https://marginalia.example/" {
			t.Error("the unchanged index was re-announced; only what changed " +
				"should go out")
		}
	}
}

// A new page goes out as a Create.
func TestANewPageIsAnnouncedAsACreate(t *testing.T) {
	st, s := fedLoopSite(t)
	publish(t, s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "<p>Hi.</p>"},
	})
	if err := st.announceNewPublishes(); err != nil {
		t.Fatal(err)
	}
	publish(t, s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "<p>Hi.</p>"},
		"news":  map[string]any{"title": "News", "body": "<p>New.</p>"},
	})
	if err := st.announceNewPublishes(); err != nil {
		t.Fatal(err)
	}
	due := st.Federation.Queue.Due()
	if len(due) != 1 || due[0].Activity["type"] != "Create" {
		t.Fatalf("a new page produced %d activities of type %v, want 1 Create",
			len(due), func() any {
				if len(due) > 0 {
					return due[0].Activity["type"]
				}
				return nil
			}())
	}
}

// recordingSender is a Sender that just remembers what it was asked to deliver.
type recordingSender struct {
	mu   sync.Mutex
	sent []string
}

func (r *recordingSender) Send(inbox string, _ map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, inbox)
	return nil
}

func (r *recordingSender) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent)
}

// Federate must actually drain the queue through the sender, and return when
// its context ends. Driven with a queued item and a fast deadline rather than
// waiting on the production tick.
func TestFederateDrainsTheQueueAndStops(t *testing.T) {
	st, s := fedLoopSite(t)
	publish(t, s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "<p>Hi.</p>"},
	})
	// Queue one delivery directly, as a publish would.
	if _, err := st.Announce(nil); err != nil {
		t.Fatal(err)
	}
	if st.Federation.Queue.Len() == 0 {
		t.Fatal("nothing queued to drain")
	}

	sender := &recordingSender{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		st.Federate(ctx, sender, func(error) {})
		close(done)
	}()

	// Poll for the drain rather than sleeping a fixed tick: the queue empties
	// on the first delivery pass.
	deadline := time.After(5 * time.Second)
	for st.Federation.Queue.Len() > 0 {
		select {
		case <-deadline:
			t.Fatalf("queue still holds %d after 5s; nothing drained it",
				st.Federation.Queue.Len())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Federate did not return after its context was cancelled")
	}
	if sender.count() == 0 {
		t.Error("the queue emptied but the sender was never called")
	}
}

// A site that does not federate must run Federate as a no-op that returns at
// once, so the serve path can call it unconditionally.
func TestFederateOnANonFederatingSiteReturnsAtOnce(t *testing.T) {
	st := New(nil, render.OneLayout("x"))
	done := make(chan struct{})
	go func() {
		st.Federate(context.Background(), &recordingSender{}, func(error) {})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Federate blocked on a site with no federation")
	}
}
