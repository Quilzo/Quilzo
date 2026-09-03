package public

import (
	"crypto"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/activitypub"
	"github.com/quilzo/quilzo/internal/httpsig"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// What this site sends must be what its own inbox would accept.
//
// Asking of others what this program refuses itself is how an implementation
// ends up interoperating with nobody — and the body-digest requirement here
// exists precisely because the inbox was exploitable without it. A delivery
// signed the old way would be refused by any server that fixed the same bug.
func TestADeliveryIsSignedTheWayThisSitesOwnInboxDemands(t *testing.T) {
	key, publicPEM := fedKey(t)
	now := time.Unix(1787000000, 0)

	var captured *http.Request
	var body []byte
	s := &Signer{
		KeyID: "https://marginalia.example/@#main-key",
		Key:   key,
		Now:   func() time.Time { return now },
		Post: func(req *http.Request) (int, error) {
			captured = req
			body, _ = io.ReadAll(req.Body)
			return http.StatusAccepted, nil
		},
	}

	if err := s.Send("https://r.example/inbox",
		map[string]any{"type": "Create", "id": "x"}); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if captured == nil {
		t.Fatal("nothing was sent")
	}

	// Verify it exactly as a receiving server would.
	remote, err := httpsig.ParsePEM("https://marginalia.example/@#main-key",
		publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the request as it arrives at the far end.
	arriving := httptest.NewRequest("POST", "https://r.example/inbox",
		stringReader(string(body)))
	arriving.Host = "r.example"
	for k, v := range captured.Header {
		arriving.Header[k] = v
	}

	signed, err := httpsig.Verify(arriving, []httpsig.PublicKey{remote}, 0, now)
	if err != nil {
		t.Fatalf("what this site sends does not verify: %v", err)
	}
	if signed == nil {
		t.Fatal("the delivery carried no signature")
	}
	if !signed.CoversBody() {
		t.Fatal("the delivery's signature does not cover the body, which is " +
			"what this program's own inbox refuses")
	}
	if err := httpsig.CheckContentDigest(arriving, body); err != nil {
		t.Fatalf("the digest does not match the body sent: %v", err)
	}
	if got := captured.Header.Get("Content-Type"); got != activitypub.ContentType {
		t.Errorf("Content-Type is %q; a server that content-negotiates would "+
			"not recognise this as an activity", got)
	}
}

// A 410 means the account is gone. Reported as an error so the queue records
// it and exhausts its attempts, rather than retrying forever against something
// that will never answer differently.
func TestAGoneInboxIsAnErrorSoTheQueueGivesUp(t *testing.T) {
	key, _ := fedKey(t)
	for _, status := range []int{http.StatusGone, http.StatusNotFound,
		http.StatusInternalServerError} {
		s := &Signer{
			KeyID: "k", Key: key,
			Now:  func() time.Time { return time.Unix(1787000000, 0) },
			Post: func(*http.Request) (int, error) { return status, nil },
		}
		if err := s.Send("https://r.example/inbox",
			map[string]any{"type": "Create"}); err == nil {
			t.Errorf("status %d was treated as a successful delivery", status)
		}
	}
}

func TestASuccessfulDeliveryIsNotAnError(t *testing.T) {
	key, _ := fedKey(t)
	for _, status := range []int{200, 201, 202, 204} {
		s := &Signer{
			KeyID: "k", Key: key,
			Now:  func() time.Time { return time.Unix(1787000000, 0) },
			Post: func(*http.Request) (int, error) { return status, nil },
		}
		if err := s.Send("https://r.example/inbox",
			map[string]any{"type": "Create"}); err != nil {
			t.Errorf("status %d was treated as a failure: %v", status, err)
		}
	}
}

// A site with no followers queues nothing, rather than building activities
// nobody will receive.
func TestAnnouncingWithNoFollowersQueuesNothing(t *testing.T) {
	st := &Site{Federation: &Federation{
		Actor:     activitypub.Actor{ID: "https://marginalia.example/@"},
		Followers: activitypub.NewFollowers(),
		Queue:     activitypub.NewQueue(),
	}}
	n, err := st.Announce(nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("queued %d deliveries with no followers", n)
	}
}

var _ crypto.Signer = (crypto.Signer)(nil)

// The whole point of the feature: a published page reaches the people who
// followed.
//
// Everything else here is about doing it correctly. This is about doing it at
// all — and it is the case the other tests miss, because a queue that enqueues
// nothing passes every test asserting what a delivery looks like.
func TestAPublishedPageIsQueuedForEveryFollower(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "<p>Welcome.</p>"},
		"about": map[string]any{"title": "About", "body": "<p>Founded.</p>"},
	}, "pages", "dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, s.GetRef(site.RefDraft)); err != nil {
		t.Fatal(err)
	}

	st := New(s, render.OneLayout("{{ page.body }}"))
	st.BaseURL = "https://marginalia.example"
	st.Index = "index"

	followers := activitypub.NewFollowers()
	for _, host := range []string{"a.example", "b.example"} {
		if _, err := followers.Add(activitypub.Follower{
			Actor: "https://" + host + "/users/x",
			Inbox: "https://" + host + "/inbox",
		}); err != nil {
			t.Fatal(err)
		}
	}
	queue := activitypub.NewQueue()
	st.Federation = &Federation{
		Actor:     activitypub.Actor{ID: "https://marginalia.example/@"},
		Followers: followers, Queue: queue,
		Now: func() time.Time { return time.Unix(1787000000, 0) },
	}

	queued, err := st.Announce(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Two pages to two inboxes.
	if queued != 4 {
		t.Fatalf("queued %d deliveries for 2 pages and 2 followers, want 4", queued)
	}
	if queue.Len() != 4 {
		t.Fatalf("the queue holds %d", queue.Len())
	}

	// And what is queued is addressed to the followers, carrying the content
	// hash that makes it checkable.
	seen := map[string]int{}
	for _, d := range queue.Due() {
		seen[d.Inbox]++
		obj, _ := d.Activity["object"].(map[string]any)
		if obj == nil {
			t.Fatal("a queued activity has no object")
		}
		hash, _ := obj["contentHash"].(string)
		if hash == "" {
			t.Error("a queued post carries no content hash, so a reader " +
				"cannot check the copy they receive")
		}
	}
	for _, inbox := range []string{"https://a.example/inbox", "https://b.example/inbox"} {
		if seen[inbox] != 2 {
			t.Errorf("%s got %d of 2 pages", inbox, seen[inbox])
		}
	}
}

// Announcing one page queues that page, not the whole site. Republishing
// everything on every edit would be the difference between a feed and a flood.
func TestAnnouncingOnePageDoesNotResendTheSite(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "<p>Welcome.</p>"},
		"about": map[string]any{"title": "About", "body": "<p>Founded.</p>"},
		"terms": map[string]any{"title": "Terms", "body": "<p>Legal.</p>"},
	}, "pages", "dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, s.GetRef(site.RefDraft)); err != nil {
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
	queue := activitypub.NewQueue()
	st.Federation = &Federation{
		Actor:     activitypub.Actor{ID: "https://marginalia.example/@"},
		Followers: followers, Queue: queue,
		Now: func() time.Time { return time.Unix(1787000000, 0) },
	}

	queued, err := st.Announce([]string{"about"})
	if err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Fatalf("announcing one page queued %d deliveries, want 1", queued)
	}
	got := queue.Due()
	obj, _ := got[0].Activity["object"].(map[string]any)
	if id, _ := obj["id"].(string); id != "https://marginalia.example/about" {
		t.Errorf("the queued post is %q, not the page announced", id)
	}
}
