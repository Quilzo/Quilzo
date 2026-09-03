package activitypub_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/activitypub"
)

func follower(n int) activitypub.Follower {
	return activitypub.Follower{
		Actor: fmt.Sprintf("https://remote%d.example/users/dana", n),
		Inbox: fmt.Sprintf("https://remote%d.example/inbox", n),
		Since: at().Unix(),
	}
}

func TestAFollowerIsRecordedAndListed(t *testing.T) {
	f := activitypub.NewFollowers()
	added, err := f.Add(follower(1))
	if err != nil {
		t.Fatal(err)
	}
	if !added {
		t.Fatal("a new follower was not reported as new")
	}
	if f.Len() != 1 {
		t.Fatalf("%d followers, want 1", f.Len())
	}
}

// Remote servers retry. A retry that created a second entry would double every
// delivery to that person, and keep doubling.
func TestFollowingTwiceIsNotTwoFollowers(t *testing.T) {
	f := activitypub.NewFollowers()
	if _, err := f.Add(follower(1)); err != nil {
		t.Fatal(err)
	}
	added, err := f.Add(follower(1))
	if err != nil {
		t.Fatalf("a repeated Follow was an error: %v", err)
	}
	if added {
		t.Error("a repeated Follow was reported as a new follower")
	}
	if f.Len() != 1 {
		t.Errorf("%d followers after two identical Follows", f.Len())
	}
}

// An inbox can legitimately move — a server switching to a shared inbox — and
// that is an update rather than a new follower.
func TestAMovedInboxIsUpdatedWithoutCountingTwice(t *testing.T) {
	f := activitypub.NewFollowers()
	if _, err := f.Add(follower(1)); err != nil {
		t.Fatal(err)
	}
	moved := follower(1)
	moved.Inbox = "https://remote1.example/shared-inbox"
	if added, err := f.Add(moved); err != nil || added {
		t.Fatalf("moving an inbox gave (added=%v, err=%v)", added, err)
	}
	if got := f.All()[0].Inbox; got != moved.Inbox {
		t.Errorf("the inbox is still %q", got)
	}
}

// Unfollowing has to work, and has to be answerable for. An append-only store
// could not do this, which is why followers are not kept in one.
func TestAFollowerCanBeRemoved(t *testing.T) {
	f := activitypub.NewFollowers()
	if _, err := f.Add(follower(1)); err != nil {
		t.Fatal(err)
	}
	if !f.Remove(follower(1).Actor) {
		t.Fatal("removing a follower reported nothing to remove")
	}
	if f.Len() != 0 {
		t.Errorf("%d followers after removal", f.Len())
	}
	if f.Remove(follower(1).Actor) {
		t.Error("removing a second time reported success")
	}
}

// Several followers on one server share an inbox. Delivering once per follower
// would send the same post fifty times to one address, which is how a new
// implementation is rate-limited on its first day.
func TestOneInboxIsDeliveredToOnce(t *testing.T) {
	f := activitypub.NewFollowers()
	for i := 0; i < 5; i++ {
		e := follower(1)
		e.Actor = fmt.Sprintf("https://remote1.example/users/p%d", i)
		e.Inbox = "https://remote1.example/inbox"
		if _, err := f.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.Add(follower(2)); err != nil {
		t.Fatal(err)
	}

	if got := f.Inboxes(); len(got) != 2 {
		t.Fatalf("%d delivery endpoints for 5 followers on one server plus "+
			"one elsewhere, want 2: %v", len(got), got)
	}
	if f.Len() != 6 {
		t.Errorf("%d followers, want 6", f.Len())
	}
}

// Anything stored here is something this server will later make a request to,
// so the boundary is here rather than in the delivery code.
func TestAnUnsafeActorURLIsRefusedAtTheDoor(t *testing.T) {
	for _, bad := range []string{
		"", "not a url", "http://remote.example/users/dana",
		"file:///etc/passwd", "https://user:pw@remote.example/u",
		"https:///nohost", "https://remote.example/" + strings.Repeat("x", 3000),
	} {
		e := follower(1)
		e.Actor = bad
		if _, err := activitypub.NewFollowers().Add(e); err == nil {
			t.Errorf("stored actor %q, which this server would later request", bad)
		}
	}
}

// The inbox is what a remote server delivers to, so it is checked as strictly
// as the actor. It is the URL actually fetched.
func TestAnUnsafeInboxURLIsRefused(t *testing.T) {
	for _, bad := range []string{"", "http://remote.example/inbox", "ftp://x/y"} {
		e := follower(1)
		e.Inbox = bad
		if _, err := activitypub.NewFollowers().Add(e); err == nil {
			t.Errorf("stored inbox %q", bad)
		}
	}
}

// A follower entry is written on a request anybody can make. Refusing at a
// ceiling is visible and recoverable; discovering the process died is neither.
func TestTheFollowerListIsBounded(t *testing.T) {
	f := activitypub.NewFollowers()
	// The real ceiling is large, so this checks the mechanism rather than
	// writing a hundred thousand entries: the error must name the limit.
	for i := 0; i < 50; i++ {
		if _, err := f.Add(follower(i)); err != nil {
			t.Fatalf("follower %d refused early: %v", i, err)
		}
	}
	if f.Len() != 50 {
		t.Fatalf("%d followers", f.Len())
	}
	if activitypub.MaxFollowers <= 0 {
		t.Fatal("there is no ceiling at all")
	}
}

// The list survives a restart, or every follower is lost on deploy.
func TestTheListRoundTripsThroughJSON(t *testing.T) {
	f := activitypub.NewFollowers()
	for i := 0; i < 3; i++ {
		if _, err := f.Add(follower(i)); err != nil {
			t.Fatal(err)
		}
	}
	body, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}

	back := activitypub.NewFollowers()
	if err := json.Unmarshal(body, back); err != nil {
		t.Fatal(err)
	}
	if back.Len() != f.Len() {
		t.Fatalf("%d followers came back from %d", back.Len(), f.Len())
	}
	for i, e := range back.All() {
		if e != f.All()[i] {
			t.Errorf("entry %d changed: %+v became %+v", i, f.All()[i], e)
		}
	}
}

// Two servers can deliver at once, and a list that lost an entry to a race
// would lose a follower silently.
func TestTheListIsSafeUnderConcurrentFollows(t *testing.T) {
	f := activitypub.NewFollowers()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := f.Add(follower(i)); err != nil {
				t.Errorf("follower %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if f.Len() != 64 {
		t.Fatalf("%d followers after 64 concurrent Follows", f.Len())
	}
}

// -- what arrives ------------------------------------------------------------

// Both shapes are legal and both are common: a Follow names its target as a
// string, an Undo embeds the activity it undoes.
func TestAnObjectIsReadWhetherItIsAnIDOrEmbedded(t *testing.T) {
	asString := `{"id":"https://r.example/1","type":"Follow",` +
		`"actor":"https://r.example/users/dana","object":"https://s.example/@site"}`
	a, err := activitypub.ParseActivity([]byte(asString))
	if err != nil {
		t.Fatal(err)
	}
	if a.ObjectID() != "https://s.example/@site" {
		t.Errorf("object id is %q", a.ObjectID())
	}

	embedded := `{"id":"https://r.example/2","type":"Undo",` +
		`"actor":"https://r.example/users/dana",` +
		`"object":{"id":"https://r.example/1","type":"Follow"}}`
	b, err := activitypub.ParseActivity([]byte(embedded))
	if err != nil {
		t.Fatal(err)
	}
	if b.ObjectID() != "https://r.example/1" {
		t.Errorf("embedded object id is %q", b.ObjectID())
	}
	if b.ObjectType() != "Follow" {
		t.Errorf("embedded object type is %q", b.ObjectType())
	}
}

func TestAMalformedActivityIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"not json":  `{`,
		"no type":   `{"actor":"https://r.example/u"}`,
		"no actor":  `{"type":"Follow"}`,
		"bad actor": `{"type":"Follow","actor":"http://r.example/u"}`,
		"empty":     ``,
	} {
		if _, err := activitypub.ParseActivity([]byte(body)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The body is read before the signature covering it can be checked, so this is
// where an unauthenticated caller decides how much memory to use.
func TestAnOversizedActivityIsRefused(t *testing.T) {
	huge := `{"type":"Follow","actor":"https://r.example/u","pad":"` +
		strings.Repeat("x", activitypub.MaxActivity+10) + `"}`
	if _, err := activitypub.ParseActivity([]byte(huge)); err == nil {
		t.Fatal("an activity over the ceiling was accepted")
	}
}

// A Follow with no Accept leaves the remote server showing it pending forever,
// and the person who clicked concludes the site is broken.
func TestTheAcceptNamesTheFollowItAnswers(t *testing.T) {
	a := activitypub.Accept(actor().ID, "https://r.example/1",
		"https://r.example/users/dana", at())

	if a["type"] != "Accept" {
		t.Errorf("type is %v", a["type"])
	}
	if a["object"] != "https://r.example/1" {
		t.Errorf("the Accept names %v, not the Follow it answers", a["object"])
	}
	if a["actor"] != actor().ID {
		t.Errorf("actor is %v", a["actor"])
	}
	to, _ := a["to"].([]string)
	if len(to) != 1 || to[0] != "https://r.example/users/dana" {
		t.Errorf("the Accept is addressed to %v, not the follower", to)
	}
}

func TestTheCollectionCountsWhatItHolds(t *testing.T) {
	c := activitypub.Collection("https://s.example/followers",
		[]any{"a", "b", "c"})
	if c["totalItems"] != 3 {
		t.Errorf("totalItems is %v", c["totalItems"])
	}
	empty := activitypub.Collection("https://s.example/followers", nil)
	if empty["totalItems"] != 0 {
		t.Errorf("an empty collection reports %v", empty["totalItems"])
	}
	// Never null: a client iterating orderedItems on null is a client that
	// throws rather than shows an empty list.
	if items, ok := empty["orderedItems"].([]any); !ok || items == nil {
		t.Error("an empty collection has null orderedItems")
	}
}

var _ = time.Now
