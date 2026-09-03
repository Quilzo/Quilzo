package activitypub

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Who is following, and what arrives in the inbox.
//
// # Followers are not content
//
// People arrive and leave, and a request to be forgotten has to be
// answerable. An append-only store cannot erase, so a follower list kept there
// would be a list that outlives every unfollow — which is both wrong and, for
// anybody in the EU, unlawful.
//
// So this is ordinary mutable state, in one file, exactly like form
// submissions and for the same reason.
//
// # Everything arriving here was written by a stranger
//
// An inbox is a public endpoint that anybody on the internet can POST to. The
// signature proves which actor sent it and nothing else: a verified actor can
// still send a malformed activity, a Follow for somebody else, or a million of
// them. So every field is bounded and checked, and the signature is a
// precondition rather than a permission.

// MaxActivity bounds an inbox payload.
//
// The body must be read before the signature covering it can be checked, which
// makes this the one place an unauthenticated caller decides how much memory
// to use.
const MaxActivity = 1 << 20

// MaxFollowers bounds the list.
//
// A ceiling rather than unbounded growth, because a follower entry is written
// on a request anybody can make. Refusing at the ceiling is visible and
// recoverable; discovering the process died is neither.
const MaxFollowers = 100_000

// Follower is a remote actor that asked to receive posts.
type Follower struct {
	// Actor is the remote actor's id, and the key.
	Actor string `json:"actor"`
	// Inbox is where to deliver. The shared inbox when the remote server
	// offers one, because delivering once to a server with fifty followers
	// rather than fifty times is the difference between federating and
	// flooding.
	Inbox string `json:"inbox"`
	// Since is when they followed.
	Since int64 `json:"since"`
}

// Followers is the list, safe for concurrent use.
type Followers struct {
	mu   sync.Mutex
	list map[string]Follower
}

// NewFollowers returns an empty list.
func NewFollowers() *Followers {
	return &Followers{list: map[string]Follower{}}
}

// MarshalJSON writes the list as an array, which is easier to read in a file
// somebody may have to inspect than a map keyed by URL.
func (f *Followers) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.All())
}

// UnmarshalJSON reads it back.
func (f *Followers) UnmarshalJSON(b []byte) error {
	var list []Follower
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = make(map[string]Follower, len(list))
	for _, e := range list {
		f.list[e.Actor] = e
	}
	return nil
}

// Add records a follower, and reports whether anything changed.
//
// Idempotent: a Follow for somebody already following is not an error and not
// a second entry. Remote servers retry, and a retry that duplicated an entry
// would double every delivery.
func (f *Followers) Add(e Follower) (bool, error) {
	if err := validActor(e.Actor); err != nil {
		return false, err
	}
	if err := validActor(e.Inbox); err != nil {
		return false, fmt.Errorf("inbox: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.list == nil {
		f.list = map[string]Follower{}
	}
	if existing, there := f.list[e.Actor]; there {
		// The inbox may legitimately move — a server changing to a shared
		// inbox, say — so it is updated, but that is not a new follower.
		if existing.Inbox != e.Inbox {
			existing.Inbox = e.Inbox
			f.list[e.Actor] = existing
		}
		return false, nil
	}
	if len(f.list) >= MaxFollowers {
		return false, fmt.Errorf(
			"this site has %d followers, which is the ceiling. Refusing "+
				"rather than growing without bound on a request anybody can "+
				"make", MaxFollowers)
	}
	f.list[e.Actor] = e
	return true, nil
}

// Remove drops a follower, and reports whether one was there.
func (f *Followers) Remove(actor string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, there := f.list[actor]; !there {
		return false
	}
	delete(f.list, actor)
	return true
}

// All returns the followers, in a stable order.
func (f *Followers) All() []Follower {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Follower, 0, len(f.list))
	for _, e := range f.list {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Actor < out[j].Actor })
	return out
}

// Inboxes returns each distinct delivery endpoint once.
//
// Distinct, because several followers on one server share an inbox and
// delivering once per follower would send the same post fifty times to the
// same address — which is how a new implementation gets rate-limited on its
// first day.
func (f *Followers) Inboxes() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range f.All() {
		if e.Inbox == "" || seen[e.Inbox] {
			continue
		}
		seen[e.Inbox] = true
		out = append(out, e.Inbox)
	}
	sort.Strings(out)
	return out
}

// Len is how many are following.
func (f *Followers) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.list)
}

// Activity is the part of an inbox payload this program reads.
//
// Only the fields that are used. A struct mirroring everything the protocol
// allows is a struct that invites somebody to trust a field nobody checked.
type Activity struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Actor  string `json:"actor"`
	Object any    `json:"object"`
}

// ObjectID reads the object as an id, whether it arrived as a string or as an
// embedded object.
//
// Both are legal and both are common: Mastodon sends a Follow with the target
// as a string, and an Undo with the original activity embedded.
func (a Activity) ObjectID() string {
	switch v := a.Object.(type) {
	case string:
		return v
	case map[string]any:
		if id, ok := v["id"].(string); ok {
			return id
		}
	}
	return ""
}

// ObjectType reads the embedded object's type, empty when the object is a bare
// id.
func (a Activity) ObjectType() string {
	if m, ok := a.Object.(map[string]any); ok {
		if t, ok := m["type"].(string); ok {
			return t
		}
	}
	return ""
}

// ParseActivity reads an inbox payload.
func ParseActivity(body []byte) (Activity, error) {
	if len(body) > MaxActivity {
		return Activity{}, fmt.Errorf(
			"this activity is larger than %d bytes", MaxActivity)
	}
	var a Activity
	if err := json.Unmarshal(body, &a); err != nil {
		return Activity{}, fmt.Errorf("this activity is not readable: %w", err)
	}
	if strings.TrimSpace(a.Type) == "" {
		return Activity{}, fmt.Errorf("this activity has no type")
	}
	if err := validActor(a.Actor); err != nil {
		return Activity{}, fmt.Errorf("actor: %w", err)
	}
	return a, nil
}

// Accept is the reply that confirms a Follow.
//
// Required rather than optional: a Follow with no Accept leaves the remote
// server showing the follow as pending forever, and the person who clicked
// concludes the site is broken.
func Accept(actor, followActivityID, follower string, now time.Time) map[string]any {
	return map[string]any{
		"@context": Context,
		"id":       fmt.Sprintf("%s#accept-%d", actor, now.UnixNano()),
		"type":     "Accept",
		"actor":    actor,
		"to":       []string{follower},
		"object":   followActivityID,
	}
}

// validActor checks a URL arrived from a stranger and is safe to store.
//
// https only, and no credentials in it. A stored actor id is later used to
// build a delivery, so anything accepted here is something this server will
// eventually make a request to — which makes this the boundary, not the
// delivery code.
func validActor(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("no actor URL")
	}
	if len(raw) > 2048 {
		return fmt.Errorf("the URL is longer than 2048 characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf(
			"%q is not https. This server will make requests to whatever it "+
				"stores here, so plaintext and odd schemes are refused at the "+
				"door rather than at the delivery", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("the URL has no host")
	}
	if u.User != nil {
		return fmt.Errorf(
			"the URL carries credentials, which a public actor id never does")
	}
	return nil
}
