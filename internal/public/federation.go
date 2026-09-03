package public

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/activitypub"
	"github.com/quilzo/quilzo/internal/httpsig"
	"github.com/quilzo/quilzo/internal/site"
)

// The routes that make a published site followable.
//
// # Why these live here rather than in internal/activitypub
//
// That package knows the protocol; this one knows the site. Keeping the two
// apart is what let the object model be tested without a server, and it is the
// same split as every other integration: a package for the wire format, and
// the wiring where the wiring belongs.

// Federation is the actor this site publishes as.
//
// Nil means the site does not federate, which is where every deployment
// starts. Publishing an actor is a commitment — remote servers store its id
// and will keep fetching it — so it happens when an operator says so.
type Federation struct {
	// Actor is what a remote server fetches.
	Actor activitypub.Actor
	// Followers is the list, persisted by the caller.
	Followers *activitypub.Followers
	// Save persists the list after a change. Nil means changes are kept only
	// in memory, which loses every follower on restart and is refused at
	// startup rather than discovered later.
	Save func() error
	// Fetch retrieves a remote actor document, so an inbound signature can be
	// checked against the key of whoever sent it.
	//
	// Supplied rather than built here, because it must go through the same
	// connect-time address check as every other outbound request. A federation
	// package that made its own HTTP client would be a second place for that
	// check to be forgotten.
	Fetch func(url string) ([]byte, error)
	// Deliver queues an outbound activity. Nil means nothing is delivered,
	// which makes the site followable and silent.
	Deliver func(inbox string, activity map[string]any)
	// Queue holds deliveries that have not gone out yet. Nil means the site is
	// followable and silent, which is a coherent state and not the intended
	// one.
	Queue *activitypub.Queue
	// Sender drains the queue: it signs and POSTs one activity to one inbox.
	// Nil means queued activities are held and never sent — the same silent,
	// coherent, unintended state the queue itself has when nothing runs it.
	Sender activitypub.Sender
	// Now is a clock seam for tests.
	Now func() time.Time

	// Announced records the last commit whose changes were delivered, and
	// reads it back. Nil keeps the marker in memory, so a restart announces
	// nothing rather than everything — the safe direction, and not the useful
	// one.
	Announced       func() string
	RecordAnnounced func(commit string) error

	// guard bounds what an unverified caller can make this server do. Not a
	// setting: the bounds exist whenever the inbox does.
	guard inboxGuard
	// announced is the in-memory marker, used when nothing persists one.
	announced string
}

func (f *Federation) lastAnnounced() string {
	if f.Announced != nil {
		return f.Announced()
	}
	return f.announced
}

func (f *Federation) rememberAnnounced(commit string) error {
	f.announced = commit
	if f.RecordAnnounced != nil {
		return f.RecordAnnounced(commit)
	}
	return nil
}

// Announce queues a published page for delivery to every follower.
//
// Called after a publish rather than during it: delivery talks to servers this
// one does not control, and a publish that waited on the slowest of them would
// fail when any of them is down — which is the wrong failure, because the page
// is published either way.
//
// Returns how many inboxes were queued, so a caller can say "sent to eleven
// servers" rather than nothing.
func (st *Site) Announce(names []string) (int, error) {
	if st.Federation == nil || st.Federation.Queue == nil {
		return 0, nil
	}
	inboxes := st.Federation.Followers.Inboxes()
	if len(inboxes) == 0 {
		return 0, nil
	}

	notes, err := st.notes()
	if err != nil {
		return 0, err
	}
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}

	queued := 0
	for _, n := range notes {
		if len(wanted) > 0 && !wanted[pageOf(n.ID, st.BaseURL, st.Index)] {
			continue
		}
		if err := st.Federation.Queue.Enqueue(inboxes, n.Create()); err != nil {
			return queued, err
		}
		queued += len(inboxes)
	}
	return queued, nil
}

// announceChanges queues the right activity for each changed page.
//
// # Why the kind matters, and is not cosmetic
//
// A Create for an id a receiving server already holds is deduplicated: it is
// dropped or shown as a repeat, and either way the edit is invisible to the
// people who followed. So an edited page must go out as an Update, and a new
// one as a Create. Announcing every change as a Create — which is what reusing
// Announce would do — makes the common case, an edit, a no-op on the receiver
// while looking like a working delivery here. That is the failure this whole
// path exists to avoid, one layer in.
//
// A removed page has no note in the current tree, so there is nothing to build
// an activity from. A Delete/Tombstone is a real thing to send and a separate
// piece of work with its own failure modes (a Delete for an id a server never
// saw, replay, addressing); it is deliberately not improvised here. The page
// stops being served immediately regardless; what is deferred is telling
// remote timelines to drop their copy.
func (st *Site) announceChanges(changes []site.Change) (int, error) {
	if st.Federation == nil || st.Federation.Queue == nil {
		return 0, nil
	}
	inboxes := st.Federation.Followers.Inboxes()
	if len(inboxes) == 0 {
		return 0, nil
	}

	notes, err := st.notes()
	if err != nil {
		return 0, err
	}
	byName := make(map[string]activitypub.Note, len(notes))
	for _, n := range notes {
		byName[pageOf(n.ID, st.BaseURL, st.Index)] = n
	}

	queued := 0
	for _, ch := range changes {
		note, ok := byName[ch.Path]
		if !ok {
			// Removed, or a non-page tree entry (a redirect table, a schema).
			// Nothing to announce either way.
			continue
		}
		var activity map[string]any
		switch ch.Kind {
		case "added":
			activity = note.Create()
		case "modified":
			activity = note.Update()
		default:
			continue
		}
		if err := st.Federation.Queue.Enqueue(inboxes, activity); err != nil {
			return queued, err
		}
		queued += len(inboxes)
	}
	return queued, nil
}

// pageOf recovers a page name from a federated id.
func pageOf(id, baseURL, index string) string {
	name := strings.TrimPrefix(id, strings.TrimSuffix(baseURL, "/"))
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		return index
	}
	return name
}

// notes renders the published pages as federated objects.
//
// Through the same accessor the sitemap and the page handler use, so the
// outbox cannot advertise a page the site refuses to serve — the gap that
// makes a feed a disclosure rather than a listing.
func (st *Site) notes() ([]activitypub.Note, error) {
	if st.BaseURL == "" {
		// Refused rather than guessed from Host, which is attacker-controlled.
		// Every id here is stored permanently by remote servers, so one built
		// from a forged header is a mistake that cannot be withdrawn.
		return nil, fmt.Errorf(
			"no base URL is configured, so federated ids cannot be produced")
	}
	pages, hashes, err := st.pages()
	if err != nil {
		return nil, err
	}
	// The commit, so a reader can ask for exactly this version rather than
	// "the current one", which is a different thing the moment anybody edits.
	ref := st.Store.GetRef(st.ref())

	var changed map[string]time.Time
	if st.LastChanged != nil {
		changed, _ = st.LastChanged()
	}

	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)

	base := strings.TrimSuffix(st.BaseURL, "/")
	out := make([]activitypub.Note, 0, len(names))
	for _, name := range names {
		fields, _ := pages[name].(map[string]any)
		if fields == nil {
			continue
		}
		body, _ := fields["body"].(string)
		title, _ := fields["title"].(string)

		published := st.now()
		if when, ok := changed[name]; ok && !when.IsZero() {
			published = when
		}

		id := base + "/" + name
		if name == st.Index {
			id = base + "/"
		}
		out = append(out, activitypub.Note{
			ID: id, Actor: st.Federation.Actor.ID,
			Content: body, Summary: title, URL: id, Published: published,
			// The store's own object id for this page, not a digest computed
			// here. The two would usually agree and the store's is the one
			// that means something: it is the name the content is filed
			// under, so a reader holding it and the commit can ask the origin
			// for exactly those bytes and check what comes back.
			//
			// A hash this code invented would only prove that this code
			// hashed something.
			ContentHash:  hashes[name],
			PublishedRef: ref,
		})
	}
	return out, nil
}

// remoteActor is the part of a fetched actor document this program reads.
type remoteActor struct {
	ID        string `json:"id"`
	Inbox     string `json:"inbox"`
	Endpoints struct {
		SharedInbox string `json:"sharedInbox"`
	} `json:"endpoints"`
	PublicKey struct {
		ID    string `json:"id"`
		Owner string `json:"owner"`
		PEM   string `json:"publicKeyPem"`
	} `json:"publicKey"`
}

// remoteInbox finds where to deliver to a remote actor.
//
// The shared inbox when the server offers one. Fifty followers on one server
// is one delivery rather than fifty, which is the difference between
// federating and flooding.
func (st *Site) remoteInbox(actorURL string) (string, error) {
	doc, err := st.fetchActor(actorURL)
	if err != nil {
		return "", err
	}
	if doc.Endpoints.SharedInbox != "" {
		return doc.Endpoints.SharedInbox, nil
	}
	if doc.Inbox == "" {
		return "", fmt.Errorf(
			"the actor at %s publishes no inbox, so there is nowhere to "+
				"deliver", actorURL)
	}
	return doc.Inbox, nil
}

func (st *Site) fetchActor(actorURL string) (remoteActor, error) {
	now := st.now()

	body, cached := st.Federation.guard.cached(actorURL, now)
	if !cached {
		// One slot per outbound request. A per-source rate limit cannot see a
		// burst spread across many sources; this can, and past the ceiling an
		// inbox request is refused rather than adding another connection.
		if !st.Federation.guard.acquire() {
			return remoteActor{}, fmt.Errorf(
				"too many verifications are already in flight; try again")
		}
		var err error
		body, err = st.Federation.Fetch(actorURL)
		st.Federation.guard.release()
		if err != nil {
			return remoteActor{}, fmt.Errorf("cannot fetch %s: %w", actorURL, err)
		}
		// Cached after the fetch and before parsing, so a server delivering
		// several posts is fetched once rather than once per activity.
		st.Federation.guard.remember(actorURL, body, now)
	}
	var doc remoteActor
	if err := json.Unmarshal(body, &doc); err != nil {
		return remoteActor{}, fmt.Errorf(
			"the document at %s is not an actor: %w", actorURL, err)
	}
	// The document must claim to be the actor that was asked for. A server
	// that returned somebody else's actor would otherwise have its key used to
	// verify signatures attributed to the one requested.
	if doc.ID != "" && doc.ID != actorURL {
		return remoteActor{}, fmt.Errorf(
			"%s returned an actor claiming to be %s", actorURL, doc.ID)
	}
	return doc, nil
}

// verifyInbox checks the signature on an inbound activity.
//
// The key comes from the actor the activity claims to be from, and the key it
// names must belong to that actor. Without the ownership check, a server could
// sign with its own key while claiming to be somebody on another host.
func (st *Site) verifyInbox(r *http.Request, a activitypub.Activity,
	body []byte) error {

	doc, err := st.fetchActor(a.Actor)
	if err != nil {
		return err
	}
	if doc.PublicKey.PEM == "" {
		return fmt.Errorf("the actor at %s publishes no key", a.Actor)
	}
	if owner := doc.PublicKey.Owner; owner != "" && owner != a.Actor {
		return fmt.Errorf(
			"the key at %s is owned by %s, so it does not speak for this actor",
			a.Actor, owner)
	}

	key, err := httpsig.ParsePEM(doc.PublicKey.ID, doc.PublicKey.PEM)
	if err != nil {
		return fmt.Errorf("the key at %s is unreadable: %w", a.Actor, err)
	}

	signed, err := httpsig.Verify(r, []httpsig.PublicKey{key}, 0, st.now())
	if err != nil {
		return err
	}
	if signed == nil {
		return fmt.Errorf(
			"this activity is not signed. An inbox is a public endpoint, so " +
				"an unsigned POST is an anonymous instruction")
	}

	// The body has to be inside what was signed.
	//
	// Without this the signature covers the envelope and not the letter: it
	// says a known actor sent *a* POST to this path, and the body can then be
	// replaced with anything. Capturing one legitimate Follow would let
	// somebody send any activity as that actor — an Undo removing another
	// follower, a Delete — because the bytes were never part of the proof.
	//
	// That was true here until it was tested for, and the test that found it
	// replayed a Follow's signature onto an Undo and got a 202.
	//
	// Two separate conditions, and both are needed. A digest that matches but
	// was not signed is one the attacker computed for their own body. A signed
	// digest header that is absent proves nothing about bytes nobody hashed.
	if !signed.CoversBody() {
		return fmt.Errorf(
			"this signature does not cover a body digest, so it proves who " +
				"sent a request to this address and nothing about what was in " +
				"it. Sign Content-Digest along with the request line")
	}
	if err := httpsig.CheckContentDigest(r, body); err != nil {
		return err
	}
	return nil
}

func (st *Site) now() time.Time {
	if st.Federation != nil && st.Federation.Now != nil {
		return st.Federation.Now()
	}
	return time.Now()
}

// webfinger maps @handle@domain onto the actor.
//
// Without it a fediverse client cannot find the account by name at all: the
// search box takes an address, and this is the only thing that turns one into
// a URL.
func (st *Site) webfinger(w http.ResponseWriter, r *http.Request) {
	if st.Federation == nil {
		http.NotFound(w, r)
		return
	}
	doc, err := activitypub.WebFinger(r.URL.Query().Get("resource"),
		st.Federation.Actor)
	if err != nil {
		// 404 rather than 400. "No such account here" is the honest answer to
		// a lookup for somebody else, and it is what every implementation
		// expects; a 400 reads as this server being broken.
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, "application/jrd+json; charset=utf-8", doc)
}

// actor serves the account document.
func (st *Site) actor(w http.ResponseWriter, r *http.Request) {
	if st.Federation == nil {
		http.NotFound(w, r)
		return
	}
	f := st.Federation
	writeJSON(w, activitypub.ContentType, f.Actor.Document(
		f.Actor.ID+"/inbox", f.Actor.ID+"/outbox", f.Actor.ID+"/followers"))
}

// followers serves the follower collection.
//
// The count only, not the list. Publishing who follows a site exposes a
// reader's interest to anybody who asks, and no client needs the names to
// work — Mastodon shows a number.
func (st *Site) followers(w http.ResponseWriter, r *http.Request) {
	if st.Federation == nil {
		http.NotFound(w, r)
		return
	}
	c := activitypub.Collection(st.Federation.Actor.ID+"/followers", nil)
	c["totalItems"] = st.Federation.Followers.Len()
	writeJSON(w, activitypub.ContentType, c)
}

// outbox serves what has been published.
func (st *Site) outbox(w http.ResponseWriter, r *http.Request) {
	if st.Federation == nil {
		http.NotFound(w, r)
		return
	}
	notes, err := st.notes()
	if err != nil {
		http.Error(w, "cannot read the published pages", http.StatusInternalServerError)
		return
	}
	items := make([]any, 0, len(notes))
	for _, n := range notes {
		items = append(items, n.Create())
	}
	writeJSON(w, activitypub.ContentType,
		activitypub.Collection(st.Federation.Actor.ID+"/outbox", items))
}

// inbox receives activities from remote servers.
//
// # What the signature does and does not establish
//
// It proves which actor sent this. It does not make them trustworthy, and it
// does not mean the activity is well formed or that its actor may do what it
// asks. So it is a precondition checked first, and every field is checked
// after it regardless.
func (st *Site) inbox(w http.ResponseWriter, r *http.Request) {
	if st.Federation == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	// Bounded before anything else, because everything else costs something.
	//
	// Verifying means fetching the sender's key from their server, so an
	// unbounded inbox lets anybody make this server issue requests to a host
	// they name. Measured at two hundred POSTs producing two hundred outbound
	// requests before this existed — reflection, with this server's address on
	// the traffic arriving at somebody else.
	if !st.Federation.guard.allow(sourceOf(r), st.now()) {
		tooMany(w, 60, "too many activities from this address. Verifying one "+
			"means fetching the sender's key from their server, so this "+
			"endpoint is rate limited to keep it from becoming a way to send "+
			"traffic to a third party")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, activitypub.MaxActivity+1))
	if err != nil {
		http.Error(w, "cannot read the request", http.StatusBadRequest)
		return
	}

	activity, err := activitypub.ParseActivity(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The signature is checked against the sending actor's own key, which
	// means fetching their actor document — a request to a URL a stranger
	// named. That is the one part of this protocol that cannot be avoided, and
	// it goes through the same connect-time address check as every other
	// outbound request rather than a second one written here.
	if st.Federation.Fetch == nil {
		http.Error(w,
			"this server cannot verify inbox signatures because no fetcher is "+
				"configured, and an unverified activity is not an instruction",
			http.StatusServiceUnavailable)
		return
	}

	// Everything checkable without a network request is checked first.
	//
	// Verifying means fetching the sender's key from their server, so doing it
	// before the cheap local checks turns "a Follow addressed to somebody
	// else" into an outbound request to whatever host the sender named. That
	// is a request anybody can cause this server to make, for a message it was
	// always going to refuse.
	if activity.Type == "Follow" {
		if want := st.Federation.Actor.ID; activity.ObjectID() != want {
			http.Error(w, fmt.Sprintf(
				"this Follow is for %q and this server is %q",
				activity.ObjectID(), want), http.StatusBadRequest)
			return
		}
	}

	if err := st.verifyInbox(r, activity, body); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	switch activity.Type {
	case "Follow":
		st.handleFollow(w, activity)
	case "Undo":
		st.handleUndo(w, activity)
	case "Delete":
		// A remote account deleting itself. Treated as an unfollow, because
		// the alternative is delivering to an inbox that will 410 forever.
		if st.Federation.Followers.Remove(activity.Actor) {
			_ = st.saveFollowers()
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		// Accepted and ignored. A 400 for an activity type this program does
		// not implement would make remote servers retry it forever, and there
		// is nothing wrong with the request — it is simply not for us.
		w.WriteHeader(http.StatusAccepted)
	}
}

// handleFollow records a follower and confirms it.
//
// The Follow's target was already checked before the signature, so that a
// message for somebody else costs no outbound request.
func (st *Site) handleFollow(w http.ResponseWriter, a activitypub.Activity) {
	inbox, err := st.remoteInbox(a.Actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	added, err := st.Federation.Followers.Add(activitypub.Follower{
		Actor: a.Actor, Inbox: inbox, Since: st.now().Unix(),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if added {
		if err := st.saveFollowers(); err != nil {
			// Refuse rather than accept. Reporting success for a follow that
			// will not survive a restart is worse than making the remote
			// server retry.
			http.Error(w, "cannot record the follower",
				http.StatusInternalServerError)
			return
		}
	}

	// The Accept is queued rather than sent inline: a remote server waiting on
	// this response should not wait on a request to a third one.
	if st.Federation.Deliver != nil {
		st.Federation.Deliver(inbox, activitypub.Accept(
			st.Federation.Actor.ID, a.ID, a.Actor, st.now()))
	}
	w.WriteHeader(http.StatusAccepted)
}

func (st *Site) handleUndo(w http.ResponseWriter, a activitypub.Activity) {
	// Only an Undo of a Follow, and only of the sender's own. An Undo naming
	// somebody else's follow would let any server unfollow on their behalf.
	if t := a.ObjectType(); t != "" && t != "Follow" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if st.Federation.Followers.Remove(a.Actor) {
		if err := st.saveFollowers(); err != nil {
			http.Error(w, "cannot record the unfollow",
				http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

func (st *Site) saveFollowers() error {
	if st.Federation.Save == nil {
		return nil
	}
	return st.Federation.Save()
}

func writeJSON(w http.ResponseWriter, contentType string, doc map[string]any) {
	body, err := activitypub.Marshal(doc)
	if err != nil {
		http.Error(w, "cannot render this document",
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	// Federation documents are read by machines that cache aggressively. A
	// short max-age keeps a key rotation from taking a day to propagate.
	w.Header().Set("Cache-Control", "max-age=300")
	_, _ = w.Write(body)
}

var _ = strings.TrimSpace
