// Package activitypub federates published content to the open social web.
//
// # Why a CMS should do this at all
//
// Publishing to one site and hoping people come back is the model the web had
// before feeds, and the fediverse is where the readers went. Ghost and
// WordPress both shipped ActivityPub; a publishing tool that does not federate
// in 2026 is behind rather than principled.
//
// It also costs nothing this project would not otherwise pay. The protocol is
// signed HTTP requests carrying JSON, which is the shape of everything else
// here: no client script, no dependency, and the signature verification was
// already written for the crawl gate.
//
// # The part nobody else can offer
//
// An ActivityPub object is identified by a URL, and everybody's URL is a
// mutable pointer at mutable bytes. That is why "edited after it federated" is
// an unsolved social problem across the whole network: a post can be silently
// rewritten at the origin and every copy already delivered says something
// else, with no way for a reader to tell.
//
// Here content is addressed by the hash of its own bytes. So a federated
// object carries the hash of what it was made from, and a reader — or a
// receiving server, or an archivist years later — can fetch the content and
// check it is the thing that was published. The claim is not "trust this
// origin"; it is "here is the digest, go and look".
//
// That is not a protocol extension anybody has to adopt for it to be useful.
// It rides in fields the specification already has, and a server that ignores
// it is exactly as well off as it is today.
//
// # What federating deliberately does not change
//
// Publishing still moves a pointer, and the store is still append-only. A
// follower list is not content: people arrive and leave, and a request to be
// forgotten has to be answerable. So followers live outside the merkle store
// for the same reason form submissions do — a store that cannot erase is the
// wrong home for the data that must be erasable.
package activitypub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Context is the JSON-LD context every object carries.
//
// The security vocabulary is included because that is where publicKey is
// defined, and an actor without it is one Mastodon will fetch and then refuse
// to verify anything from.
var Context = []any{
	"https://www.w3.org/ns/activitystreams",
	"https://w3id.org/security/v1",
	map[string]any{
		// The digest field, declared so a consumer that understands JSON-LD
		// sees a defined term rather than an unknown one it may drop.
		"quilzo":       "https://quilzo.github.io/ns#",
		"contentHash":  "quilzo:contentHash",
		"publishedRef": "quilzo:publishedRef",
	},
}

// ContentType is what ActivityPub responses must be served as.
//
// The long form, because Mastodon and most implementations content-negotiate
// on it and a server answering application/json is treated as not speaking the
// protocol at all.
const ContentType = `application/activity+json; charset=utf-8`

// Accepts reports whether a request wants ActivityPub rather than a web page.
//
// The same URL serves both: a person following a link gets HTML, a server
// fetching the actor gets JSON. Deciding by Accept rather than by a separate
// path is what makes the page's own address usable as its federated id, which
// is what lets somebody paste a link into a fediverse client and have it
// resolve.
func Accepts(accept string) bool {
	for _, part := range strings.Split(accept, ",") {
		mediaType := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		switch mediaType {
		case "application/activity+json",
			"application/ld+json":
			return true
		}
	}
	return false
}

// Actor is the account a fediverse server follows.
type Actor struct {
	// ID is this actor's canonical URL, and its identity. Everything else
	// about it can change; this cannot, because remote servers store it.
	ID string
	// Name is the display name, Handle the local part of @handle@domain.
	Name   string
	Handle string
	// Summary is the profile description.
	Summary string
	// PublicKeyPEM is how remote servers verify what this actor signs.
	PublicKeyPEM string
	// Published is when the site started federating.
	Published time.Time
}

// KeyID is the identifier a signature names.
//
// The actor URL with a fragment, which is the convention every implementation
// expects: a remote server takes the keyId from a signature, strips the
// fragment, fetches the actor, and reads the key out of it.
func (a Actor) KeyID() string { return a.ID + "#main-key" }

// Document renders the actor as the JSON a remote server fetches.
func (a Actor) Document(inbox, outbox, followers string) map[string]any {
	return map[string]any{
		"@context":          Context,
		"id":                a.ID,
		"type":              "Service",
		"preferredUsername": a.Handle,
		"name":              a.Name,
		"summary":           a.Summary,
		"url":               a.ID,
		"published":         a.Published.UTC().Format(time.RFC3339),
		"inbox":             inbox,
		"outbox":            outbox,
		"followers":         followers,
		// Manually approving every follower would mean a queue nobody empties,
		// and a site that publishes in public has nothing to gate.
		"manuallyApprovesFollowers": false,
		"discoverable":              true,
		"publicKey": map[string]any{
			"id":           a.KeyID(),
			"owner":        a.ID,
			"publicKeyPem": a.PublicKeyPEM,
		},
	}
}

// Type is "Service" rather than "Person" on purpose.
//
// A Person is somebody; this is a website publishing automatically. Several
// clients present the two differently, and claiming to be a person would be a
// small lie told to every reader for a slightly nicer profile card.

// Note is a published page, as the fediverse sees it.
type Note struct {
	// ID is the object's canonical URL — the page's own address, so a reader
	// following it lands on the page rather than on a copy.
	ID string
	// Actor is who published it.
	Actor string
	// Content is the HTML body a client will render.
	Content string
	// Summary is the content warning, empty for none.
	Summary string
	// URL is where a person should go, which is the same as ID here.
	URL string
	// Published is when it went live.
	Published time.Time
	// ContentHash is the store's own object id for this content.
	//
	// The field that makes a federated copy checkable. Everything else in this
	// struct is a claim by the origin; this one is falsifiable — the content
	// is filed under this name, so a reader can ask for it and check what
	// comes back hashes to the same thing.
	ContentHash string
	// PublishedRef is the commit the page was published at, so a reader can
	// ask the origin for exactly that version rather than for "the current
	// one", which is a different thing the moment anybody edits.
	PublishedRef string
}

// Document renders the note as an ActivityStreams object.
func (n Note) Document() map[string]any {
	doc := map[string]any{
		"@context":     Context,
		"id":           n.ID,
		"type":         "Note",
		"attributedTo": n.Actor,
		"content":      n.Content,
		"url":          n.URL,
		"published":    n.Published.UTC().Format(time.RFC3339),
		// Public, because this is a website. The magic collection every
		// implementation checks for.
		"to": []string{"https://www.w3.org/ns/activitystreams#Public"},
	}
	if n.Summary != "" {
		doc["summary"] = n.Summary
	}
	if n.ContentHash != "" {
		doc["contentHash"] = "sha256:" + n.ContentHash
	}
	if n.PublishedRef != "" {
		doc["publishedRef"] = n.PublishedRef
	}
	return doc
}

// Create wraps a note in the activity that delivers it.
//
// The activity gets its own id, derived from the object's. Reusing the
// object's id would make the two indistinguishable in a remote server's
// storage, and several implementations key on it.
func (n Note) Create() map[string]any {
	return map[string]any{
		"@context":  Context,
		"id":        n.ID + "#create",
		"type":      "Create",
		"actor":     n.Actor,
		"published": n.Published.UTC().Format(time.RFC3339),
		"to":        []string{"https://www.w3.org/ns/activitystreams#Public"},
		"object":    withoutContext(n.Document()),
	}
}

// Update is what an edited page federates as.
//
// Sent rather than a second Create, because a Create for an id a server
// already holds is either ignored or shown as a duplicate, and neither tells
// a reader the page changed.
func (n Note) Update() map[string]any {
	a := n.Create()
	a["type"] = "Update"
	a["id"] = n.ID + "#update-" + n.ContentHash[:min(8, len(n.ContentHash))]
	return a
}

// withoutContext strips the nested @context, which belongs on the outermost
// object only. Repeating it inside is legal and makes every payload larger for
// no gain.
func withoutContext(doc map[string]any) map[string]any {
	out := make(map[string]any, len(doc))
	for k, v := range doc {
		if k == "@context" {
			continue
		}
		out[k] = v
	}
	return out
}

// WebFinger is the discovery document that turns @handle@domain into an actor.
//
// Without it a fediverse client cannot find the account by name at all: the
// search box takes an address, and this is the only thing that maps one to a
// URL.
func WebFinger(resource string, a Actor) (map[string]any, error) {
	want, err := AccountResource(a)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(resource), want) {
		return nil, fmt.Errorf(
			"this server has no account %q; it has %q", resource, want)
	}
	return map[string]any{
		"subject": want,
		"aliases": []string{a.ID},
		"links": []any{
			map[string]any{
				"rel":  "self",
				"type": "application/activity+json",
				"href": a.ID,
			},
			map[string]any{
				"rel":  "http://webfinger.net/rel/profile-page",
				"type": "text/html",
				"href": a.ID,
			},
		},
	}, nil
}

// AccountResource is the acct: URI this actor answers to.
func AccountResource(a Actor) (string, error) {
	u, err := url.Parse(a.ID)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf(
			"the actor id %q has no host, so there is no address to publish",
			a.ID)
	}
	if strings.TrimSpace(a.Handle) == "" {
		return "", fmt.Errorf("the actor has no handle")
	}
	return "acct:" + a.Handle + "@" + u.Host, nil
}

// Collection renders an OrderedCollection, which is how the protocol carries
// a list.
func Collection(id string, items []any) map[string]any {
	if items == nil {
		items = []any{}
	}
	return map[string]any{
		"@context":     Context,
		"id":           id,
		"type":         "OrderedCollection",
		"totalItems":   len(items),
		"orderedItems": items,
	}
}

// Digest computes a content hash the same way the store does.
//
// Present for callers with bytes and no store — a preview, a test. Where a
// stored object exists its own id is used instead, because that is the name
// the content is filed under and a hash computed here would only prove that
// this code hashed something.
func Digest(rendered []byte) string {
	sum := sha256.Sum256(rendered)
	return hex.EncodeToString(sum[:])
}

// Marshal renders a document the way the protocol expects it on the wire.
func Marshal(doc map[string]any) ([]byte, error) {
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("cannot render this activity: %w", err)
	}
	return body, nil
}

// SortedKeys is a small helper for deterministic output in tests and logs.
func SortedKeys(doc map[string]any) []string {
	out := make([]string, 0, len(doc))
	for k := range doc {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
