package activitypub_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/activitypub"
)

func at() time.Time { return time.Unix(1787000000, 0).UTC() }

func actor() activitypub.Actor {
	return activitypub.Actor{
		ID: "https://marginalia.example/@site", Name: "Marginalia",
		Handle: "site", Summary: "A shop selling paper.",
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		Published:    at(),
	}
}

func note() activitypub.Note {
	return activitypub.Note{
		ID: "https://marginalia.example/about", Actor: actor().ID,
		Content: "<p>Founded 2019.</p>", URL: "https://marginalia.example/about",
		Published: at(), ContentHash: strings.Repeat("a", 64),
		PublishedRef: strings.Repeat("c", 64),
	}
}

// The property no other fediverse server can offer.
//
// Every ActivityPub id is a URL, which is a mutable pointer at mutable bytes —
// which is why "edited after it federated" is unsolved across the network. A
// digest of the published bytes makes the claim falsifiable: a reader fetches
// the content and checks, rather than trusting the origin.
func TestAFederatedNoteCarriesTheHashOfWhatWasPublished(t *testing.T) {
	doc := note().Document()

	got, ok := doc["contentHash"].(string)
	if !ok {
		t.Fatalf("no contentHash on the note; the fields are %v",
			activitypub.SortedKeys(doc))
	}
	if !strings.HasPrefix(got, "sha256:") {
		t.Errorf("contentHash is %q and does not name its algorithm — a bare "+
			"hex string is not checkable without guessing", got)
	}
	if !strings.HasSuffix(got, strings.Repeat("a", 64)) {
		t.Errorf("contentHash is %q, not the hash it was given", got)
	}

	// And the commit, so a reader can ask for exactly that version rather than
	// "the current one", which is a different thing once anybody edits.
	if doc["publishedRef"] != strings.Repeat("c", 64) {
		t.Errorf("publishedRef is %v", doc["publishedRef"])
	}
}

// The digest is over what a reader receives. A hash of something nobody can
// fetch is a hash nobody can check.
func TestTheDigestIsOverTheRenderedBytes(t *testing.T) {
	a := activitypub.Digest([]byte("<p>Founded 2019.</p>"))
	b := activitypub.Digest([]byte("<p>Founded 2020.</p>"))
	if a == b {
		t.Fatal("two different renderings produced one digest")
	}
	if len(a) != 64 {
		t.Errorf("the digest is %d characters, want a 64-character sha256", len(a))
	}
	if again := activitypub.Digest([]byte("<p>Founded 2019.</p>")); again != a {
		t.Error("the digest is not stable for the same bytes")
	}
}

// Without publicKey a remote server fetches the actor and then refuses to
// verify anything it signs, which looks like the site being silently ignored.
func TestTheActorCarriesAKeyRemoteServersCanFind(t *testing.T) {
	doc := actor().Document("https://x/inbox", "https://x/outbox", "https://x/followers")

	key, ok := doc["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("the actor has no publicKey; fields are %v",
			activitypub.SortedKeys(doc))
	}
	if key["id"] != actor().KeyID() {
		t.Errorf("the key id is %v, want %s", key["id"], actor().KeyID())
	}
	if key["owner"] != actor().ID {
		t.Errorf("the key owner is %v", key["owner"])
	}
	if !strings.Contains(key["publicKeyPem"].(string), "BEGIN PUBLIC KEY") {
		t.Error("the key is not PEM")
	}

	// The convention every implementation relies on: strip the fragment from a
	// keyId and you have the actor to fetch.
	if base, _, _ := strings.Cut(actor().KeyID(), "#"); base != actor().ID {
		t.Errorf("the key id does not resolve to the actor by dropping its "+
			"fragment: %s", actor().KeyID())
	}
}

// A website publishing automatically is a Service. Claiming to be a Person
// would be a small lie told to every reader for a nicer profile card.
func TestTheActorIsAServiceNotAPerson(t *testing.T) {
	doc := actor().Document("https://x/inbox", "https://x/outbox", "https://x/followers")
	if doc["type"] != "Service" {
		t.Errorf("the actor is a %v", doc["type"])
	}
}

// Without WebFinger a client cannot find the account by name at all: the
// search box takes an address and this is the only thing that maps one to a
// URL.
func TestWebFingerResolvesTheAddressAndOnlyThatAddress(t *testing.T) {
	doc, err := activitypub.WebFinger("acct:site@marginalia.example", actor())
	if err != nil {
		t.Fatalf("the site's own address did not resolve: %v", err)
	}
	if doc["subject"] != "acct:site@marginalia.example" {
		t.Errorf("subject is %v", doc["subject"])
	}

	links, _ := doc["links"].([]any)
	var found bool
	for _, l := range links {
		m, _ := l.(map[string]any)
		if m["rel"] == "self" && m["type"] == "application/activity+json" {
			if m["href"] != actor().ID {
				t.Errorf("the self link points at %v", m["href"])
			}
			found = true
		}
	}
	if !found {
		t.Error("there is no self link, so a client finds no actor")
	}

	// Somebody else's address must not resolve here.
	for _, other := range []string{
		"acct:someone@elsewhere.example",
		"acct:other@marginalia.example",
		"",
	} {
		if _, err := activitypub.WebFinger(other, actor()); err == nil {
			t.Errorf("this server answered for %q", other)
		}
	}
}

// An edit federates as Update. A second Create for an id a server already
// holds is ignored or shown as a duplicate, and neither tells a reader the
// page changed.
func TestAnEditFederatesAsUpdateNotASecondCreate(t *testing.T) {
	create := note().Create()
	update := note().Update()

	if create["type"] != "Create" || update["type"] != "Update" {
		t.Fatalf("types are %v and %v", create["type"], update["type"])
	}
	if create["id"] == update["id"] {
		t.Error("the Create and the Update share an id, so a remote server " +
			"cannot tell them apart")
	}

	// The activity's id differs from the object's, because several
	// implementations key on it and storing both under one id loses one.
	obj, _ := create["object"].(map[string]any)
	if create["id"] == obj["id"] {
		t.Error("the activity and its object share an id")
	}
}

// @context belongs on the outermost object only. Repeating it inside makes
// every payload larger for no gain.
func TestTheNestedObjectDropsTheContext(t *testing.T) {
	obj, _ := note().Create()["object"].(map[string]any)
	if _, there := obj["@context"]; there {
		t.Error("the nested object repeats @context")
	}
	if obj["id"] == "" {
		t.Error("the nested object lost its id along with the context")
	}
}

// Public, or nobody sees it. The magic collection every implementation checks.
func TestPostsAreAddressedToThePublicCollection(t *testing.T) {
	const public = "https://www.w3.org/ns/activitystreams#Public"
	for name, doc := range map[string]map[string]any{
		"note": note().Document(), "create": note().Create(),
	} {
		to, _ := doc["to"].([]string)
		if len(to) == 0 || to[0] != public {
			t.Errorf("%s is addressed to %v, not the public collection", name, to)
		}
	}
}

// Content negotiation is what lets one URL be both a page and a federated
// object, which is what makes a pasted link resolve in a fediverse client.
func TestActivityPubIsRecognisedByAcceptHeader(t *testing.T) {
	for _, yes := range []string{
		"application/activity+json",
		`application/ld+json; profile="https://www.w3.org/ns/activitystreams"`,
		"text/html, application/activity+json",
	} {
		if !activitypub.Accepts(yes) {
			t.Errorf("%q was not recognised as an ActivityPub request", yes)
		}
	}
	for _, no := range []string{
		"text/html", "application/json", "*/*", "",
	} {
		if activitypub.Accepts(no) {
			t.Errorf("%q was treated as an ActivityPub request; a browser "+
				"would be served JSON instead of the page", no)
		}
	}
}

func TestTheDocumentIsValidJSON(t *testing.T) {
	for name, doc := range map[string]map[string]any{
		"actor":  actor().Document("https://x/i", "https://x/o", "https://x/f"),
		"note":   note().Document(),
		"create": note().Create(),
	} {
		body, err := activitypub.Marshal(doc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var back map[string]any
		if err := json.Unmarshal(body, &back); err != nil {
			t.Errorf("%s does not round trip through JSON: %v", name, err)
		}
	}
}
