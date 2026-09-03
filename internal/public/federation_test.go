package public

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/activitypub"
	"github.com/quilzo/quilzo/internal/httpsig"
)

func fedKey(t *testing.T) (crypto.Signer, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: der,
	}))
}

// The loop that has to close, and the one a live server cannot prove.
//
// This site signs an outbound request; a remote server fetches this site's
// actor, reads the key out of it, and verifies. If those two halves disagree
// the site is silently unfollowable from every server running authorized
// fetch, and the only symptom is follows that never complete.
//
// mastodon.social answers this request with a 503 from its edge, which says
// nothing either way — so the loop is closed here, against the published
// document rather than against somebody's rate limiter.
func TestWhatThisSiteSignsVerifiesAgainstTheKeyItPublishes(t *testing.T) {
	signer, publicPEM := fedKey(t)

	actor := activitypub.Actor{
		ID: "https://marginalia.example/@", Handle: "marginalia",
		Name: "Marginalia", PublicKeyPEM: publicPEM,
		Published: time.Unix(1787000000, 0),
	}

	// What a remote server would fetch and read.
	doc := actor.Document(actor.ID+"/inbox", actor.ID+"/outbox",
		actor.ID+"/followers")
	published, _ := doc["publicKey"].(map[string]any)
	keyID, _ := published["id"].(string)
	pemText, _ := published["publicKeyPem"].(string)

	remoteKey, err := httpsig.ParsePEM(keyID, pemText)
	if err != nil {
		t.Fatalf("a remote server could not read the key this site "+
			"publishes: %v", err)
	}

	// What this site sends when it fetches somebody's actor.
	req := httptest.NewRequest("GET", "https://mastodon.example/users/dana", nil)
	now := time.Unix(1787000000, 0)
	if err := httpsig.Sign(req, actor.KeyID(), httpsig.RSAPKCS1SHA256, signer,
		[]string{"@method", "@authority", "@path"}, now); err != nil {
		t.Fatalf("signing the outbound request failed: %v", err)
	}

	got, err := httpsig.Verify(req, []httpsig.PublicKey{remoteKey}, 0, now)
	if err != nil {
		t.Fatalf("what this site signs does not verify against the key it "+
			"publishes: %v\n"+
			"  Every server running authorized fetch would refuse it, and the "+
			"only\n  symptom would be follows that never complete.", err)
	}
	if got == nil {
		t.Fatal("no signature was reported")
	}
	if got.KeyID != actor.KeyID() {
		t.Errorf("the signature names %q and the actor publishes %q",
			got.KeyID, actor.KeyID())
	}
}

// A Follow addressed to somebody else must be refused before any outbound
// request is made.
//
// Verifying means fetching the sender's key from their server, so checking the
// target afterwards would turn a message anybody can send into a request this
// server makes to a host they named — for something it was always going to
// refuse.
func TestAFollowForSomebodyElseCostsNoOutboundRequest(t *testing.T) {
	fetched := 0
	st := &Site{Federation: &Federation{
		Actor:     activitypub.Actor{ID: "https://marginalia.example/@"},
		Followers: activitypub.NewFollowers(),
		Fetch: func(string) ([]byte, error) {
			fetched++
			return nil, nil
		},
		Now: func() time.Time { return time.Unix(1787000000, 0) },
	}}

	body := `{"id":"https://r.example/1","type":"Follow",` +
		`"actor":"https://r.example/users/dana",` +
		`"object":"https://elsewhere.example/@someone"}`
	rec := httptest.NewRecorder()
	st.inbox(rec, httptest.NewRequest("POST", "/@/inbox",
		stringReader(body)))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status is %d, want 400", rec.Code)
	}
	if fetched != 0 {
		t.Errorf("%d outbound request(s) were made for a Follow addressed to "+
			"another server; anybody could use this to make this server "+
			"fetch a URL of their choosing", fetched)
	}
}

// An inbox with no way to verify must refuse rather than accept. An
// unverified activity is an anonymous instruction.
func TestAnInboxThatCannotVerifyRefuses(t *testing.T) {
	st := &Site{Federation: &Federation{
		Actor:     activitypub.Actor{ID: "https://marginalia.example/@"},
		Followers: activitypub.NewFollowers(),
	}}
	body := `{"id":"https://r.example/1","type":"Follow",` +
		`"actor":"https://r.example/users/dana",` +
		`"object":"https://marginalia.example/@"}`

	rec := httptest.NewRecorder()
	st.inbox(rec, httptest.NewRequest("POST", "/@/inbox", stringReader(body)))
	if rec.Code == http.StatusAccepted {
		t.Fatal("an activity was accepted with no way to verify who sent it")
	}
}

// A site that does not federate serves nothing at these routes, rather than an
// empty actor that remote servers would store and keep fetching.
func TestASiteThatDoesNotFederateHasNoActor(t *testing.T) {
	st := &Site{}
	for name, h := range map[string]func(http.ResponseWriter, *http.Request){
		"actor": st.actor, "inbox": st.inbox, "outbox": st.outbox,
		"followers": st.followers, "webfinger": st.webfinger,
	} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest("GET", "/@", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s answered %d on a site that does not federate",
				name, rec.Code)
		}
	}
}

// stringReader is strings.NewReader, and was briefly not.
//
// A hand-rolled reader returned a custom error at the end instead of io.EOF,
// so io.ReadAll failed on every body and the handler answered 400 before it
// did anything. Both tests using it passed — one of them asserting exactly
// that 400 — and would have passed whatever the handler did.
//
// Worth the comment rather than a silent fix: a fixture that makes every path
// return the same answer is a test that proves the fixture.
func stringReader(s string) *strings.Reader { return strings.NewReader(s) }

// remoteFixture is a working remote server: an actor document with a key.
func remoteFixture(t *testing.T) (signer crypto.Signer, actorDoc func(overrides map[string]any) []byte) {
	t.Helper()
	key, pub := fedKey(t)
	return key, func(overrides map[string]any) []byte {
		doc := map[string]any{
			"id":    "https://r.example/users/dana",
			"type":  "Person",
			"inbox": "https://r.example/users/dana/inbox",
			"publicKey": map[string]any{
				"id":           "https://r.example/users/dana#main-key",
				"owner":        "https://r.example/users/dana",
				"publicKeyPem": pub,
			},
		}
		for k, v := range overrides {
			doc[k] = v
		}
		body, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
}

func wiredSite(fetch func(string) ([]byte, error)) *Site {
	return &Site{Federation: &Federation{
		Actor:     activitypub.Actor{ID: "https://marginalia.example/@"},
		Followers: activitypub.NewFollowers(),
		Fetch:     fetch,
		Now:       func() time.Time { return time.Unix(1787000000, 0) },
	}}
}

const followBody = `{"id":"https://r.example/1","type":"Follow",` +
	`"actor":"https://r.example/users/dana",` +
	`"object":"https://marginalia.example/@"}`

// An inbox is a public endpoint anybody can POST to. An unsigned activity is
// an anonymous instruction, and accepting one means anybody can add themselves
// as a follower — or, once Undo is handled, remove somebody else.
func TestAnUnsignedActivityIsRefusedByAWiredInbox(t *testing.T) {
	_, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })

	rec := httptest.NewRecorder()
	st.inbox(rec, httptest.NewRequest("POST", "/@/inbox", stringReader(followBody)))

	if rec.Code == http.StatusAccepted {
		t.Fatal("an unsigned Follow was accepted, so anybody can add " +
			"themselves as a follower")
	}
	if st.Federation.Followers.Len() != 0 {
		t.Error("an unsigned Follow was recorded")
	}
}

// A correctly signed Follow is accepted, or every refusal above proves only
// that the inbox refuses.
func TestASignedFollowIsAcceptedAndRecorded(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	if err := httpsig.Sign(r, "https://r.example/users/dana#main-key",
		httpsig.RSAPKCS1SHA256, signer,
		[]string{"@method", "@authority", "@path"}, now); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("a signed Follow was refused with %d: %s",
			rec.Code, rec.Body.String())
	}
	if st.Federation.Followers.Len() != 1 {
		t.Fatalf("%d followers after a signed Follow", st.Federation.Followers.Len())
	}
	if got := st.Federation.Followers.All()[0].Inbox; got != "https://r.example/users/dana/inbox" {
		t.Errorf("the delivery inbox is %q", got)
	}
}

// A server returning somebody else's actor would have that key used to verify
// signatures attributed to the actor that was asked for.
func TestAServerReturningAnotherActorIsRefused(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) {
		return doc(map[string]any{"id": "https://elsewhere.example/users/mallory"}), nil
	})
	now := time.Unix(1787000000, 0)

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	if err := httpsig.Sign(r, "https://r.example/users/dana#main-key",
		httpsig.RSAPKCS1SHA256, signer,
		[]string{"@method", "@authority", "@path"}, now); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code == http.StatusAccepted {
		t.Fatal("a document claiming to be a different actor was used to " +
			"verify a signature attributed to the one requested")
	}
}

// A key whose owner is somebody else does not speak for this actor. Without
// the check, a server could sign with its own key while claiming to be an
// account on another host.
func TestAKeyOwnedBySomebodyElseIsRefused(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) {
		return doc(map[string]any{"publicKey": map[string]any{
			"id":           "https://r.example/users/dana#main-key",
			"owner":        "https://elsewhere.example/users/mallory",
			"publicKeyPem": mustPEM(t, signer),
		}}), nil
	})
	now := time.Unix(1787000000, 0)

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	if err := httpsig.Sign(r, "https://r.example/users/dana#main-key",
		httpsig.RSAPKCS1SHA256, signer,
		[]string{"@method", "@authority", "@path"}, now); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code == http.StatusAccepted {
		t.Fatal("a key belonging to another account was used to verify this one")
	}
}

func mustPEM(t *testing.T, signer crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
