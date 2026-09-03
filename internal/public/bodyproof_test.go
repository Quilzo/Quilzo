package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/httpsig"
)

// The hole this closed, kept as the test that found it.
//
// A signature covering only the request line says a known actor sent *a* POST
// to this address. It says nothing about the bytes. So capturing one
// legitimate Follow let somebody send any activity as that actor — an Undo
// removing another follower, a Delete — by putting the captured signature
// headers on a different body.
//
// This returned 202 before the body digest was required. It is kept rather
// than deleted because the shape is easy to reintroduce: any change making the
// digest optional, or dropping the check on what the signature covered, opens
// it again.
func TestASignatureFromOneBodyIsNotAcceptedOnAnother(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)

	// A legitimate Follow, signed correctly by the remote actor.
	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	httpsig.SetContentDigest(r, []byte(followBody))
	if err := httpsig.Sign(r, "https://r.example/users/dana#main-key",
		httpsig.RSAPKCS1SHA256, signer,
		[]string{"@method", "@authority", "@path"}, now); err != nil {
		t.Fatal(err)
	}

	// The same signature headers on a completely different body: an Undo that
	// removes a follow.
	evil := `{"id":"https://r.example/9","type":"Undo",` +
		`"actor":"https://r.example/users/dana",` +
		`"object":{"id":"https://r.example/1","type":"Follow"}}`
	attack := httptest.NewRequest("POST", "/@/inbox", stringReader(evil))
	attack.Host = "marginalia.example"
	attack.Header.Set("Signature-Input", r.Header.Get("Signature-Input"))
	attack.Header.Set("Signature", r.Header.Get("Signature"))
	attack.Header.Set("Content-Digest", r.Header.Get("Content-Digest"))

	rec := httptest.NewRecorder()
	st.inbox(rec, attack)
	if rec.Code < 400 {
		t.Fatalf("a signature made over one body was accepted on another "+
			"(status %d).\n"+
			"  Anybody who captures one activity from a legitimate actor can "+
			"then send\n  any activity as them.", rec.Code)
	}
	if st.Federation.Followers.Len() != 0 {
		t.Error("the replayed activity changed the follower list")
	}
}

// The same request, correctly signed with the body covered, is accepted — or
// the test above passes because nothing works at all.
func TestASignatureCoveringTheBodyIsAccepted(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	httpsig.SetContentDigest(r, []byte(followBody))
	if err := httpsig.Sign(r, "https://r.example/users/dana#main-key",
		httpsig.RSAPKCS1SHA256, signer,
		[]string{"@method", "@authority", "@path", "content-digest"},
		now); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("a properly signed Follow was refused with %d: %s",
			rec.Code, rec.Body.String())
	}
	if st.Federation.Followers.Len() != 1 {
		t.Errorf("%d followers after a valid Follow",
			st.Federation.Followers.Len())
	}
}

// A digest that matches but was not signed is one the attacker computed for
// their own body. Both halves are required, and this is the half that looks
// redundant until it is not.
func TestAnUnsignedDigestIsNotEnough(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	// Signed without naming the digest...
	if err := httpsig.Sign(r, "https://r.example/users/dana#main-key",
		httpsig.RSAPKCS1SHA256, signer,
		[]string{"@method", "@authority", "@path"}, now); err != nil {
		t.Fatal(err)
	}
	// ...and a correct digest added afterwards.
	httpsig.SetContentDigest(r, []byte(followBody))

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code == http.StatusAccepted {
		t.Fatal("a correct but unsigned digest was accepted as proof of the " +
			"body; an attacker computes their own")
	}
}

// A signed digest that does not match the body that arrived.
func TestASignedDigestMustMatchTheBody(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)

	other := `{"id":"https://r.example/2","type":"Follow",` +
		`"actor":"https://r.example/users/dana",` +
		`"object":"https://marginalia.example/@"}`

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	// A digest of a different body, then signed — so the signature is honest
	// about a digest that is wrong for what arrived.
	httpsig.SetContentDigest(r, []byte(other))
	if err := httpsig.Sign(r, "https://r.example/users/dana#main-key",
		httpsig.RSAPKCS1SHA256, signer,
		[]string{"@method", "@authority", "@path", "content-digest"},
		now); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code == http.StatusAccepted {
		t.Fatal("a signed digest that does not match the body was accepted")
	}
}

// The older spelling, because the fediverse is mid-migration and a server
// sending only Digest is not doing anything wrong.
func TestTheLegacyDigestHeaderIsAlsoAccepted(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	httpsig.SetContentDigest(r, []byte(followBody))
	r.Header.Del("Content-Digest")
	if err := httpsig.Sign(r, "https://r.example/users/dana#main-key",
		httpsig.RSAPKCS1SHA256, signer,
		[]string{"@method", "@authority", "@path", "digest"}, now); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("a request using the older Digest header was refused with "+
			"%d: %s", rec.Code, rec.Body.String())
	}
}

// A signature has to say which server it was for.
//
// The mirror image of the body-binding bug above, and it shipped alongside it.
// A signature covering only the body digest says this actor produced these
// bytes and nothing about where they were going — so whoever receives one
// legitimate delivery can forward it verbatim to any other inbox, where it
// verifies as an instruction from the original sender. A malicious server
// handed a Follow could replay it, or an Undo, or a Delete, across the
// fediverse as somebody else.
//
// This inbox accepted exactly that: a Follow signed over content-digest alone
// answered 202. The deliverer in this package has always signed @method,
// @authority and @path — the requirement is now the same in both directions,
// and it is what Mastodon signs.
func TestASignatureThatNamesNoDestinationIsRefused(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	httpsig.SetContentDigest(r, []byte(followBody))
	if err := httpsig.Sign(r, "https://r.example/users/dana#main-key",
		httpsig.RSAPKCS1SHA256, signer,
		[]string{"content-digest"}, now); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code == http.StatusAccepted {
		t.Fatal("an activity whose signature binds no destination was " +
			"accepted, so those exact bytes replay at every other inbox as " +
			"this actor")
	}
	if !strings.Contains(rec.Body.String(), "request line") {
		t.Errorf("the refusal does not say what is missing: %s", rec.Body.String())
	}
}

// And @target-uri is accepted instead of authority and path, because it
// contains both and is what some implementations sign.
func TestATargetURISignatureIsAccepted(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	httpsig.SetContentDigest(r, []byte(followBody))
	if err := httpsig.Sign(r, "https://r.example/users/dana#main-key",
		httpsig.RSAPKCS1SHA256, signer,
		[]string{"@method", "@target-uri", "content-digest"}, now); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("a signature over @method and @target-uri was refused with "+
			"%d: %s", rec.Code, rec.Body.String())
	}
}
