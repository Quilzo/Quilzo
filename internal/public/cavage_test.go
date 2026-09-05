package public

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The delivery every real fediverse server sends.
//
// Mastodon before June 2025, Pleroma, Akkoma, Misskey and GoToSocial sign with
// draft-cavage: a Signature header and no Signature-Input at all. This inbox
// refused every one of them with "this request carries one half of a
// signature" — a federation feature that could not receive, and an error
// message the sender could do nothing about.
func TestADraftCavageDeliveryIsAccepted(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)

	sum := sha256.Sum256([]byte(followBody))
	digest := "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
	date := now.UTC().Format(http.TimeFormat)

	base := fmt.Sprintf(
		"(request-target): post /@/inbox\nhost: marginalia.example\n"+
			"date: %s\ndigest: %s", date, digest)
	h := sha256.Sum256([]byte(base))
	raw, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	r.Header.Set("Date", date)
	r.Header.Set("Digest", digest)
	r.Header.Set("Signature", fmt.Sprintf(
		`keyId="https://r.example/users/dana#main-key",algorithm="rsa-sha256",`+
			`headers="(request-target) host date digest",signature="%s"`,
		base64.StdEncoding.EncodeToString(raw)))

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code >= 400 {
		t.Fatalf("a draft-cavage delivery was refused (%d): %s\n"+
			"  This is what almost every fediverse server sends, so this "+
			"inbox\n  receives nothing.", rec.Code, rec.Body)
	}
	if st.Federation.Followers.Len() != 1 {
		t.Errorf("the follow was accepted but not recorded: %d followers",
			st.Federation.Followers.Len())
	}
}

// The coverage rules are the same for both formats.
//
// A cavage signature that does not cover the body must be refused exactly as
// an RFC 9421 one is. The component names differ — (request-target) rather
// than @method and @path — and translating them at the parse boundary is what
// keeps there being one policy instead of two, where the older format is the
// weaker one.
func TestACavageSignatureThatSkipsTheBodyIsRefused(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)
	date := now.UTC().Format(http.TimeFormat)

	// No digest in the covered list, so the body is unauthenticated.
	base := fmt.Sprintf(
		"(request-target): post /@/inbox\nhost: marginalia.example\ndate: %s",
		date)
	h := sha256.Sum256([]byte(base))
	raw, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	r.Header.Set("Date", date)
	r.Header.Set("Signature", fmt.Sprintf(
		`keyId="https://r.example/users/dana#main-key",algorithm="rsa-sha256",`+
			`headers="(request-target) host date",signature="%s"`,
		base64.StdEncoding.EncodeToString(raw)))

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code < 400 {
		t.Fatalf("a cavage signature covering no body was accepted (%d).\n"+
			"  Capture one legitimate activity and any other can be sent as "+
			"that actor.", rec.Code)
	}
}

// A signature over a body that is not the body sent.
func TestACavageSignatureFromAnotherBodyIsRefused(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)

	sum := sha256.Sum256([]byte(followBody))
	digest := "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
	date := now.UTC().Format(http.TimeFormat)

	base := fmt.Sprintf(
		"(request-target): post /@/inbox\nhost: marginalia.example\n"+
			"date: %s\ndigest: %s", date, digest)
	h := sha256.Sum256([]byte(base))
	raw, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	// The genuine headers, on a different activity.
	evil := `{"id":"https://r.example/9","type":"Undo",` +
		`"actor":"https://r.example/users/dana",` +
		`"object":{"id":"https://r.example/1","type":"Follow"}}`
	r := httptest.NewRequest("POST", "/@/inbox", stringReader(evil))
	r.Host = "marginalia.example"
	r.Header.Set("Date", date)
	r.Header.Set("Digest", digest)
	r.Header.Set("Signature", fmt.Sprintf(
		`keyId="https://r.example/users/dana#main-key",algorithm="rsa-sha256",`+
			`headers="(request-target) host date digest",signature="%s"`,
		base64.StdEncoding.EncodeToString(raw)))

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code < 400 {
		t.Fatalf("a signature made over one body was accepted on another (%d)",
			rec.Code)
	}
}

// An old delivery is refused. The draft's replay bound is the Date header, and
// it only bounds anything because the date is one of the signed headers.
func TestAStaleCavageDeliveryIsRefused(t *testing.T) {
	signer, doc := remoteFixture(t)
	st := wiredSite(func(string) ([]byte, error) { return doc(nil), nil })
	now := time.Unix(1787000000, 0)

	// Signed with a date a week before the site's clock.
	old := now.Add(-7 * 24 * time.Hour)
	sum := sha256.Sum256([]byte(followBody))
	digest := "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
	date := old.UTC().Format(http.TimeFormat)

	base := fmt.Sprintf(
		"(request-target): post /@/inbox\nhost: marginalia.example\n"+
			"date: %s\ndigest: %s", date, digest)
	h := sha256.Sum256([]byte(base))
	raw, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/@/inbox", stringReader(followBody))
	r.Host = "marginalia.example"
	r.Header.Set("Date", date)
	r.Header.Set("Digest", digest)
	r.Header.Set("Signature", fmt.Sprintf(
		`keyId="https://r.example/users/dana#main-key",algorithm="rsa-sha256",`+
			`headers="(request-target) host date digest",signature="%s"`,
		base64.StdEncoding.EncodeToString(raw)))

	rec := httptest.NewRecorder()
	st.inbox(rec, r)
	if rec.Code < 400 {
		t.Fatalf("a week-old delivery was accepted (%d), so a captured one "+
			"can be replayed indefinitely", rec.Code)
	}
}

// What this site sends has to be what the other end can read.
//
// The two signature formats put incompatible syntax in the same header, so a
// receiver picks by whether Signature-Input is present. Sending RFC 9421 --
// which this did -- means every implementation that verifies only the draft
// sees a Signature header it cannot parse, and the delivery fails as a bad
// signature rather than as an unsupported format.
func TestWhatThisSiteSendsIsTheFormatTheFediverseVerifies(t *testing.T) {
	key, _ := fedKey(t)
	var captured *http.Request
	s := &Signer{
		KeyID: "https://marginalia.example/@#main-key", Key: key,
		Now: func() time.Time { return time.Unix(1787000000, 0) },
		Post: func(r *http.Request) (int, error) {
			captured = r
			return 202, nil
		},
	}
	activity := map[string]any{
		"id": "https://marginalia.example/1", "type": "Accept",
		"actor": "https://marginalia.example/@",
	}
	if err := s.Send("https://r.example/inbox", activity); err != nil {
		t.Fatal(err)
	}

	if captured.Header.Get("Signature-Input") != "" {
		t.Error("the delivery carries Signature-Input, so a receiver reads it " +
			"as RFC 9421 and every draft-only implementation refuses it")
	}
	sig := captured.Header.Get("Signature")
	for _, want := range []string{"keyId=", "algorithm=", "headers=", "signature="} {
		if !strings.Contains(sig, want) {
			t.Errorf("the Signature header has no %s: %s", want, sig)
		}
	}
	// The draft's replay bound, and the thing that makes it one.
	if captured.Header.Get("Date") == "" {
		t.Error("the delivery carries no Date header, so nothing bounds a replay")
	}
	if !strings.Contains(sig, "date") {
		t.Error("the signature does not cover the date, so the replay bound " +
			"is a header anybody can rewrite")
	}
	if captured.Header.Get("Digest") == "" {
		t.Error("the delivery carries no Digest header, which the draft uses " +
			"rather than Content-Digest")
	}
}
