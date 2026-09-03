package crawl_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/crawl"
)

func at() time.Time { return time.Unix(1787000000, 0) }

func botKey(t *testing.T) (ed25519.PrivateKey, crawl.Key) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	key, err := crawl.ParseKey("ExampleBot", "bot-key-1",
		base64.StdEncoding.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	return priv, key
}

// signedRequest builds a Web Bot Auth request the way a crawler would.
//
// The signature base is assembled here from the RFC rather than by calling the
// package's own builder. A test that signs with the function it is testing
// proves only that the function agrees with itself, and this is the one check
// between a paying crawler and a free one.
func signedRequest(t *testing.T, priv ed25519.PrivateKey, keyID, purpose string,
	created int64) *http.Request {

	t.Helper()
	r := httptest.NewRequest("GET", "http://example.test/pricing", nil)
	if purpose != "" {
		r.Header.Set("Crawler-Purpose", purpose)
	}

	params := fmt.Sprintf(`("@method" "@authority" "@path");created=%d;keyid="%s";alg="ed25519"`,
		created, keyID)
	base := fmt.Sprintf("\"@method\": %s\n\"@authority\": %s\n\"@path\": %s\n"+
		"\"@signature-params\": %s", r.Method, r.Host, r.URL.EscapedPath(), params)

	sig := ed25519.Sign(priv, []byte(base))
	r.Header.Set("Signature-Input", "sig1="+params)
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return r
}

func terms() crawl.Terms {
	return crawl.Terms{
		Permits:    []string{"search"},
		Prohibits:  []string{"train", "ai-summarize"},
		Price:      "USD 0.005",
		Contact:    "rights@example.test",
		LicenceURL: "https://example.test/license.xml",
	}
}

// The control. Without it every refusal below proves only that Verify refuses.
func TestAGenuinelySignedCrawlerIsIdentified(t *testing.T) {
	priv, key := botKey(t)
	r := signedRequest(t, priv, key.ID, "search", at().Unix())

	id, err := crawl.Verify(r, []crawl.Key{key}, at())
	if err != nil {
		t.Fatalf("a correctly signed request was refused: %v", err)
	}
	if id == nil {
		t.Fatal("a correctly signed request produced no identity")
	}
	if id.Name != "ExampleBot" {
		t.Errorf("identified as %q", id.Name)
	}
	if id.Use != crawl.Search {
		t.Errorf("purpose is %q, want search", id.Use)
	}
}

// The case that decides whether this is safe to deploy at all.
//
// An unsigned request is a person, and a public site serves people. A gate
// that turned readers away on a guess would have broken the thing it protects.
func TestAnUnsignedRequestIsServed(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.test/pricing", nil)
	// Even one that looks exactly like a crawler.
	r.Header.Set("User-Agent", "GPTBot/1.0 (+https://example.com/bot)")

	id, err := crawl.Verify(r, nil, at())
	if err != nil {
		t.Fatalf("an unsigned request produced an error: %v", err)
	}
	if id != nil {
		t.Fatal("an unsigned request was given an identity")
	}
	if d := crawl.Decide(id, terms()); !d.Serve {
		t.Fatalf("an unsigned request was refused with %d — a public site "+
			"cannot turn away readers on a guess", d.Status)
	}
}

// A permitted use is served even though the crawler identified itself.
func TestAPermittedUseIsServed(t *testing.T) {
	priv, key := botKey(t)
	id, err := crawl.Verify(t2(t, priv, key, "search"), []crawl.Key{key}, at())
	if err != nil {
		t.Fatal(err)
	}
	if d := crawl.Decide(id, terms()); !d.Serve {
		t.Fatalf("search is permitted and was refused with %d", d.Status)
	}
}

func t2(t *testing.T, priv ed25519.PrivateKey, key crawl.Key, purpose string) *http.Request {
	return signedRequest(t, priv, key.ID, purpose, at().Unix())
}

// A refused use with a price gets 402 and the header crawlers read.
func TestARefusedUseWithAPriceGets402(t *testing.T) {
	priv, key := botKey(t)
	id, err := crawl.Verify(t2(t, priv, key, "train"), []crawl.Key{key}, at())
	if err != nil {
		t.Fatal(err)
	}

	d := crawl.Decide(id, terms())
	if d.Serve {
		t.Fatal("training is prohibited and was served")
	}
	if d.Status != http.StatusPaymentRequired {
		t.Errorf("status is %d, want 402", d.Status)
	}
	if got := d.Headers["crawler-price"]; got != "USD 0.005" {
		t.Errorf("crawler-price is %q; a price nobody can parse is a price "+
			"nobody pays", got)
	}
	if !strings.Contains(d.Headers["Link"], `rel="license"`) {
		t.Errorf("the refusal does not link the terms: %q", d.Headers["Link"])
	}
	if d.Headers["X-Licence-Contact"] == "" {
		t.Error("a refusal with nowhere to ask is a wall rather than a " +
			"negotiation")
	}
}

// A refused use with no price is a different answer, and is sent as one.
// 402 means "pay this"; there is nothing to pay.
func TestARefusedUseWithNoPriceGets403NotAPriceOfZero(t *testing.T) {
	priv, key := botKey(t)
	id, err := crawl.Verify(t2(t, priv, key, "train"), []crawl.Key{key}, at())
	if err != nil {
		t.Fatal(err)
	}
	free := terms()
	free.Price = ""

	d := crawl.Decide(id, free)
	if d.Status != http.StatusForbidden {
		t.Errorf("status is %d, want 403 — 402 would advertise a price that "+
			"does not exist", d.Status)
	}
	if _, priced := d.Headers["crawler-price"]; priced {
		t.Error("a price header was sent when nothing is for sale")
	}
}

// Silence in the terms is not a refusal. Charging for a use nobody wrote down
// would be charging for something never offered.
func TestAUseTheTermsDoNotMentionIsServed(t *testing.T) {
	priv, key := botKey(t)
	id, err := crawl.Verify(t2(t, priv, key, "ai-summarize"), []crawl.Key{key}, at())
	if err != nil {
		t.Fatal(err)
	}
	quiet := crawl.Terms{Permits: []string{"search"}, Price: "USD 0.005"}

	if d := crawl.Decide(id, quiet); !d.Serve {
		t.Fatalf("a use the terms are silent about was refused with %d", d.Status)
	}
}

// A crawler that identifies itself and says nothing about why is treated as
// the most permissive thing it could be. Guessing "training" from silence
// would charge a search indexer for a use it never asked for.
func TestAnUnstatedPurposeIsNotTreatedAsTraining(t *testing.T) {
	priv, key := botKey(t)
	id, err := crawl.Verify(t2(t, priv, key, ""), []crawl.Key{key}, at())
	if err != nil {
		t.Fatal(err)
	}
	if id.Use != crawl.Unstated {
		t.Fatalf("purpose is %q, want unstated", id.Use)
	}
	if d := crawl.Decide(id, terms()); !d.Serve {
		t.Fatalf("a crawler that stated no purpose was charged as if it had "+
			"stated the most expensive one (%d)", d.Status)
	}
}

// -- the signature itself ----------------------------------------------------

func TestATamperedRequestIsRefused(t *testing.T) {
	priv, key := botKey(t)
	r := signedRequest(t, priv, key.ID, "search", at().Unix())
	r.URL.Path = "/somewhere-else"

	if id, err := crawl.Verify(r, []crawl.Key{key}, at()); err == nil {
		t.Fatalf("a request whose path changed after signing verified: %+v", id)
	}
}

func TestAnotherCrawlersKeyIsRefused(t *testing.T) {
	priv, key := botKey(t)
	other := make([]byte, ed25519.SeedSize)
	for i := range other {
		other[i] = byte(200 - i)
	}
	otherKey, err := crawl.ParseKey("OtherBot", key.ID,
		base64.StdEncoding.EncodeToString(
			ed25519.NewKeyFromSeed(other).Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := crawl.Verify(signedRequest(t, priv, key.ID, "search", at().Unix()),
		[]crawl.Key{otherKey}, at()); err == nil {
		t.Fatal("a signature verified against a different crawler's key")
	}
}

func TestAnUnknownKeyIDIsRefused(t *testing.T) {
	priv, key := botKey(t)
	r := signedRequest(t, priv, "some-other-key", "search", at().Unix())
	if _, err := crawl.Verify(r, []crawl.Key{key}, at()); err == nil {
		t.Fatal("a signature naming an unconfigured key verified")
	}
}

// A signature over unchanging components authenticates forever without an age
// check, so a request captured from a log replays indefinitely.
func TestAnOldSignatureIsRefused(t *testing.T) {
	priv, key := botKey(t)
	old := at().Add(-10 * time.Minute).Unix()
	if _, err := crawl.Verify(signedRequest(t, priv, key.ID, "search", old),
		[]crawl.Key{key}, at()); err == nil {
		t.Fatal("a ten-minute-old signature verified")
	}
	recent := at().Add(-4 * time.Minute).Unix()
	if _, err := crawl.Verify(signedRequest(t, priv, key.ID, "search", recent),
		[]crawl.Key{key}, at()); err != nil {
		t.Errorf("a four-minute-old signature was refused: %v", err)
	}
}

// The created time is inside the signed parameters, so re-dating a capture
// must break it.
func TestTheCreatedTimeCannotBeMovedToDefeatTheAgeCheck(t *testing.T) {
	priv, key := botKey(t)
	old := at().Add(-10 * time.Minute).Unix()
	r := signedRequest(t, priv, key.ID, "search", old)
	r.Header.Set("Signature-Input",
		strings.Replace(r.Header.Get("Signature-Input"),
			fmt.Sprintf("created=%d", old),
			fmt.Sprintf("created=%d", at().Unix()), 1))

	if _, err := crawl.Verify(r, []crawl.Key{key}, at()); err == nil {
		t.Fatal("re-dating a captured signature let it through")
	}
}

// A component the verifier does not understand must be refused, never skipped.
// Verifying over fewer components than were signed and calling it valid is a
// forgery the verifier performs on itself.
func TestAnUnknownCoveredComponentIsRefusedNotSkipped(t *testing.T) {
	priv, key := botKey(t)
	r := signedRequest(t, priv, key.ID, "search", at().Unix())
	r.Header.Set("Signature-Input", strings.Replace(
		r.Header.Get("Signature-Input"), `"@path"`, `"@path" "@invented"`, 1))

	_, err := crawl.Verify(r, []crawl.Key{key}, at())
	if err == nil {
		t.Fatal("a signature covering an unknown component verified")
	}
	if !strings.Contains(err.Error(), "@invented") {
		t.Errorf("the error does not name the component: %v", err)
	}
}

// Half a proof is not a weaker proof.
func TestHalfASignatureIsRefused(t *testing.T) {
	priv, key := botKey(t)
	for _, drop := range []string{"Signature", "Signature-Input"} {
		r := signedRequest(t, priv, key.ID, "search", at().Unix())
		r.Header.Del(drop)
		if _, err := crawl.Verify(r, []crawl.Key{key}, at()); err == nil {
			t.Errorf("a request with no %s verified", drop)
		}
	}
}

// A signed request with no keys configured cannot be checked, and an
// unverifiable signature is not an identity.
func TestASignedRequestWithNoKeysConfiguredIsAnError(t *testing.T) {
	priv, key := botKey(t)
	r := signedRequest(t, priv, key.ID, "search", at().Unix())
	if id, err := crawl.Verify(r, nil, at()); err == nil {
		t.Fatalf("a signature verified with nothing to check it against: %+v", id)
	}
}

// -- what the crawler offered ------------------------------------------------

func TestAnOfferIsReadAndCompared(t *testing.T) {
	h := http.Header{}
	h.Set("crawler-max-price", "USD 0.01")
	if ok, why := crawl.Affordable("USD 0.005", h); !ok {
		t.Errorf("an offer above the price was refused: %s", why)
	}

	h.Set("crawler-max-price", "USD 0.001")
	if ok, _ := crawl.Affordable("USD 0.005", h); ok {
		t.Error("an offer below the price was accepted")
	}
}

// Converting currencies would mean holding a rate, and a rate wrong by a day
// is a price wrong by a day.
func TestADifferentCurrencyIsRefusedRatherThanConverted(t *testing.T) {
	h := http.Header{}
	h.Set("crawler-max-price", "EUR 10.00")
	ok, why := crawl.Affordable("USD 0.005", h)
	if ok {
		t.Fatal("an offer in another currency was accepted")
	}
	if !strings.Contains(why, "convert") {
		t.Errorf("the reason does not say why: %q", why)
	}
}

func TestAnUnreadableOfferIsNotTreatedAsGenerous(t *testing.T) {
	for _, bad := range []string{"", "free", "USD", "0.01", "USD -1", "USD abc"} {
		h := http.Header{}
		h.Set("crawler-max-price", bad)
		if ok, _ := crawl.Affordable("USD 0.005", h); ok {
			t.Errorf("offer %q was accepted", bad)
		}
	}
}
