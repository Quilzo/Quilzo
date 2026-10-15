// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package commerce

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/crawl"
	"github.com/quilzo/quilzo/internal/httpsig"
	"github.com/quilzo/quilzo/internal/listing"
)

// Minting SD-JWTs the way an issuer would, for tests.
//
// The digest arithmetic is written out here from RFC 9901 rather than by
// calling the package's own flatten: a test that minted credentials with the
// function that verifies them proves only that the function agrees with
// itself, and this is the one check between a shop and a mandate that
// authorises spending somebody's money.

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mintSDJWT makes a presentation with the hidden claims in disclosures and
// the visible ones in the payload, the ordinary _sd form.
func mintSDJWT(t *testing.T, priv *ecdsa.PrivateKey, kid, typ string,
	visible, hidden map[string]any) string {

	t.Helper()
	payload := map[string]any{}
	for k, v := range visible {
		payload[k] = v
	}
	if len(hidden) > 0 {
		payload["_sd_alg"] = "sha-256"
	}
	var digests []any
	var disclosures []string
	for k, v := range hidden {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			t.Fatal(err)
		}
		arr, err := json.Marshal([]any{b64u(salt), k, v})
		if err != nil {
			t.Fatal(err)
		}
		d := b64u(arr)
		sum := sha256.Sum256([]byte(d))
		digests = append(digests, b64u(sum[:]))
		disclosures = append(disclosures, d)
	}
	payload["_sd"] = digests
	return strings.Join(append([]string{signJWS(t, priv, kid, typ, payload)}, disclosures...), "~")
}

// mintDelegateSDJWT makes the form AP2's closed mandates use: the claims
// live one level down, behind a "..." pointer in delegate_payload.
func mintDelegateSDJWT(t *testing.T, priv *ecdsa.PrivateKey, kid, typ string,
	claims map[string]any) string {

	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	arr, err := json.Marshal([]any{b64u(salt), claims})
	if err != nil {
		t.Fatal(err)
	}
	d := b64u(arr)
	sum := sha256.Sum256([]byte(d))
	payload := map[string]any{
		"_sd_alg": "sha-256",
		"delegate_payload": []any{map[string]any{
			"...": b64u(sum[:]),
		}},
	}
	return strings.Join([]string{signJWS(t, priv, kid, typ, payload), d}, "~")
}

// signJWS signs a payload as a compact ES256 JWS with raw R||S.
func signJWS(t *testing.T, priv *ecdsa.PrivateKey, kid, typ string,
	payload map[string]any) string {

	t.Helper()
	h, err := json.Marshal(map[string]any{"alg": "ES256", "typ": typ, "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	input := b64u(h) + "." + b64u(p)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	size := (priv.Curve.Params().BitSize + 7) / 8
	sig := append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	return input + "." + b64u(sig)
}

// issuerFor makes an issuer key pair and its configured half.
func issuerFor(t *testing.T, name, kid string) (*ecdsa.PrivateKey, IssuerKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, IssuerKey{Name: name, KeyID: kid, Public: &priv.PublicKey}
}

// The ordinary form: hidden claims reappear, digests verified.
func TestHiddenClaimsAreRevealedByTheirDigests(t *testing.T) {
	priv, _ := issuerFor(t, "issuer", "k1")
	token := mintSDJWT(t, priv, "k1", "example+sd-jwt",
		map[string]any{"iat": float64(time.Now().Unix())},
		map[string]any{"vct": "mandate.payment.1", "payee": map[string]any{"name": "Shop"}})

	parsed, _, err := parseSDJWT(token)
	if err != nil {
		t.Fatalf("a minted SD-JWT did not parse: %v", err)
	}
	if parsed.Payload["vct"] != "mandate.payment.1" {
		t.Errorf("vct is %v", parsed.Payload["vct"])
	}
	payee, _ := parsed.Payload["payee"].(map[string]any)
	if payee["name"] != "Shop" {
		t.Errorf("payee name is %v", payee["name"])
	}
	if _, still := parsed.Payload["_sd"]; still {
		t.Error("the _sd list was left in the flattened claims")
	}
}

// The AP2 form: claims behind a "..." pointer in delegate_payload.
func TestDelegatePayloadClaimsAreResolved(t *testing.T) {
	priv, _ := issuerFor(t, "issuer", "k1")
	token := mintDelegateSDJWT(t, priv, "k1", "example+sd-jwt",
		map[string]any{"vct": "mandate.checkout.1",
			"checkout_hash": "AbCdEf", "exp": float64(time.Now().Add(time.Hour).Unix())})

	// Hoisting happens in the mandate verification, which is where the
	// claims are read; parseSDJWT alone leaves the resolved object where the
	// payload put it.
	parsed, _, err := parseSDJWT(token)
	if err != nil {
		t.Fatalf("a delegate-form SD-JWT did not parse: %v", err)
	}
	dp, ok := parsed.Payload["delegate_payload"].([]any)
	if !ok || len(dp) != 1 {
		t.Fatalf("delegate_payload resolved to %#v", parsed.Payload["delegate_payload"])
	}
	claims, ok := dp[0].(map[string]any)
	if !ok || claims["vct"] != "mandate.checkout.1" {
		t.Fatalf("the delegated claims resolved to %#v", dp[0])
	}
}

// Tampering has two shapes, and each is caught where it lives.
//
// In the _sd form, an altered disclosure no longer matches its digest, so
// the claim simply does not reappear — and a mandate without its vct is
// refused as one that does not say what it authorises. In the pointer form,
// the payload says something belongs where nothing arrived, which is an
// error at the parse.
func TestATamperedSDFormDisclosureMakesTheClaimVanish(t *testing.T) {
	priv, _ := issuerFor(t, "issuer", "k1")
	token := mintSDJWT(t, priv, "k1", "example+sd-jwt",
		nil, map[string]any{"vct": "mandate.payment.1"})
	parts := strings.Split(token, "~")
	tampered := []byte(parts[1])
	if tampered[10] == 'a' {
		tampered[10] = 'b'
	} else {
		tampered[10] = 'a'
	}
	parts[1] = string(tampered)
	if _, _, err := parseSDJWT(strings.Join(parts, "~")); err != nil {
		t.Fatalf("the parse refused a well-formed token: %v", err)
	}
	// The claim vanished, so the mandate level says so.
	if _, err := VerifyPaymentMandate(strings.Join(parts, "~"), "Shop",
		"https://shop.test", 100, "GBP",
		[]IssuerKey{{Name: "issuer", KeyID: "k1", Public: &priv.PublicKey}},
		time.Now()); err == nil ||
		!strings.Contains(err.Error(), "vct") {
		t.Fatalf("a mandate whose claims vanished was accepted: %v", err)
	}
}

func TestATamperedPointerDisclosureIsRefusedAtTheParse(t *testing.T) {
	priv, _ := issuerFor(t, "issuer", "k1")
	token := mintDelegateSDJWT(t, priv, "k1", "example+sd-jwt",
		map[string]any{"vct": "mandate.payment.1"})
	parts := strings.Split(token, "~")
	tampered := []byte(parts[1])
	if tampered[10] == 'a' {
		tampered[10] = 'b'
	} else {
		tampered[10] = 'a'
	}
	parts[1] = string(tampered)
	if _, _, err := parseSDJWT(strings.Join(parts, "~")); err == nil {
		t.Fatal("a tampered pointer disclosure was accepted")
	}
}

// An algorithm the verifier has not agreed to is a refusal, not a choice.
func TestAnotherDigestAlgorithmIsRefused(t *testing.T) {
	priv, _ := issuerFor(t, "issuer", "k1")
	payload := map[string]any{"_sd_alg": "sha-512", "_sd": []any{"AAAA"}}
	token := signJWS(t, priv, "k1", "example+sd-jwt", payload) + "~" + b64u([]byte(`["s","k",1]`))
	if _, _, err := parseSDJWT(token); err == nil ||
		!strings.Contains(err.Error(), "sha-512") {
		t.Fatalf("sha-512 was accepted or refused for the wrong reason: %v", err)
	}
}

// A "..." pointer with no disclosure behind it is a hole the payload says is
// filled, which is an error rather than a silent drop.
func TestAPointerToAnUnpresentedDisclosureIsRefused(t *testing.T) {
	priv, _ := issuerFor(t, "issuer", "k1")
	payload := map[string]any{"delegate_payload": []any{
		map[string]any{"...": "ZHVtbXlk"}}, "_sd_alg": "sha-256"}
	token := signJWS(t, priv, "k1", "example+sd-jwt", payload) + "~" + b64u([]byte(`["s","x",1]`))
	if _, _, err := parseSDJWT(token); err == nil {
		t.Fatal("a pointer to an unpresented disclosure was accepted")
	}
}

// A decoy digest — present in _sd, no disclosure beside it — is dropped
// quietly, because undisclosed claims are the holder's right, not an error.
func TestADecoyDigestIsDropped(t *testing.T) {
	priv, _ := issuerFor(t, "issuer", "k1")
	// One real disclosure so the token is a presentation at all, and a decoy
	// digest in the signed _sd list that nothing matches.
	payload := map[string]any{"_sd": []any{"ZGVjb3lkaWdlc3Q=", "_sd_alg_placeholder"},
		"_sd_alg": "sha-256"}
	token := signJWS(t, priv, "k1", "example+sd-jwt", payload) +
		"~" + b64u([]byte(`["c2FsdA","unused",1]`))
	parsed, _, err := parseSDJWT(token)
	if err != nil {
		t.Fatalf("a decoy digest broke the parse: %v", err)
	}
	if _, there := parsed.Payload["ZGVjb3lkaWdlc3Q="]; there {
		t.Error("the decoy digest was revealed as a claim")
	}
}

// A key-binding JWT appended with a tilde is separated, not swallowed as a
// disclosure, and not verified here.
func TestTheKeyBindingSegmentIsSeparated(t *testing.T) {
	priv, _ := issuerFor(t, "issuer", "k1")
	token := mintDelegateSDJWT(t, priv, "k1", "example+sd-jwt",
		map[string]any{"vct": "mandate.payment.1"})
	kb := signJWS(t, priv, "holder", "kb+jwt", map[string]any{"iat": 1})
	parsed, _, err := parseSDJWT(token + "~" + kb)
	if err != nil {
		t.Fatalf("a key-bound presentation did not parse: %v", err)
	}
	if !parsed.KeyBinding {
		t.Error("the appended key-binding JWT was not noticed")
	}
	dp, ok := parsed.Payload["delegate_payload"].([]any)
	if !ok || len(dp) != 1 {
		t.Fatalf("delegate_payload resolved to %#v", parsed.Payload["delegate_payload"])
	}
	claims, ok := dp[0].(map[string]any)
	if !ok || claims["vct"] != "mandate.payment.1" {
		t.Fatalf("the delegated claims resolved to %#v", dp[0])
	}
}

// agentKey makes a Web Bot Auth key pair the way a shopping agent would
// hold one, with the configured half.
func agentKey(t *testing.T, name, keyID string) (ed25519.PrivateKey, crawl.Key) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv, crawl.Key{Name: name, ID: keyID, Public: pub}
}

// signedAgentRequest signs a request the way a Web Bot Auth agent would:
// RFC 9421 over the destination, and over the body's digest when there is
// one — assembled here from the RFC, not from the verifier's own builder.
func signedAgentRequest(t *testing.T, priv ed25519.PrivateKey, keyID, method, path string,
	body []byte, created time.Time) *http.Request {

	t.Helper()
	var rdr *strings.Reader
	if body == nil {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(string(body))
	}
	r := httptest.NewRequest(method, "http://shop.test"+path, rdr)
	if body != nil {
		httpsig.SetContentDigest(r, body)
	}
	covered := `"@authority"`
	if body != nil {
		covered = `"@authority" "content-digest"`
	}
	params := fmt.Sprintf("(%s);created=%d;keyid=%q;alg=%q",
		covered, created.Unix(), keyID, "ed25519")
	base := fmt.Sprintf(`"@authority": shop.test` + "\n")
	if body != nil {
		base += fmt.Sprintf(`"content-digest": %s`+"\n",
			r.Header.Get("Content-Digest"))
	}
	base += fmt.Sprintf(`"@signature-params": %s`, params)
	sig := ed25519.Sign(priv, []byte(base))
	r.Header.Set("Signature-Input", "sig1="+params)
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return r
}

// shopRows is a catalogue of shaped records for the service tests.
func shopRows() []listing.Row {
	rows := []map[string]any{
		{"slug": "notebook", "name": "Linen Notebook", "summary": "A tall notebook",
			"price": float64(2400), "currency": "GBP", "sku": "NB-1",
			"availability": "in_stock", "image": "/media/" + strings.Repeat("a", 64),
			"alt": "A notebook"},
		{"slug": "pen", "name": "Brass Pen", "summary": "A slim pen",
			"price": float64(4500), "currency": "GBP", "sku": "PN-1",
			"availability": "sold_out"},
		{"slug": "cards", "name": "Correspondence Cards", "summary": "Green cards",
			"price": float64(1200), "currency": "GBP", "sku": "CD-1",
			"availability": "made_to_order"},
	}
	out := make([]listing.Row, 0, len(rows))
	for _, r := range rows {
		out = append(out, listing.Row(r))
	}
	return out
}

// newShop makes a wired service with a real merchant key, an agent and an
// issuer, over the rows above.
func newShop(t *testing.T, dir string) (*Service, ed25519.PrivateKey, crawl.Key, *ecdsa.PrivateKey, IssuerKey) {
	t.Helper()
	merchant, err := GenerateMerchantKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, agent := agentKey(t, "ExampleAgent", "ag1")
	issuerPriv, issuer := issuerFor(t, "ExampleTS", "ts1")
	svc := &Service{
		PayeeName: "Marginalia", PayeeWebsite: "https://shop.test",
		Merchant: merchant, Agents: []crawl.Key{agent},
		Issuers: []IssuerKey{issuer},
		Rows:    func() ([]listing.Row, error) { return shopRows(), nil },
		Now:     func() time.Time { return time.Now().UTC() },
	}
	if dir != "" {
		svc.Path = OrdersPath(dir)
	}
	if err := svc.Init(); err != nil {
		t.Fatal(err)
	}
	return svc, priv, agent, issuerPriv, issuer
}
