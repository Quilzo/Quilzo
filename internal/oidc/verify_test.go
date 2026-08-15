package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

type oneKey struct{ k crypto.PublicKey }

func (o oneKey) Key(kid string) (crypto.PublicKey, error) { return o.k, nil }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type signer struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{rsaKey: r, ecKey: e}
}

// sign builds a token with whatever header and claims the caller wants, so a
// test can produce the malformed ones a real attacker would.
func (s *signer) sign(t *testing.T, alg string, h map[string]any, claims map[string]any) string {
	t.Helper()
	if h == nil {
		h = map[string]any{}
	}
	h["alg"] = alg
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	input := b64(hb) + "." + b64(cb)

	digest := sha256.Sum256([]byte(input))
	var sig []byte
	var err error
	switch alg {
	case "RS256":
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.rsaKey, crypto.SHA256, digest[:])
	case "PS256":
		sig, err = rsa.SignPSS(rand.Reader, s.rsaKey, crypto.SHA256, digest[:],
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case "ES256":
		var r, ss *big.Int
		r, ss, err = ecdsa.Sign(rand.Reader, s.ecKey, digest[:])
		if err == nil {
			sig = append(pad(r, 32), pad(ss, 32)...)
		}
	case "none":
		sig = nil
	case "HS256":
		// The forgery: HMAC the signing input with the RSA public modulus,
		// which is what a verifier that trusts the header's alg would check.
		mac := hmac.New(sha256.New, s.rsaKey.PublicKey.N.Bytes())
		mac.Write([]byte(input))
		sig = mac.Sum(nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func pad(v *big.Int, n int) []byte {
	b := v.Bytes()
	if len(b) >= n {
		return b
	}
	return append(make([]byte, n-len(b)), b...)
}

func goodClaims() map[string]any {
	return map[string]any{
		"iss": "https://idp.example", "sub": "user-1",
		"aud": "scrivet-client", "nonce": "the-nonce",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"email": "dana@example.com", "email_verified": true,
	}
}

func verifier(s *signer, algs ...Algorithm) *Verifier {
	if len(algs) == 0 {
		algs = []Algorithm{RS256}
	}
	var key crypto.PublicKey = &s.rsaKey.PublicKey
	for _, a := range algs {
		if a == ES256 {
			key = &s.ecKey.PublicKey
		}
	}
	return &Verifier{
		Issuer: "https://idp.example", ClientID: "scrivet-client",
		Algorithms: algs, Keys: oneKey{key},
		Now: func() time.Time { return now },
	}
}

func TestAValidTokenVerifies(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, "RS256", nil, goodClaims())

	c, err := verifier(s).Verify(tok, "the-nonce")
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user-1" || c.Email != "dana@example.com" {
		t.Errorf("claims not read: %#v", c)
	}
}

func TestES256AndPS256Verify(t *testing.T) {
	s := newSigner(t)
	for _, alg := range []Algorithm{ES256, PS256} {
		tok := s.sign(t, string(alg), nil, goodClaims())
		if _, err := verifier(s, alg).Verify(tok, "the-nonce"); err != nil {
			t.Errorf("%s: %v", alg, err)
		}
	}
}

// -- the two forgeries that define JWT security ------------------------------

// The token says it is unsigned and a naive verifier agrees.
func TestAlgNoneIsRefused(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, "none", nil, goodClaims())

	_, err := verifier(s).Verify(tok, "the-nonce")
	if err == nil {
		t.Fatal("an unsigned token was accepted")
	}
	if !strings.Contains(err.Error(), "not an instruction") {
		t.Errorf("refused, but the message does not explain why: %v", err)
	}
}

// The classic: the token claims a symmetric algorithm, and a verifier that
// hands the RSA public key to HMAC will validate it. The public key is public,
// so anybody can forge.
func TestASymmetricAlgorithmIsRefusedEvenWithAValidHMAC(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, "HS256", nil, goodClaims())

	// The HMAC in this token is genuinely correct for the public modulus. The
	// only thing standing between it and acceptance is that HS256 is not on the
	// agreed list — which is why the list must never come from the token.
	if _, err := verifier(s).Verify(tok, "the-nonce"); err == nil {
		t.Fatal("a token signed with the public key as an HMAC secret was accepted")
	}
}

// An algorithm this package implements, but which the provider does not
// advertise, is still refused — the list is an intersection, not a superset.
func TestAnAlgorithmOutsideTheAgreedListIsRefused(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, "RS256", nil, goodClaims())

	v := verifier(s, ES256) // provider advertises only ES256
	if _, err := v.Verify(tok, "the-nonce"); err == nil {
		t.Fatal("an unadvertised algorithm was accepted")
	}
}

func TestAVerifierWithNoAgreedAlgorithmsRefusesEverything(t *testing.T) {
	s := newSigner(t)
	v := verifier(s)
	v.Algorithms = nil
	if _, err := v.Verify(s.sign(t, "RS256", nil, goodClaims()), "the-nonce"); err == nil {
		t.Fatal("a verifier with no algorithms accepted a token")
	}
}

// -- the signature covers what is read ---------------------------------------

// The SAML lesson in a different format: if verification and extraction see
// different bytes, the signature proves nothing about what was read.
func TestAlteringThePayloadInvalidatesTheSignature(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, "RS256", nil, goodClaims())
	parts := strings.Split(tok, ".")

	// Swap the subject for somebody else's, keeping everything else.
	evil := goodClaims()
	evil["sub"] = "admin"
	eb, _ := json.Marshal(evil)
	forged := parts[0] + "." + b64(eb) + "." + parts[2]

	if _, err := verifier(s).Verify(forged, "the-nonce"); err == nil {
		t.Fatal("a token with a rewritten subject verified")
	}
}

func TestAlteringTheHeaderInvalidatesTheSignature(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, "RS256", nil, goodClaims())
	parts := strings.Split(tok, ".")

	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "other"})
	forged := b64(hb) + "." + parts[1] + "." + parts[2]

	if _, err := verifier(s).Verify(forged, "the-nonce"); err == nil {
		t.Fatal("a token with a rewritten header verified")
	}
}

// -- claim checks ------------------------------------------------------------

// Requesting a nonce and not checking it comes back is the same as not sending
// one, and it is the most commonly skipped step in every guide.
func TestTheNonceMustMatch(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, "RS256", nil, goodClaims())

	if _, err := verifier(s).Verify(tok, "a-different-nonce"); err == nil {
		t.Fatal("a token from another sign-in was accepted")
	}
	if _, err := verifier(s).Verify(tok, ""); err == nil {
		t.Fatal("verification with no nonce succeeded, which makes the " +
			"parameter decorative")
	}
}

// Prefix matching, case folding or forgiving a trailing slash is how a token
// from a provider you do not trust reaches one you do.
func TestTheIssuerMustMatchExactly(t *testing.T) {
	s := newSigner(t)
	for _, iss := range []string{
		"https://idp.example/", "https://IDP.example", "http://idp.example",
		"https://idp.example.evil.test", "https://idp.example/../x",
	} {
		claims := goodClaims()
		claims["iss"] = iss
		if _, err := verifier(s).Verify(s.sign(t, "RS256", nil, claims),
			"the-nonce"); err == nil {
			t.Errorf("issuer %q was accepted", iss)
		}
	}
}

func TestTheAudienceMustIncludeThisClient(t *testing.T) {
	s := newSigner(t)
	claims := goodClaims()
	claims["aud"] = "somebody-else"
	if _, err := verifier(s).Verify(s.sign(t, "RS256", nil, claims),
		"the-nonce"); err == nil {
		t.Fatal("a token for another client was accepted")
	}
}

// A token minted for a different client that merely lists this one as a
// secondary audience must be caught by azp.
func TestMultipleAudiencesNeedAnAuthorizedParty(t *testing.T) {
	s := newSigner(t)

	claims := goodClaims()
	claims["aud"] = []any{"scrivet-client", "another-client"}
	if _, err := verifier(s).Verify(s.sign(t, "RS256", nil, claims),
		"the-nonce"); err == nil {
		t.Fatal("a multi-audience token with no azp was accepted")
	}

	claims["azp"] = "another-client"
	if _, err := verifier(s).Verify(s.sign(t, "RS256", nil, claims),
		"the-nonce"); err == nil {
		t.Fatal("a token minted for another client was accepted because this " +
			"client was listed as a secondary audience")
	}

	claims["azp"] = "scrivet-client"
	if _, err := verifier(s).Verify(s.sign(t, "RS256", nil, claims),
		"the-nonce"); err != nil {
		t.Errorf("a correct multi-audience token was refused: %v", err)
	}
}

func TestExpiryAndFutureIssuanceAreChecked(t *testing.T) {
	s := newSigner(t)

	expired := goodClaims()
	expired["exp"] = now.Add(-time.Hour).Unix()
	if _, err := verifier(s).Verify(s.sign(t, "RS256", nil, expired),
		"the-nonce"); err == nil {
		t.Error("an expired token was accepted")
	}

	future := goodClaims()
	future["iat"] = now.Add(time.Hour).Unix()
	if _, err := verifier(s).Verify(s.sign(t, "RS256", nil, future),
		"the-nonce"); err == nil {
		t.Error("a token issued an hour in the future was accepted")
	}

	noExp := goodClaims()
	delete(noExp, "exp")
	if _, err := verifier(s).Verify(s.sign(t, "RS256", nil, noExp),
		"the-nonce"); err == nil {
		t.Error("a token with no expiry was accepted")
	}
}

// Small clock differences between machines are normal and must not lock people
// out, or the tolerance gets set to something absurd instead.
func TestASmallClockDifferenceIsTolerated(t *testing.T) {
	s := newSigner(t)
	claims := goodClaims()
	claims["exp"] = now.Add(-30 * time.Second).Unix()

	v := verifier(s)
	v.Skew = 2 * time.Minute
	if _, err := v.Verify(s.sign(t, "RS256", nil, claims), "the-nonce"); err != nil {
		t.Errorf("a token thirty seconds past expiry was refused: %v", err)
	}
}

func TestATokenWithNoSubjectIdentifiesNobody(t *testing.T) {
	s := newSigner(t)
	claims := goodClaims()
	delete(claims, "sub")
	if _, err := verifier(s).Verify(s.sign(t, "RS256", nil, claims),
		"the-nonce"); err == nil {
		t.Fatal("a token with no subject was accepted")
	}
}

// -- structural refusals -----------------------------------------------------

// crit means "reject if you do not understand these". Ignoring it is the
// extension mechanism working exactly backwards.
func TestACriticalHeaderThisDoesNotUnderstandIsRefused(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, "RS256", map[string]any{"crit": []string{"exp-policy"}},
		goodClaims())
	if _, err := verifier(s).Verify(tok, "the-nonce"); err == nil {
		t.Fatal("a token with an unknown critical header was accepted")
	}
}

func TestAnEncryptedTokenIsRefused(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, "RS256", map[string]any{"enc": "A256GCM"}, goodClaims())
	if _, err := verifier(s).Verify(tok, "the-nonce"); err == nil {
		t.Fatal("a token marked as encrypted was accepted")
	}

	// Five segments is the JWE shape, and the error should say so rather than
	// complaining about the count.
	_, err := verifier(s).Verify("a.b.c.d.e", "the-nonce")
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("a five-segment token was not recognised as JWE: %v", err)
	}
}

func TestMalformedTokensAreRefusedCleanly(t *testing.T) {
	s := newSigner(t)
	for _, bad := range []string{
		"", "notatoken", "a.b", "a.b.c", "....", "!!!.???.###",
	} {
		if _, err := verifier(s).Verify(bad, "the-nonce"); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// An ECDSA JWS signature is the fixed-width concatenation of r and s, not ASN.1
// DER. The two are easy to confuse and the failure looks like a wrong key.
func TestAnASN1EncodedECDSASignatureIsRefused(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, "ES256", nil, goodClaims())
	parts := strings.Split(tok, ".")

	// A DER signature is longer than 64 bytes and starts with 0x30.
	der := append([]byte{0x30, 0x44}, make([]byte, 68)...)
	forged := parts[0] + "." + parts[1] + "." + b64(der)

	if _, err := verifier(s, ES256).Verify(forged, "the-nonce"); err == nil {
		t.Fatal("a DER-encoded signature was accepted")
	}
}

func TestAKeyOfTheWrongTypeIsRefused(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, "RS256", nil, goodClaims())

	v := verifier(s)
	v.Keys = oneKey{&s.ecKey.PublicKey} // EC key for an RSA algorithm
	if _, err := v.Verify(tok, "the-nonce"); err == nil {
		t.Fatal("an EC key verified an RS256 token")
	}
}
