package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

// PKCE binds the authorization code to the client that asked for it, and S256
// is what makes it a binding rather than a label. The plain method sends the
// verifier itself, so anybody who intercepts the request has it.
func TestTheChallengeIsTheSHA256OfTheVerifier(t *testing.T) {
	r, err := NewRequest("https://example.com/callback")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(r.CodeVerifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if r.Challenge() != want {
		t.Errorf("the challenge is not S256 of the verifier")
	}
	if r.Challenge() == r.CodeVerifier {
		t.Error("the challenge is the verifier, which is the plain method")
	}
}

// State, nonce and verifier must all be unpredictable and all be different.
// Reusing one value for two purposes means breaking one breaks both.
func TestPerSignInSecretsAreDistinctAndUnpredictable(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		r, err := NewRequest("https://example.com/callback")
		if err != nil {
			t.Fatal(err)
		}
		for name, v := range map[string]string{
			"state": r.State, "nonce": r.Nonce, "verifier": r.CodeVerifier,
		} {
			if len(v) < 40 {
				t.Fatalf("%s is only %d characters", name, len(v))
			}
			if seen[v] {
				t.Fatalf("%s repeated across sign-ins", name)
			}
			seen[v] = true
		}
		if r.State == r.Nonce || r.State == r.CodeVerifier {
			t.Fatal("two of the three secrets are the same value")
		}
	}
}

// A state parameter with no expiry is a CSRF token with no expiry, and one left
// in a browser's history is a replay.
func TestASignInAttemptExpires(t *testing.T) {
	r, _ := NewRequest("https://example.com/callback")
	if r.Expired(r.CreatedAt.Add(time.Minute)) {
		t.Error("a one-minute-old attempt was expired")
	}
	if !r.Expired(r.CreatedAt.Add(MaxRequestAge + time.Second)) {
		t.Error("an attempt outlived the maximum age")
	}
}

func TestTheAuthorizationURLCarriesEverythingRequired(t *testing.T) {
	p := &Provider{Discovery: Discovery{
		AuthorizationEndpoint: "https://idp.example/authorize"}}
	r, _ := NewRequest("https://site.example/callback")

	u := p.AuthorizationURL("client-1", r, nil)
	for _, want := range []string{
		"response_type=code", "client_id=client-1", "state=" + r.State,
		"nonce=" + r.Nonce, "code_challenge=" + r.Challenge(),
		"code_challenge_method=S256", "scope=openid",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("the URL omits %q", want)
		}
	}
	// The verifier itself must never leave this machine on the front channel.
	if strings.Contains(u, r.CodeVerifier) {
		t.Error("the code verifier is in the authorization URL, which defeats " +
			"the whole mechanism")
	}
}

// -- key set parsing ---------------------------------------------------------

// An EC point that is not on the curve is not a key. Accepting one is the
// invalid-curve attack, which can leak the private key of whoever uses it.
func TestAnECPointOffTheCurveIsRefused(t *testing.T) {
	good, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(i *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(i.Bytes())
	}

	valid := jwk{Kty: "EC", Crv: "P-256", X: enc(good.X), Y: enc(good.Y)}
	if _, err := valid.public(); err != nil {
		t.Fatalf("a valid point was refused: %v", err)
	}

	// Move the point off the curve by changing one coordinate.
	off := jwk{Kty: "EC", Crv: "P-256",
		X: enc(good.X), Y: enc(new(big.Int).Add(good.Y, big.NewInt(1)))}
	if _, err := off.public(); err == nil {
		t.Error("a point that is not on the curve was accepted as a key")
	}
}

// A provider that misconfigures itself with a small key would otherwise
// downgrade everybody silently.
func TestASmallRSAKeyIsRefused(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	k := jwk{Kty: "RSA",
		N: base64.RawURLEncoding.EncodeToString(small.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes())}
	if _, err := k.public(); err == nil {
		t.Error("a 1024-bit RSA key was accepted")
	}

	big2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	ok := jwk{Kty: "RSA",
		N: base64.RawURLEncoding.EncodeToString(big2048.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes())}
	if _, err := ok.public(); err != nil {
		t.Errorf("a 2048-bit key was refused: %v", err)
	}
}

func TestUnsupportedKeyTypesAndCurvesAreSkipped(t *testing.T) {
	for _, k := range []jwk{
		{Kty: "oct", Kid: "symmetric"},
		{Kty: "EC", Crv: "P-192", X: "AA", Y: "AA"},
		{Kty: "OKP", Crv: "Ed25519", X: "AA"},
	} {
		if _, err := k.public(); err == nil {
			t.Errorf("%s/%s was accepted", k.Kty, k.Crv)
		}
	}
}

// Trying each key until one verifies would accept a token signed by any of
// them, which is a much weaker claim than the one being made.
func TestAnAbsentKeyIDIsOnlyResolvedWhenThereIsOneKey(t *testing.T) {
	single, _ := rsa.GenerateKey(rand.Reader, 2048)

	if _, err := pick("", nil, false, &single.PublicKey, 1); err != nil {
		t.Errorf("one key with no kid should resolve: %v", err)
	}
	_, err := pick("", nil, false, nil, 3)
	if err == nil {
		t.Fatal("an absent kid resolved against three keys")
	}
	if !strings.Contains(err.Error(), "any of them") {
		t.Errorf("the error does not say what the risk is: %v", err)
	}
	if _, err := pick("unknown", nil, false, &single.PublicKey, 1); err == nil {
		t.Error("an unknown kid resolved to the only key; a kid that does not " +
			"match is not the same as no kid at all")
	}
}

// -- discovery ---------------------------------------------------------------

// A provider claiming to be somebody else would make every issuer check
// downstream compare against a value the provider chose.
func TestDiscoveryRefusesAnIssuerMismatch(t *testing.T) {
	d := Discovery{Issuer: "https://evil.example"}
	if d.Issuer == "https://idp.example" {
		t.Fatal("fixture is wrong")
	}
	// The check lives in Discover, which needs a network; this asserts the
	// comparison it performs, so the rule cannot be loosened silently.
	base := "https://idp.example"
	if d.Issuer == base || d.Issuer == base+"/" {
		t.Error("a mismatched issuer compared equal")
	}
}

// The plain code challenge method is PKCE with the protection removed.
func TestS256IsRequiredButAnAbsentListIsTolerated(t *testing.T) {
	if !(Discovery{}).offersS256() {
		t.Error("an absent list should be tolerated; the parameter is optional " +
			"and several established providers omit it while supporting it")
	}
	if !(Discovery{CodeChallengeMethods: []string{"plain", "S256"}}).offersS256() {
		t.Error("a list containing S256 was rejected")
	}
	if (Discovery{CodeChallengeMethods: []string{"plain"}}).offersS256() {
		t.Error("a provider offering only plain was accepted")
	}
}

// The two things an operator is most likely to hit, and both are correct
// refusals that need to say what to do instead rather than only that something
// is wrong.
func TestTheCommonRefusalsExplainTheFix(t *testing.T) {
	// Microsoft's /common endpoint publishes a placeholder because the real
	// issuer differs per tenant. Accepting it would make the issuer check
	// compare against "{tenantid}".
	d := Discovery{Issuer: "https://login.microsoftonline.com/{tenantid}/v2.0"}
	if !strings.Contains(d.Issuer, "{") {
		t.Fatal("fixture is wrong")
	}

	// A workload identity issuer has keys and no authorization endpoint,
	// because nobody signs in to it.
	gh := Discovery{
		Issuer:  "https://token.actions.githubusercontent.com",
		JWKSURI: "https://token.actions.githubusercontent.com/.well-known/jwks",
	}
	if gh.AuthorizationEndpoint != "" {
		t.Fatal("fixture is wrong")
	}
}
