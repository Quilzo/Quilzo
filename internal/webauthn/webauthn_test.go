package webauthn_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/webauthn"
)

const (
	rpID   = "cms.example"
	origin = "https://cms.example"
)

func party() webauthn.Party {
	return webauthn.Party{ID: rpID, Origin: origin}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// authenticator is a stand-in for a real one, built from the specification
// rather than from this package's own code. A test that assembles its input
// with the functions under test proves only that they agree with each other.
type authenticator struct {
	key   *ecdsa.PrivateKey
	rpID  string
	count uint32
	// flags overrides the flags byte when non-zero.
	flags byte
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{key: k, rpID: rpID, count: 1}
}

func (a *authenticator) spki(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(a.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// authData builds the 37-byte fixed part: rpIdHash, flags, counter.
func (a *authenticator) authData() []byte {
	sum := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, sum[:]...)
	flags := byte(0x01 | 0x04) // present and verified
	if a.flags != 0 {
		flags = a.flags
	}
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, a.count)
}

func clientDataFor(t *testing.T, kind, challenge, org string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type": kind, "challenge": challenge, "origin": org,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (a *authenticator) register(t *testing.T, challenge string) webauthn.Registration {
	t.Helper()
	return webauthn.Registration{
		ID:                b64([]byte("credential-one")),
		ClientDataJSON:    b64(clientDataFor(t, "webauthn.create", challenge, origin)),
		AuthenticatorData: b64(a.authData()),
		PublicKey:         b64(a.spki(t)),
		Algorithm:         webauthn.AlgES256,
	}
}

// sign produces an assertion the way an authenticator does: over the
// authenticator data followed by a hash of the client data.
func (a *authenticator) assert(t *testing.T, challenge string) webauthn.Assertion {
	t.Helper()
	return a.assertAs(t, "webauthn.get", challenge, origin)
}

func (a *authenticator) assertAs(t *testing.T, kind, challenge, org string) webauthn.Assertion {
	t.Helper()
	cd := clientDataFor(t, kind, challenge, org)
	ad := a.authData()
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return webauthn.Assertion{
		ID:                b64([]byte("credential-one")),
		ClientDataJSON:    b64(cd),
		AuthenticatorData: b64(ad),
		Signature:         b64(sig),
	}
}

func registered(t *testing.T) (*authenticator, webauthn.Credential) {
	t.Helper()
	a := newAuthenticator(t)
	ch, err := webauthn.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := party().Register(ch, a.register(t, ch))
	if err != nil {
		t.Fatal(err)
	}
	return a, cred
}

// The control. Without it every refusal below proves only that Verify refuses.
func TestARealPasskeyRegistersAndSignsIn(t *testing.T) {
	a, cred := registered(t)

	ch, err := webauthn.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	a.count++
	count, err := party().Verify(cred, ch, a.assert(t, ch))
	if err != nil {
		t.Fatalf("a genuine passkey was refused: %v", err)
	}
	if count != a.count {
		t.Errorf("the counter came back %d, want %d", count, a.count)
	}
}

// The challenge is the proof of freshness. Without checking it, one captured
// assertion signs somebody in forever.
func TestAnAssertionForAnotherChallengeIsRefused(t *testing.T) {
	a, cred := registered(t)

	first, _ := webauthn.NewChallenge()
	second, _ := webauthn.NewChallenge()
	a.count++
	if _, err := party().Verify(cred, second, a.assert(t, first)); err == nil {
		t.Fatal("an assertion answering a different challenge was accepted, " +
			"so a captured one can be replayed for as long as the key exists")
	}
}

// The origin check is what makes a passkey unphishable. It is a string
// comparison, and loosening it gives the whole property away.
func TestAnAssertionFromAnotherOriginIsRefused(t *testing.T) {
	a, cred := registered(t)
	ch, _ := webauthn.NewChallenge()
	a.count++

	for _, bad := range []string{
		"https://cms.example.evil.test", // suffix confusion
		"https://evil.test",
		"http://cms.example", // scheme
		"https://cms.example:8443",
	} {
		_, err := party().Verify(cred, ch, a.assertAs(t, "webauthn.get", ch, bad))
		if err == nil {
			t.Errorf("an assertion reporting origin %q was accepted", bad)
		}
	}
}

// A registration signature and a sign-in signature are both a signature over a
// challenge by the same key. Only the ceremony type separates them.
func TestARegistrationCannotBeReplayedAsASignIn(t *testing.T) {
	a, cred := registered(t)
	ch, _ := webauthn.NewChallenge()
	a.count++

	if _, err := party().Verify(cred, ch,
		a.assertAs(t, "webauthn.create", ch, origin)); err == nil {
		t.Fatal("a registration ceremony was accepted as a sign-in")
	}
}

// A credential is bound to one site by the hash in the authenticator data.
func TestACredentialForAnotherSiteIsRefused(t *testing.T) {
	a, cred := registered(t)
	ch, _ := webauthn.NewChallenge()

	a.rpID = "someone-else.example"
	a.count++
	if _, err := party().Verify(cred, ch, a.assert(t, ch)); err == nil {
		t.Fatal("a credential bound to another site was accepted")
	}
}

// Somebody has to have touched it.
func TestAnAssertionWithNobodyPresentIsRefused(t *testing.T) {
	a, cred := registered(t)
	ch, _ := webauthn.NewChallenge()

	a.flags = 0x04 // verified but not present, which is not a state that means anything
	a.count++
	if _, err := party().Verify(cred, ch, a.assert(t, ch)); err == nil {
		t.Fatal("an assertion with no user-presence flag was accepted, so a " +
			"key on a compromised machine can be used silently")
	}
}

// Requiring verification means requiring it.
func TestUserVerificationIsEnforcedWhenRequired(t *testing.T) {
	a, cred := registered(t)
	ch, _ := webauthn.NewChallenge()

	p := party()
	p.RequireUserVerification = true
	a.flags = 0x01 // present, not verified
	a.count++
	if _, err := p.Verify(cred, ch, a.assert(t, ch)); err == nil {
		t.Fatal("a touch-only assertion was accepted where a PIN was required")
	}
}

// A counter that does not advance is the one clone signal WebAuthn gives.
func TestACounterThatDoesNotAdvanceIsRefused(t *testing.T) {
	a, cred := registered(t)
	cred.SignCount = 5
	a.count = 5
	ch, _ := webauthn.NewChallenge()

	if _, err := party().Verify(cred, ch, a.assert(t, ch)); err == nil {
		t.Fatal("a counter that went backwards was accepted, so a copied " +
			"credential is indistinguishable from the original")
	}
}

// Authenticators that keep no counter report zero forever, and refusing those
// would refuse most phones.
func TestAnAuthenticatorWithNoCounterStillWorks(t *testing.T) {
	a := newAuthenticator(t)
	a.count = 0
	ch, _ := webauthn.NewChallenge()
	cred, err := party().Register(ch, a.register(t, ch))
	if err != nil {
		t.Fatal(err)
	}

	next, _ := webauthn.NewChallenge()
	if _, err := party().Verify(cred, next, a.assert(t, next)); err != nil {
		t.Fatalf("an authenticator that keeps no counter was refused: %v", err)
	}
}

// The signature has to be by this credential's key.
func TestAnAssertionSignedByAnotherKeyIsRefused(t *testing.T) {
	_, cred := registered(t)
	other := newAuthenticator(t)
	ch, _ := webauthn.NewChallenge()
	other.count = cred.SignCount + 1

	if _, err := party().Verify(cred, ch, other.assert(t, ch)); err == nil {
		t.Fatal("an assertion signed by a different key was accepted")
	}
}

// An assertion made with one credential must not verify as another.
func TestAnAssertionNamingAnotherCredentialIsRefused(t *testing.T) {
	a, cred := registered(t)
	ch, _ := webauthn.NewChallenge()
	a.count++

	as := a.assert(t, ch)
	as.ID = b64([]byte("some-other-credential"))
	if _, err := party().Verify(cred, ch, as); err == nil {
		t.Fatal("an assertion whose credential id differs from the stored one " +
			"was accepted")
	}
}

// A key whose type is not what the browser claimed must be refused, because
// the claim decides which verification gets applied.
func TestAKeyThatDoesNotMatchTheClaimedAlgorithmIsRefused(t *testing.T) {
	a := newAuthenticator(t)
	ch, _ := webauthn.NewChallenge()

	reg := a.register(t, ch)
	reg.Algorithm = webauthn.AlgEdDSA // an ECDSA key described as Ed25519
	if _, err := party().Register(ch, reg); err == nil {
		t.Fatal("a P-256 key registered as Ed25519")
	}
}

// Registering with no challenge is not a weaker registration, it is none.
func TestRegisteringWithNoChallengeIsRefused(t *testing.T) {
	a := newAuthenticator(t)
	if _, err := party().Register("", a.register(t, "")); err == nil {
		t.Fatal("a registration with no challenge was accepted")
	}
}

// Challenges have to differ. A fixed one is a signature somebody can obtain in
// advance.
func TestChallengesAreNotReused(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		c, err := webauthn.NewChallenge()
		if err != nil {
			t.Fatal(err)
		}
		if seen[c] {
			t.Fatal("a challenge repeated within 256 draws")
		}
		if len(c) < 32 {
			t.Fatalf("a challenge is %d characters, which is not 32 bytes", len(c))
		}
		seen[c] = true
	}
}

// The failure message must not say which algorithm failed or how.
func TestTheFailureMessageSaysNothingUseful(t *testing.T) {
	_, cred := registered(t)
	other := newAuthenticator(t)
	other.count = cred.SignCount + 1
	ch, _ := webauthn.NewChallenge()

	_, err := party().Verify(cred, ch, other.assert(t, ch))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, leak := range []string{"P-256", "ecdsa", "ASN.1", "curve"} {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(leak)) {
			t.Errorf("the refusal mentions %q: %v", leak, err)
		}
	}
}
