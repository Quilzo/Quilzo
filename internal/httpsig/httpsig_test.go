// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package httpsig_test

import (
	"bufio"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/httpsig"
)

func at() time.Time { return time.Unix(1787000000, 0) }

func edPair(t *testing.T, seed byte) (ed25519.PrivateKey, httpsig.PublicKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv, httpsig.PublicKey{
		ID: "k-ed", Alg: httpsig.Ed25519,
		Ed: priv.Public().(ed25519.PublicKey),
	}
}

func rsaPair(t *testing.T) (*rsa.PrivateKey, httpsig.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return priv, httpsig.PublicKey{
		ID: "k-rsa", Alg: httpsig.RSAPKCS1SHA256, RSA: &priv.PublicKey,
	}
}

func req() *http.Request {
	return httptest.NewRequest("POST", "http://example.test/inbox", nil)
}

var cover = []string{"@method", "@authority", "@path"}

// The round trip, for both algorithms. Two consumers need different ones and
// a package that signed what it could not verify would be worse than useless.
func TestSignAndVerifyRoundTrip(t *testing.T) {
	edPriv, edPub := edPair(t, 3)
	rsaPriv, rsaPub := rsaPair(t)

	for _, c := range []struct {
		name string
		alg  httpsig.Algorithm
		priv crypto.Signer
		pub  httpsig.PublicKey
	}{
		{"ed25519", httpsig.Ed25519, edPriv, edPub},
		{"rsa", httpsig.RSAPKCS1SHA256, rsaPriv, rsaPub},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := req()
			if err := httpsig.Sign(r, c.pub.ID, c.alg, c.priv, cover, at()); err != nil {
				t.Fatalf("signing failed: %v", err)
			}

			got, err := httpsig.Verify(r, []httpsig.PublicKey{c.pub}, 0, at())
			if err != nil {
				t.Fatalf("a signature this package made did not verify: %v", err)
			}
			if got == nil {
				t.Fatal("no signature was reported")
			}
			if got.KeyID != c.pub.ID {
				t.Errorf("key id is %q", got.KeyID)
			}
			for _, want := range cover {
				if !got.Covers(want) {
					t.Errorf("%s is not reported as covered", want)
				}
			}
		})
	}
}

// An unsigned request is not an error. A browser signs nothing.
func TestAnUnsignedRequestIsNotAFailure(t *testing.T) {
	got, err := httpsig.Verify(req(), nil, 0, at())
	if err != nil || got != nil {
		t.Fatalf("an unsigned request gave (%v, %v)", got, err)
	}
}

// The algorithm claim cannot be rewritten, because it is inside what was
// signed.
//
// This test first asserted the weaker thing — that a rewritten claim would be
// ignored and the signature would still verify — and it failed, which was the
// test being wrong rather than the code. The @signature-params line is the raw
// Signature-Input value and it is part of the base, so changing any of it,
// including alg, changes the base and the signature stops matching.
//
// That is a better property than ignoring the claim: it cannot be tampered
// with at all, rather than being tampered with harmlessly.
func TestTheAlgorithmClaimIsItselfSigned(t *testing.T) {
	edPriv, edPub := edPair(t, 5)
	r := req()
	if err := httpsig.Sign(r, edPub.ID, httpsig.Ed25519, edPriv, cover, at()); err != nil {
		t.Fatal(err)
	}

	// It verifies as sent.
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{edPub}, 0, at()); err != nil {
		t.Fatalf("the signature did not verify as made: %v", err)
	}

	// And not once the claim is edited.
	r.Header.Set("Signature-Input", strings.Replace(
		r.Header.Get("Signature-Input"), `alg="ed25519"`, `alg="rsa-v1_5-sha256"`, 1))
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{edPub}, 0, at()); err == nil {
		t.Fatal("the algorithm claim was rewritten and the signature still " +
			"verified, so it is not covered by the signature")
	}

	// The same holds for the key id, which is the other field an attacker
	// would want to move.
	r2 := req()
	if err := httpsig.Sign(r2, edPub.ID, httpsig.Ed25519, edPriv, cover, at()); err != nil {
		t.Fatal(err)
	}
	swapped := httpsig.PublicKey{ID: "someone-else", Alg: edPub.Alg, Ed: edPub.Ed}
	r2.Header.Set("Signature-Input", strings.Replace(
		r2.Header.Get("Signature-Input"), `keyid="k-ed"`, `keyid="someone-else"`, 1))
	if _, err := httpsig.Verify(r2, []httpsig.PublicKey{swapped}, 0, at()); err == nil {
		t.Fatal("the key id was rewritten to another configured key and the " +
			"signature still verified")
	}
}

// A key declaring one algorithm and carrying another's material must refuse
// rather than reach for whatever is present.
func TestAKeyMustCarryTheAlgorithmItDeclares(t *testing.T) {
	edPriv, edPub := edPair(t, 9)
	r := req()
	if err := httpsig.Sign(r, edPub.ID, httpsig.Ed25519, edPriv, cover, at()); err != nil {
		t.Fatal(err)
	}
	broken := httpsig.PublicKey{ID: edPub.ID, Alg: httpsig.RSAPKCS1SHA256}
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{broken}, 0, at()); err == nil {
		t.Fatal("a key declaring RSA with no RSA key verified something")
	}
}

// Both algorithms, because a round trip passes even when verification always
// says yes — signing and verifying agree perfectly if the verifier agrees with
// everything. Only a tampered request separates the two, and the RSA path had
// no such test while being the one most of the fediverse actually uses.
func TestATamperedRequestIsRefused(t *testing.T) {
	edPriv, edPub := edPair(t, 11)
	rsaPriv, rsaPub := rsaPair(t)

	for _, c := range []struct {
		name string
		alg  httpsig.Algorithm
		priv crypto.Signer
		pub  httpsig.PublicKey
	}{
		{"ed25519", httpsig.Ed25519, edPriv, edPub},
		{"rsa", httpsig.RSAPKCS1SHA256, rsaPriv, rsaPub},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := req()
			if err := httpsig.Sign(r, c.pub.ID, c.alg, c.priv, cover, at()); err != nil {
				t.Fatal(err)
			}
			// It verifies as made, so a failure below is the tampering and not
			// a broken fixture.
			if _, err := httpsig.Verify(r, []httpsig.PublicKey{c.pub}, 0, at()); err != nil {
				t.Fatalf("the signature did not verify as made: %v", err)
			}

			r.URL.Path = "/somewhere-else"
			if _, err := httpsig.Verify(r, []httpsig.PublicKey{c.pub}, 0, at()); err == nil {
				t.Fatal("a request altered after signing verified")
			}
		})
	}
}

// And a signature from another key of the same algorithm, for both. Tampering
// catches a verifier that ignores the bytes; this catches one that ignores the
// key.
func TestASignatureFromAnotherKeyIsRefusedForBothAlgorithms(t *testing.T) {
	edPriv, _ := edPair(t, 41)
	_, edOther := edPair(t, 43)
	edOther.ID = "k-ed"

	rsaPriv, _ := rsaPair(t)
	_, rsaOther := rsaPair(t)
	rsaOther.ID = "k-rsa"

	for _, c := range []struct {
		name  string
		alg   httpsig.Algorithm
		priv  crypto.Signer
		other httpsig.PublicKey
	}{
		{"ed25519", httpsig.Ed25519, edPriv, edOther},
		{"rsa", httpsig.RSAPKCS1SHA256, rsaPriv, rsaOther},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := req()
			if err := httpsig.Sign(r, c.other.ID, c.alg, c.priv, cover, at()); err != nil {
				t.Fatal(err)
			}
			if _, err := httpsig.Verify(r, []httpsig.PublicKey{c.other}, 0, at()); err == nil {
				t.Fatal("a signature verified against a different key of the " +
					"same name and algorithm")
			}
		})
	}
}

// A component that cannot be rebuilt is refused, never skipped. Verifying over
// less than was signed and calling it valid is a forgery the verifier performs
// on itself.
func TestAnUnknownCoveredComponentIsRefusedNotSkipped(t *testing.T) {
	priv, pub := edPair(t, 13)
	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Signature-Input", strings.Replace(
		r.Header.Get("Signature-Input"), `"@path"`, `"@path" "@invented"`, 1))

	_, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at())
	if err == nil {
		t.Fatal("a signature covering an unrebuildable component verified")
	}
	if !strings.Contains(err.Error(), "@invented") {
		t.Errorf("the error does not name the component: %v", err)
	}
}

// Covers is what lets a caller require that something in particular was
// signed. A signature over "@method" alone is valid and proves almost nothing.
func TestCoversReportsWhatWasActuallySigned(t *testing.T) {
	priv, pub := edPair(t, 17)
	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv,
		[]string{"@method"}, at()); err != nil {
		t.Fatal(err)
	}
	got, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Covers("@method") {
		t.Error("@method was signed and is not reported as covered")
	}
	if got.Covers("@path") {
		t.Error("@path was not signed and is reported as covered, so a caller " +
			"requiring it would be satisfied by a signature that omitted it")
	}
}

func TestAnOldSignatureIsRefused(t *testing.T) {
	priv, pub := edPair(t, 19)
	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover,
		at().Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err == nil {
		t.Fatal("a ten-minute-old signature verified")
	}
}

func TestHalfASignatureIsRefused(t *testing.T) {
	priv, pub := edPair(t, 23)
	for _, drop := range []string{"Signature", "Signature-Input"} {
		r := req()
		if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
			t.Fatal(err)
		}
		r.Header.Del(drop)
		if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err == nil {
			t.Errorf("a request with no %s verified", drop)
		}
	}
}

func TestAnotherKeyIsRefused(t *testing.T) {
	priv, pub := edPair(t, 29)
	_, other := edPair(t, 31)
	other.ID = pub.ID // same name, different key

	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
		t.Fatal(err)
	}
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{other}, 0, at()); err == nil {
		t.Fatal("a signature verified against a different key of the same name")
	}
}

func TestSigningNothingIsRefused(t *testing.T) {
	priv, pub := edPair(t, 37)
	if err := httpsig.Sign(req(), pub.ID, httpsig.Ed25519, priv, nil, at()); err == nil {
		t.Fatal("a signature covering no components was produced")
	}
}

// A key too small to mean anything is refused rather than used.
//
// A signature verified against a 1024-bit RSA key proves less than it appears
// to, and the appearance is the problem: everything downstream treats "the
// signature verified" as settled. Refusing at the parse is where a remote
// server publishing a weak key is a configuration error rather than a
// silently weaker guarantee.
func TestAWeakRSAKeyIsRefused(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&weak.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	weakPEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: der,
	}))

	if _, err := httpsig.ParsePEM("k", weakPEM); err == nil {
		t.Fatal("a 1024-bit RSA key was accepted; every signature checked " +
			"against it would read as settled")
	}

	// And a key of a usable size still parses, or the check is a wall.
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err = x509.MarshalPKIXPublicKey(&strong.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	strongPEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: der,
	}))
	key, err := httpsig.ParsePEM("k", strongPEM)
	if err != nil {
		t.Fatalf("a 2048-bit key was refused: %v", err)
	}
	if key.Alg != httpsig.RSAPKCS1SHA256 {
		t.Errorf("an RSA key parsed as %q", key.Alg)
	}
}

// The algorithm is read out of the key material here, which is the one place
// that is right: a PEM block is the key, not a claim about it, and an RSA key
// cannot be verified as Ed25519 whatever anybody says.
func TestParsePEMReadsTheAlgorithmFromTheKeyItself(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	key, err := httpsig.ParsePEM("k", string(pem.EncodeToMemory(
		&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	if key.Alg != httpsig.Ed25519 {
		t.Errorf("an Ed25519 key parsed as %q", key.Alg)
	}
}

func TestAnUnreadableKeyIsRefused(t *testing.T) {
	for name, text := range map[string]string{
		"not pem":   "hello",
		"empty":     "",
		"junk body": "-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----\n",
	} {
		if _, err := httpsig.ParsePEM("k", text); err == nil {
			t.Errorf("%s was accepted as a key", name)
		}
	}
}

// A signature that covers nothing is refused by the parser.
//
// An empty component list parses cleanly and produces a base of the parameters
// alone, so the signature authenticates possession of a key against any request
// at all. Every caller would have to remember to check; one that forgot would
// report "valid" for a proof about nothing, which is the forgery this package's
// own documentation says it must never perform on itself.
func TestASignatureOverNothingIsRefused(t *testing.T) {
	priv, pub := edPair(t, 7)
	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
		t.Fatal(err)
	}
	// The same signature bytes, re-labelled as covering nothing.
	r.Header.Set("Signature-Input",
		`sig1=();created=1787000000;keyid="`+pub.ID+`"`)

	if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err == nil {
		t.Fatal("a signature covering no components verified")
	}
}

// And the request line is a question a caller can ask, because the two
// verifiers in this tree both have to ask it.
func TestCoversRequestNeedsTheDestination(t *testing.T) {
	cases := map[string]struct {
		covered []string
		want    bool
	}{
		"method, authority and path": {
			[]string{"@method", "@authority", "@path"}, true},
		"method and target-uri": {[]string{"@method", "@target-uri"}, true},
		"the body alone":        {[]string{"content-digest"}, false},
		"no method":             {[]string{"@authority", "@path"}, false},
		"authority without path": {
			[]string{"@method", "@authority"}, false},
	}
	for what, c := range cases {
		s := httpsig.Signed{Covered: c.covered}
		if got := s.CoversRequest(); got != c.want {
			t.Errorf("%s: CoversRequest() = %v, want %v", what, got, c.want)
		}
	}
}

// Where the server knows its origin, the destination a signature covers is
// checked against that origin, not against the Host the request names. The
// receiver of a delivery signed for b.example could replay it to a.example
// with Host: b.example inside the age window, and it passed every check an
// inbox makes, CoversDestination and CoversRequest included.
func TestASignatureForAnotherHostIsRefusedWhereTheOriginIsKnown(t *testing.T) {
	priv, pub := edPair(t, 9)
	keys := []httpsig.PublicKey{pub}
	for _, format := range []string{"rfc9421", "cavage"} {
		t.Run(format, func(t *testing.T) {
			signedFor := func(host string) http.Header {
				out, err := http.NewRequest("POST", "https://"+host+"/@/inbox", nil)
				if err != nil {
					t.Fatal(err)
				}
				if format == "rfc9421" {
					err = httpsig.Sign(out, pub.ID, pub.Alg, priv, cover, at())
				} else {
					err = httpsig.SignCavage(out, pub.ID, pub.Alg, priv, []string{"(request-target)", "host", "date"}, at())
				}
				if err != nil {
					t.Fatal(err)
				}
				return out.Header
			}
			arriving := func(h http.Header, host string) *http.Request {
				r := httptest.NewRequest("POST", "/@/inbox", nil)
				r.Host, r.Header = host, h.Clone()
				return r
			}
			if s, err := httpsig.VerifyAt(arriving(signedFor("b.example"), "b.example"), "https://a.example", keys, 0, at()); err == nil {
				t.Errorf("a delivery signed for b.example verified at a.example, covering %v", s.Covered)
			}
			// Signed for this server, it verifies whatever Host a proxy in
			// front passed on, as @target-uri already did.
			for _, host := range []string{"a.example", "A.EXAMPLE", "10.0.0.5:8080"} {
				s, err := httpsig.VerifyAt(arriving(signedFor("a.example"), host), "https://a.example", keys, 0, at())
				if err != nil || s == nil || !s.CoversRequest() {
					t.Errorf("signed for a.example and arriving as %s: %v %v", host, s, err)
				}
			}
		})
	}
}

// A request line may name the whole URL (RFC 9112 section 3.2.2), and Go's
// server then takes both the request's URL and its Host from it. Reading
// such a request as one this server was about to send let the receiver of
// a delivery signed for b.example replay it to a.example as
// "POST https://b.example/@/inbox" and pass every destination check, the
// origin notwithstanding, whether the signature covered @authority, the
// draft's host line or @target-uri.
func TestARequestLineNamingAnotherHostIsReadAgainstTheOrigin(t *testing.T) {
	priv, pub := edPair(t, 11)
	keys := []httpsig.PublicKey{pub}
	for _, c := range []struct {
		format string
		cover  []string
	}{
		{"rfc9421", []string{"@method", "@authority", "@path"}},
		{"rfc9421", []string{"@method", "@target-uri"}},
		{"cavage", []string{"(request-target)", "host", "date"}},
	} {
		t.Run(c.format+" "+strings.Join(c.cover, " "), func(t *testing.T) {
			arriving := func(signedHost, line string) *http.Request {
				out, err := http.NewRequest("POST", "https://"+signedHost+"/@/inbox", nil)
				if err != nil {
					t.Fatal(err)
				}
				if c.format == "rfc9421" {
					err = httpsig.Sign(out, pub.ID, pub.Alg, priv, c.cover, at())
				} else {
					err = httpsig.SignCavage(out, pub.ID, pub.Alg, priv, c.cover, at())
				}
				if err != nil {
					t.Fatal(err)
				}
				var raw strings.Builder
				raw.WriteString("POST " + line + " HTTP/1.1\r\nHost: " + signedHost + "\r\n")
				out.Header.Write(&raw)
				raw.WriteString("Content-Length: 0\r\n\r\n")
				in, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw.String())))
				if err != nil {
					t.Fatal(err)
				}
				return in
			}
			r := arriving("b.example", "https://b.example/@/inbox")
			if s, err := httpsig.VerifyAt(r, "https://a.example", keys, 0, at()); err == nil {
				t.Errorf("a delivery signed for b.example, sent as %s %s, verified at a.example covering %v",
					r.Method, r.RequestURI, s.Covered)
			}
			// Signed for this server, it verifies however the line is written.
			for _, line := range []string{"/@/inbox", "https://a.example/@/inbox"} {
				r := arriving("a.example", line)
				if s, err := httpsig.VerifyAt(r, "https://a.example", keys, 0, at()); err != nil || s == nil {
					t.Errorf("signed for a.example, sent as %s: %v %v", line, s, err)
				}
			}
		})
	}
}

// A site's origin may be configured with its scheme's own port written out,
// as https://a.example:443. A sender leaves that port out of the host it
// signs, as RFC 9421 section 2.2.3 and HTTP's normal form have it, so the
// destination read from the origin has to leave it out too: kept, it
// refused every delivery to such a site that verified before the
// destination was read from the origin.
func TestTheOriginsOwnDefaultPortIsNotPartOfTheDestination(t *testing.T) {
	priv, pub := edPair(t, 13)
	keys := []httpsig.PublicKey{pub}
	for _, format := range []string{"rfc9421", "cavage"} {
		for _, origin := range []string{"https://a.example:443", "http://a.example:80"} {
			t.Run(format+" "+origin, func(t *testing.T) {
				scheme, _, _ := strings.Cut(origin, "://")
				out, err := http.NewRequest("POST", scheme+"://a.example/@/inbox", nil)
				if err != nil {
					t.Fatal(err)
				}
				if format == "rfc9421" {
					err = httpsig.Sign(out, pub.ID, pub.Alg, priv, cover, at())
				} else {
					err = httpsig.SignCavage(out, pub.ID, pub.Alg, priv, []string{"(request-target)", "host", "date"}, at())
				}
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest("POST", "/@/inbox", nil)
				r.Host, r.Header = "a.example", out.Header.Clone()
				if s, err := httpsig.VerifyAt(r, origin, keys, 0, at()); err != nil || s == nil || !s.CoversRequest() {
					t.Errorf("signed for a.example and checked at %s: %v %v", origin, s, err)
				}
				// A port that is not the scheme's own stays part of the host.
				if _, err := httpsig.VerifyAt(r, scheme+"://a.example:8443", keys, 0, at()); err == nil {
					t.Error("signed for a.example and verified at a.example:8443")
				}
			})
		}
	}
}
