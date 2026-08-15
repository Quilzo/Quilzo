// Package oidc authenticates people against an identity provider.
//
// # Why this and not SAML
//
// SAML is what enterprise buyers ask for, and implementing it in Go is a bad
// idea for a specific reason: Go's encoding/xml does not preserve semantics
// across a parse and re-serialise. That lets a crafted document present one
// thing to signature verification and a different thing to data extraction —
// XML Signature Wrapping — and both major Go SAML libraries shipped variants of
// it. The irony is exact: the loose tokenizer that makes encoding/xml immune to
// XXE, which this project relies on elsewhere, is what makes the wrapping
// possible.
//
// An OIDC ID token is a JWT: three base64url segments, and the signature covers
// the first two *as received*. There is no canonicalisation step, so there is no
// gap between what was verified and what is read. Nothing here ever
// re-serialises a token before checking it.
//
// SAML is still reachable — through an identity provider that speaks both, which
// is how most organisations already run it. That moves the XML parsing to
// software whose full-time job it is.
//
// # The algorithm allow-list is the whole ballgame
//
// The classic JWT failure is trusting the `alg` in the token's own header. Two
// forms:
//
//	alg: none    the token says it is unsigned, and a naive verifier agrees
//	alg: HS256   the token says it is symmetric, and a verifier that hands the
//	             RSA *public* key to HMAC will validate it — the public key is
//	             public, so anybody can forge
//
// So the algorithm is never read from the token to decide what to do. The
// provider's discovery document says which algorithms it signs with, that list
// is intersected with the ones implemented here, and a token whose header names
// anything else is refused before its signature is examined.
//
// Only RS256 and ES256 are implemented, plus the 384 and 512 variants. That is
// not a limitation to apologise for — every algorithm is code that can be wrong,
// and these cover essentially every provider in use.
//
// # What is refused outright
//
//	symmetric algorithms   HS256 and friends; see above
//	alg: none              obviously
//	nested JWTs            a JWT whose payload is another JWT doubles the
//	                       parsing surface for no benefit here
//	crit headers           a header saying "you must understand this" that this
//	                       does not understand is a refusal, not something to
//	                       ignore
package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

// Algorithm is a signing algorithm this package implements.
type Algorithm string

const (
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
)

// supported is the closed set. Nothing outside it is verified, whatever a token
// or a discovery document claims.
var supported = map[Algorithm]bool{
	RS256: true, RS384: true, RS512: true,
	ES256: true, ES384: true, ES512: true,
	PS256: true, PS384: true, PS512: true,
}

// Supported lists the algorithms, for the error message when a provider offers
// none of them.
func Supported() []string {
	out := make([]string, 0, len(supported))
	for a := range supported {
		out = append(out, string(a))
	}
	sortStrings(out)
	return out
}

// header is the first segment of a JWT.
type header struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Crit []string `json:"crit"`
	// Enc being present means this is an encrypted JWT rather than a signed
	// one, which is a different structure entirely.
	Enc string `json:"enc"`
}

// Claims are the parts of an ID token this package reads.
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  any    `json:"aud"` // string or []string, per the spec
	Expiry    int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Nonce     string `json:"nonce"`
	// AuthorizedParty is required when there is more than one audience, and is
	// how a token minted for a different client is caught.
	AuthorizedParty string `json:"azp"`

	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Groups        []string `json:"groups"`

	// Raw is the decoded payload, so a caller can read a claim this struct does
	// not name without the token being parsed twice.
	Raw map[string]any `json:"-"`
}

// Audiences normalises the audience claim, which the spec allows to be either a
// string or an array.
func (c Claims) Audiences() []string {
	switch v := c.Audience.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Verifier checks ID tokens against one provider.
type Verifier struct {
	// Issuer must match the token's iss exactly. Not a prefix, not
	// case-insensitively, not ignoring a trailing slash: issuer confusion is
	// how a token from a provider you do not trust gets accepted by one you do.
	Issuer string
	// ClientID is the audience this client expects.
	ClientID string
	// Algorithms is the intersection of what the provider advertises and what
	// this package implements. Empty means nothing can be verified, which is a
	// refusal rather than a permissive default.
	Algorithms []Algorithm
	// Keys resolves a key id to a public key.
	Keys KeySource
	// Skew tolerates clock drift between this machine and the provider.
	Skew time.Duration
	// Now is injectable for tests. Nil means time.Now.
	Now func() time.Time
}

// KeySource supplies public keys by key id.
type KeySource interface {
	// Key returns the key for a kid. An empty kid is permitted only when the
	// provider publishes exactly one key, because otherwise the verifier would
	// have to try each in turn — and a verifier that tries keys until one works
	// is a verifier that accepts a token signed by any of them.
	Key(kid string) (crypto.PublicKey, error)
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify checks an ID token and returns its claims.
//
// nonce is the value this client sent on the authorization request. It is
// required: without checking that it comes back inside the token, the parameter
// provides no replay protection at all, which is the most commonly skipped step
// in every OIDC implementation guide.
func (v *Verifier) Verify(token, nonce string) (*Claims, error) {
	if v.Issuer == "" || v.ClientID == "" {
		return nil, fmt.Errorf("the verifier has no issuer or client id")
	}
	if len(v.Algorithms) == 0 {
		return nil, fmt.Errorf(
			"no signing algorithm is agreed with this provider. It advertises "+
				"none that are implemented here (%s), which is a refusal rather "+
				"than something to work around", strings.Join(Supported(), ", "))
	}
	if nonce == "" {
		return nil, fmt.Errorf("a nonce is required. Requesting one and not " +
			"checking it comes back is the same as not sending one")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		if len(parts) == 5 {
			return nil, fmt.Errorf("this is an encrypted JWT (five segments), " +
				"not a signed one. Encrypted ID tokens are not accepted")
		}
		return nil, fmt.Errorf("an ID token has three segments, this has %d",
			len(parts))
	}

	rawHeader, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("the header is not valid base64url: %w", err)
	}
	var h header
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return nil, fmt.Errorf("the header is not JSON: %w", err)
	}

	if h.Enc != "" {
		return nil, fmt.Errorf("this token carries an enc header, so it is " +
			"encrypted rather than signed")
	}
	if len(h.Crit) > 0 {
		// crit means "you must understand these or reject". Nothing here
		// understands any of them, so the honest answer is to reject.
		return nil, fmt.Errorf(
			"the header marks %v as critical, and this verifier implements none "+
				"of them. A crit header that is ignored is the extension "+
				"mechanism working exactly backwards", h.Crit)
	}
	if h.Typ != "" && !strings.EqualFold(h.Typ, "JWT") {
		return nil, fmt.Errorf("unexpected token type %q", h.Typ)
	}

	// The algorithm is checked against the agreed list, never taken from the
	// token as an instruction. This is the check that stops alg:none and the
	// HMAC-with-the-public-key forgery.
	alg := Algorithm(h.Alg)
	if !v.agreed(alg) {
		return nil, fmt.Errorf(
			"this token is signed with %q, which is not one of the algorithms "+
				"agreed with %s (%s). The algorithm a token names is a claim by "+
				"whoever made it, not an instruction",
			h.Alg, v.Issuer, algList(v.Algorithms))
	}

	key, err := v.Keys.Key(h.Kid)
	if err != nil {
		return nil, fmt.Errorf("no key for kid %q: %w", h.Kid, err)
	}

	sig, err := decodeSegment(parts[2])
	if err != nil {
		return nil, fmt.Errorf("the signature is not valid base64url: %w", err)
	}
	// Signed over the segments exactly as received. Re-encoding the header or
	// payload before verifying would reintroduce the gap between what is
	// checked and what is read — which is the SAML bug in a different format.
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(alg, key, signingInput, sig); err != nil {
		return nil, fmt.Errorf("the signature does not verify: %w", err)
	}

	rawPayload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("the payload is not valid base64url: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(rawPayload, &c); err != nil {
		return nil, fmt.Errorf("the payload is not JSON: %w", err)
	}
	_ = json.Unmarshal(rawPayload, &c.Raw)

	if err := v.checkClaims(&c, nonce); err != nil {
		return nil, err
	}
	return &c, nil
}

func (v *Verifier) agreed(a Algorithm) bool {
	if !supported[a] {
		return false
	}
	for _, ok := range v.Algorithms {
		if ok == a {
			return true
		}
	}
	return false
}

func (v *Verifier) checkClaims(c *Claims, nonce string) error {
	// Exact string comparison. A prefix match, a case-insensitive one, or one
	// that forgives a trailing slash is how a token from evil.example/../trusted
	// gets accepted.
	if c.Issuer != v.Issuer {
		return fmt.Errorf("this token was issued by %q, not %q", c.Issuer, v.Issuer)
	}

	auds := c.Audiences()
	if len(auds) == 0 {
		return fmt.Errorf("the token has no audience")
	}
	found := false
	for _, a := range auds {
		if subtle.ConstantTimeCompare([]byte(a), []byte(v.ClientID)) == 1 {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("this token is for %v, not for this client", auds)
	}
	// With more than one audience the spec requires azp, and it must be us.
	// Without this check a token minted for a different client at the same
	// provider, listing us as a secondary audience, would be accepted.
	if len(auds) > 1 {
		if c.AuthorizedParty == "" {
			return fmt.Errorf("this token has %d audiences and no azp, so there "+
				"is no way to tell which client it was minted for", len(auds))
		}
		if c.AuthorizedParty != v.ClientID {
			return fmt.Errorf("this token was minted for %q and merely lists "+
				"this client as an audience", c.AuthorizedParty)
		}
	}

	if subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1 {
		return fmt.Errorf("the nonce does not match the one sent with the " +
			"authorization request; this token is a replay or belongs to a " +
			"different sign-in")
	}

	now := v.now()
	skew := v.Skew
	if skew == 0 {
		skew = 2 * time.Minute
	}
	if c.Expiry == 0 {
		return fmt.Errorf("the token has no expiry")
	}
	if now.After(time.Unix(c.Expiry, 0).Add(skew)) {
		return fmt.Errorf("this token expired at %s",
			time.Unix(c.Expiry, 0).UTC().Format(time.RFC3339))
	}
	if c.NotBefore != 0 && now.Before(time.Unix(c.NotBefore, 0).Add(-skew)) {
		return fmt.Errorf("this token is not valid until %s",
			time.Unix(c.NotBefore, 0).UTC().Format(time.RFC3339))
	}
	// A token issued in the future is either a clock problem or a forgery, and
	// both are worth stopping.
	if c.IssuedAt != 0 && now.Add(skew).Before(time.Unix(c.IssuedAt, 0)) {
		return fmt.Errorf("this token claims to have been issued at %s, which "+
			"is in the future",
			time.Unix(c.IssuedAt, 0).UTC().Format(time.RFC3339))
	}
	if c.Subject == "" {
		return fmt.Errorf("the token has no subject, so it identifies nobody")
	}
	return nil
}

// -- signatures --------------------------------------------------------------

func verifySignature(alg Algorithm, key crypto.PublicKey, input, sig []byte) error {
	h, hashID := hasherFor(alg)
	if h == nil {
		return fmt.Errorf("no hash for %s", alg)
	}
	h.Write(input)
	digest := h.Sum(nil)

	switch alg {
	case RS256, RS384, RS512:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s needs an RSA key, the provider published a %T",
				alg, key)
		}
		return rsa.VerifyPKCS1v15(pub, hashID, digest, sig)

	case PS256, PS384, PS512:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s needs an RSA key, the provider published a %T",
				alg, key)
		}
		return rsa.VerifyPSS(pub, hashID, digest, sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hashID,
		})

	case ES256, ES384, ES512:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s needs an EC key, the provider published a %T",
				alg, key)
		}
		// JWS ECDSA signatures are the fixed-width concatenation of r and s,
		// not the ASN.1 DER encoding that ecdsa.VerifyASN1 expects. Passing DER
		// bytes here silently fails and passing these to VerifyASN1 silently
		// fails, so the two are easy to confuse and the failure looks like a
		// wrong key.
		n := keyBytes(alg)
		if len(sig) != 2*n {
			return fmt.Errorf("an %s signature is %d bytes, this is %d",
				alg, 2*n, len(sig))
		}
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return fmt.Errorf("the signature is not valid for this key")
		}
		return nil
	}
	return fmt.Errorf("unsupported algorithm %s", alg)
}

func hasherFor(alg Algorithm) (hash.Hash, crypto.Hash) {
	switch alg {
	case RS256, PS256, ES256:
		return sha256.New(), crypto.SHA256
	case RS384, PS384, ES384:
		return sha512.New384(), crypto.SHA384
	case RS512, PS512, ES512:
		return sha512.New(), crypto.SHA512
	}
	return nil, 0
}

// keyBytes is the coordinate size for an ECDSA curve, which decides the
// signature length.
func keyBytes(alg Algorithm) int {
	switch alg {
	case ES256:
		return 32
	case ES384:
		return 48
	case ES512:
		return 66 // P-521 rounds up to 66 bytes, not 64
	}
	return 0
}

// decodeSegment reads base64url without padding, which is what JWS uses.
func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func algList(a []Algorithm) string {
	out := make([]string, len(a))
	for i := range a {
		out[i] = string(a[i])
	}
	return strings.Join(out, ", ")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
