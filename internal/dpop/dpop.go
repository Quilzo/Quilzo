// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package dpop binds a token to a key, as RFC 9449 says.
//
// A bearer token works for whoever holds it, so a token copied out of a
// program's environment, a log or a crash dump works for whoever copied it
// until it expires. A token bound to a key works only with a proof made by
// that key, fresh for each request: the program keeps the private key and
// sends a short signed statement of the method and address it is calling,
// with a hash of the token. A copied token without the key is useless, and a
// copied proof is good for one request to one address for a few minutes.
//
// The binding is the key's RFC 7638 thumbprint, kept with the token. The
// checks are the ones RFC 9449 lists for a resource server: one well-formed
// proof of type dpop+jwt, an asymmetric algorithm, a public key and no
// private one, a signature that verifies, the method and the address of
// this request, a recent time, an identifier not seen before, the hash of
// the token presented, and the thumbprint of the token's key.
package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/oidc"
)

// Window is how old a proof may be, and Skew how far ahead of this
// machine's clock its time may be.
const (
	Window = 5 * time.Minute
	Skew   = time.Minute
)

// Algorithms are the signatures a proof may use.
var Algorithms = []oidc.Algorithm{oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256, oidc.PS384, oidc.PS512,
	oidc.RS256, oidc.RS384, oidc.RS512}

// AlgorithmNames is Algorithms for a WWW-Authenticate challenge.
func AlgorithmNames() string {
	names := make([]string, len(Algorithms))
	for i, a := range Algorithms {
		names[i] = string(a)
	}
	return strings.Join(names, " ")
}

// ErrProof is a proof that does not hold.
var ErrProof = errors.New("invalid DPoP proof")

// Replays remembers the identifiers of the proofs seen within the window,
// so a proof is good for one request.
type Replays struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (r *Replays) first(jti string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[string]time.Time{}
	}
	for k, at := range r.seen {
		if now.Sub(at) > Window+Skew {
			delete(r.seen, k)
		}
	}
	if _, ok := r.seen[jti]; ok {
		return false
	}
	r.seen[jti] = now
	return true
}

type header struct {
	Typ string          `json:"typ"`
	Alg string          `json:"alg"`
	JWK json.RawMessage `json:"jwk"`
}

type claims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath"`
}

type oneKey struct{ key crypto.PublicKey }

func (k oneKey) Key(string) (crypto.PublicKey, error) { return k.key, nil }

// Check verifies a proof for one request and returns the thumbprint of the
// key that made it. accessToken is the token the request presents, or empty
// when the proof comes with a request for one.
func Check(proof, method, url, accessToken string, now time.Time, replays *Replays) (string, error) {
	fail := func(format string, a ...any) (string, error) {
		return "", fmt.Errorf("%w: %s", ErrProof, fmt.Sprintf(format, a...))
	}
	if len(proof) > 8<<10 {
		return fail("the proof is larger than any proof needs to be")
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return fail("a proof is a signed JWT, three segments")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fail("the header is not base64url")
	}
	var h header
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return fail("the header is not JSON")
	}
	if len(h.JWK) == 0 {
		return fail("the header carries no jwk")
	}
	var members map[string]any
	if err := json.Unmarshal(h.JWK, &members); err != nil {
		return fail("the jwk is not an object")
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if _, ok := members[private]; ok {
			return fail("the jwk carries a private key")
		}
	}
	key, err := oidc.PublicKey(h.JWK)
	if err != nil {
		return fail("the jwk is not a usable public key: %v", err)
	}
	payload, err := oidc.VerifyJWS(proof, Algorithms, oneKey{key}, "the client", "a DPoP proof",
		func(t string) bool { return t == "dpop+jwt" })
	if err != nil {
		return fail("%v", err)
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return fail("the claims are not JSON")
	}
	switch {
	case len(c.JTI) < 12 || len(c.JTI) > 256:
		return fail("jti is missing, or not a usable identifier")
	case c.HTM != method:
		return fail("the proof is for %s, this request is %s", c.HTM, method)
	case !sameTarget(c.HTU, url):
		return fail("the proof is for %s, this request is to %s", c.HTU, url)
	case c.IAT == 0:
		return fail("iat is missing")
	case time.Unix(c.IAT, 0).After(now.Add(Skew)):
		return fail("the proof is dated in the future")
	case now.Sub(time.Unix(c.IAT, 0)) > Window:
		return fail("the proof is older than %s", Window)
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if c.ATH != base64.RawURLEncoding.EncodeToString(sum[:]) {
			return fail("ath is not the hash of the token presented")
		}
	}
	thumb, err := Thumbprint(h.JWK)
	if err != nil {
		return fail("%v", err)
	}
	if replays != nil && !replays.first(thumb+"|"+c.JTI, now) {
		return fail("this proof was used before")
	}
	return thumb, nil
}

// sameTarget compares a proof's htu with a request's address, without query
// or fragment, the scheme and host in any case.
func sameTarget(htu, url string) bool {
	cut := func(s string) string {
		if i := strings.IndexAny(s, "?#"); i >= 0 {
			s = s[:i]
		}
		scheme, rest, ok := strings.Cut(s, "://")
		if !ok {
			return s
		}
		host, path, _ := strings.Cut(rest, "/")
		host = strings.ToLower(host)
		host = strings.TrimSuffix(strings.TrimSuffix(host, ":443"), ":80")
		return strings.ToLower(scheme) + "://" + host + "/" + path
	}
	return htu != "" && cut(htu) == cut(url)
}

// Thumbprint is a public JWK's RFC 7638 SHA-256 thumbprint: the required
// members, in order, with no spaces, hashed.
func Thumbprint(raw []byte) (string, error) {
	var k struct {
		Kty, Crv, X, Y, N, E string
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", fmt.Errorf("the jwk is not JSON: %w", err)
	}
	var canonical []byte
	var err error
	switch k.Kty {
	case "EC":
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{k.Crv, k.Kty, k.X, k.Y})
	case "RSA":
		canonical, err = json.Marshal(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{k.E, k.Kty, k.N})
	default:
		return "", fmt.Errorf("a %q key has no thumbprint here", k.Kty)
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// PublicJWK is a key's public half as a JWK.
func PublicJWK(pub crypto.PublicKey) ([]byte, error) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		pad := func(n *big.Int) []byte { return n.FillBytes(make([]byte, size)) }
		return json.Marshal(map[string]string{"kty": "EC", "crv": k.Curve.Params().Name,
			"x": b64(pad(k.X)), "y": b64(pad(k.Y))})
	case *rsa.PublicKey:
		return json.Marshal(map[string]string{"kty": "RSA", "n": b64(k.N.Bytes()),
			"e": b64(big.NewInt(int64(k.E)).Bytes())})
	}
	return nil, fmt.Errorf("a %T key cannot be written as a JWK here", pub)
}

// Prove makes a proof with an EC key for one request, carrying the hash of
// the token when there is one: what a program holding the key sends in its
// DPoP header.
func Prove(key *ecdsa.PrivateKey, method, url, accessToken string, now time.Time) (string, error) {
	alg := map[int]string{256: "ES256", 384: "ES384", 521: "ES512"}[key.Curve.Params().BitSize]
	if alg == "" {
		return "", fmt.Errorf("a key on %s cannot make a proof here", key.Curve.Params().Name)
	}
	pub, err := PublicJWK(&key.PublicKey)
	if err != nil {
		return "", err
	}
	h, err := json.Marshal(header{Typ: "dpop+jwt", Alg: alg, JWK: pub})
	if err != nil {
		return "", err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	c := claims{JTI: base64.RawURLEncoding.EncodeToString(id), HTM: method, HTU: url, IAT: now.Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		c.ATH = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	var digest []byte
	switch alg {
	case "ES256":
		d := sha256.Sum256([]byte(input))
		digest = d[:]
	case "ES384":
		d := sha512.Sum384([]byte(input))
		digest = d[:]
	default:
		d := sha512.Sum512([]byte(input))
		digest = d[:]
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return "", err
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	sig := append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
