// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package commerce

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// The merchant's signing key, and the checkout JWT it makes.
//
// AP2 binds a purchase mandate to the merchant's checkout through
// checkout_hash — the hash of a JWT the merchant signs. The specification
// requires that JWT to be signed with a non-deterministic scheme (ECDSA, not
// Ed25519): the hash has to inherit entropy from the signature, or an
// attacker could precompute checkouts for every plausible basket and search
// a stolen mandate's hash against them — the rainbow-table reasoning in the
// protocol's own security considerations.
//
// So the merchant key is ECDSA P-256, and this file never signs anything
// with a scheme that would make the binding searchable.

// MerchantKey is this shop's signing key for checkouts.
type MerchantKey struct {
	Private *ecdsa.PrivateKey
	// KeyID names the key in the JWT header and the discovery document, so
	// an agent that checks a merchant signature knows which key to check.
	KeyID string
}

// GenerateMerchantKey makes a fresh P-256 key with a random id.
func GenerateMerchantKey() (*MerchantKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &MerchantKey{Private: key, KeyID: fmt.Sprintf("mk_%x", id)}, nil
}

// merchantKeyFile is the JWK the key persists as.
type merchantKeyFile struct {
	Kty   string `json:"kty"`
	Crv   string `json:"crv"`
	KeyID string `json:"kid"`
	X     string `json:"x"`
	Y     string `json:"y"`
	D     string `json:"d"`
}

// Save writes the key, private, in its own directory.
func (m *MerchantKey) Save(path string) error {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	size := (m.Private.Curve.Params().BitSize + 7) / 8
	pad := func(n *big.Int) []byte { return n.FillBytes(make([]byte, size)) }
	file := merchantKeyFile{
		Kty: "EC", Crv: "P-256", KeyID: m.KeyID,
		X: b64(pad(m.Private.X)), Y: b64(pad(m.Private.Y)),
		D: b64(pad(m.Private.D)),
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadMerchantKey reads the key file GenerateMerchantKey's Save wrote.
func LoadMerchantKey(path string) (*MerchantKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f merchantKeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s is not a merchant key: %w", path, err)
	}
	if f.Kty != "EC" || f.Crv != "P-256" || f.X == "" || f.Y == "" || f.D == "" {
		return nil, fmt.Errorf("%s is not a complete EC P-256 key", path)
	}
	x, err := base64.RawURLEncoding.DecodeString(f.X)
	if err != nil {
		return nil, fmt.Errorf("%s: x is not base64url", path)
	}
	y, err := base64.RawURLEncoding.DecodeString(f.Y)
	if err != nil {
		return nil, fmt.Errorf("%s: y is not base64url", path)
	}
	d, err := base64.RawURLEncoding.DecodeString(f.D)
	if err != nil {
		return nil, fmt.Errorf("%s: d is not base64url", path)
	}
	curve := elliptic.P256()
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve,
			X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)},
		D: new(big.Int).SetBytes(d),
	}
	if !curve.IsOnCurve(priv.X, priv.Y) {
		return nil, fmt.Errorf("%s: the public half is not a point on P-256", path)
	}
	return &MerchantKey{Private: priv, KeyID: f.KeyID}, nil
}

// PublicJWK is the merchant key's public half as a JWK, for the discovery
// document, so an agent or credential provider can verify this shop's
// checkout JWTs without asking anybody.
func (m *MerchantKey) PublicJWK() map[string]string {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	size := (m.Private.Curve.Params().BitSize + 7) / 8
	pad := func(n *big.Int) []byte { return n.FillBytes(make([]byte, size)) }
	return map[string]string{
		"kty": "EC", "crv": "P-256", "kid": m.KeyID,
		"x": b64(pad(m.Private.X)), "y": b64(pad(m.Private.Y)),
	}
}

// SignCheckout signs the checkout object as a compact JWS.
//
// The payload is the caller's checkout JSON with the standard claims added:
// iss names this shop, jti the checkout's id, iat and exp the session's
// life. The signature is ECDSA over SHA-256, its R and S written raw as
// JOSE requires — the encoding internal/dpop's proofs use, verified by the
// same convention on the other side.
func (m *MerchantKey) SignCheckout(checkout map[string]any, issuer string, now, expires time.Time) (string, error) {
	header := map[string]any{"alg": "ES256", "typ": "checkout+jwt", "kid": m.KeyID}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claims := map[string]any{}
	for k, v := range checkout {
		claims[k] = v
	}
	claims["iss"] = issuer
	claims["iat"] = now.Unix()
	claims["exp"] = expires.Unix()
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	input := b64(h) + "." + b64(p)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, m.Private, digest[:])
	if err != nil {
		return "", err
	}
	size := (m.Private.Curve.Params().BitSize + 7) / 8
	sig := append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	return input + "." + b64(sig), nil
}

// CheckoutHash is the base64url SHA-256 of a checkout JWT — the value a
// checkout mandate's checkout_hash claim must carry, per AP2.
func CheckoutHash(jwt string) string {
	sum := sha256.Sum256([]byte(jwt))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
