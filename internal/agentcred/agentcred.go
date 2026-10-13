// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package agentcred issues and checks agent credentials: what another
// vendor's agent presents to use what Quilzo offers it, in place of a
// person's token.
//
// # What a credential is
//
// A W3C Verifiable Credential 2.0, secured with JOSE as a compact JWS
// (typ "vc+jwt", alg EdDSA) and signed by this store's own issuer key,
// whose public half is published so anybody can check one. It names the
// agent, the person who answers for it, the one grant it may use, whether
// it may act or only read, when it is valid, and the agent's own public
// key: the credential is bound to that key, and is worth nothing to
// whoever copies it without the key.
//
// # Presenting one
//
// With every request, a proof: a compact JWS (typ "agent-proof+jwt")
// signed by the agent's key, naming the method and the address it is for,
// when it was made, a one-time identifier, and a digest of the credential
// it goes with. A proof is accepted once, within a minute of being made,
// for exactly that request. The shape is DPoP's (RFC 9449), bound to a
// credential rather than to an access token.
//
// Standard library only: Ed25519, SHA-256, JSON and base64url, plus the
// base58btc that did:key needs.
package agentcred

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Bounds.
const (
	// MaxValid is the longest a credential is issued for.
	MaxValid = 30 * 24 * time.Hour
	// ProofWindow is how far a proof's time may be from now, either way.
	ProofWindow = 60 * time.Second
	// MaxToken bounds a credential or proof as presented.
	MaxToken = 8 << 10
)

// Credential is what a credential says, once checked.
type Credential struct {
	ID         string
	Issuer     string
	Agent      string
	Sponsor    string
	Grant      string
	Act        bool
	Holder     ed25519.PublicKey
	ValidFrom  time.Time
	ValidUntil time.Time
	// Hash is the digest a proof names it by.
	Hash string
}

var (
	reName  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
	reGrant = regexp.MustCompile(`^browser:[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// vc is the credential's payload: a VC 2.0 document, with the holder's
// key confirmed as RFC 7800 does.
type vc struct {
	Context    []string  `json:"@context"`
	Type       []string  `json:"type"`
	ID         string    `json:"id"`
	Issuer     string    `json:"issuer"`
	ValidFrom  string    `json:"validFrom"`
	ValidUntil string    `json:"validUntil"`
	Subject    vcSubject `json:"credentialSubject"`
	Cnf        cnf       `json:"cnf"`
}

type vcSubject struct {
	ID      string `json:"id"`
	Agent   string `json:"agent"`
	Sponsor string `json:"sponsor"`
	Grant   string `json:"grant"`
	Act     bool   `json:"act,omitempty"`
}

type cnf struct {
	JWK jwk `json:"jwk"`
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid,omitempty"`
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

var b64 = base64.RawURLEncoding

// sign makes a compact JWS.
func sign(key ed25519.PrivateKey, h header, payload any) (string, error) {
	hb, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	in := b64.EncodeToString(hb) + "." + b64.EncodeToString(pb)
	return in + "." + b64.EncodeToString(ed25519.Sign(key, []byte(in))), nil
}

// open splits and decodes a compact JWS, without checking its signature.
func open(token string) (header, []byte, []byte, string, error) {
	var h header
	if len(token) > MaxToken {
		return h, nil, nil, "", errors.New("longer than a credential or proof is")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return h, nil, nil, "", errors.New("not a compact JWS")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return h, nil, nil, "", errors.New("its header is not base64url")
	}
	dec := json.NewDecoder(strings.NewReader(string(hb)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return h, nil, nil, "", errors.New("its header is not one this reads")
	}
	if h.Alg != "EdDSA" {
		return h, nil, nil, "", fmt.Errorf("signed with %q, and only EdDSA is accepted", h.Alg)
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return h, nil, nil, "", errors.New("its payload is not base64url")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return h, nil, nil, "", errors.New("its signature is not one")
	}
	return h, pb, sig, parts[0] + "." + parts[1], nil
}

// KeyID is how an issuer key is named: the first sixteen hex digits of
// the SHA-256 of the public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// JWKS is the issuer's public keys as a JSON Web Key Set, to publish.
func JWKS(keys ...ed25519.PublicKey) ([]byte, error) {
	set := struct {
		Keys []jwk `json:"keys"`
	}{}
	for _, k := range keys {
		set.Keys = append(set.Keys, jwk{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(k), Kid: KeyID(k)})
	}
	return json.MarshalIndent(set, "", "  ")
}

// Issue signs a credential.
func Issue(key ed25519.PrivateKey, issuer string, c Credential, now time.Time) (string, error) {
	switch {
	case !reName.MatchString(c.Agent):
		return "", fmt.Errorf("%q is not an agent's name", c.Agent)
	case strings.TrimSpace(c.Sponsor) == "":
		return "", errors.New("a credential names the person who answers for the agent")
	case !reGrant.MatchString(c.Grant):
		return "", fmt.Errorf("%q is not a grant a credential may carry (browser:NAME)", c.Grant)
	case len(c.Holder) != ed25519.PublicKeySize:
		return "", errors.New("a credential is bound to the agent's own Ed25519 key")
	case !c.ValidUntil.After(now) || c.ValidUntil.Sub(now) > MaxValid:
		return "", fmt.Errorf("a credential is valid for up to %s", MaxValid)
	}
	if c.ID == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		c.ID = "urn:uuid:" + fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	}
	pub := key.Public().(ed25519.PublicKey)
	doc := vc{
		Context:    []string{"https://www.w3.org/ns/credentials/v2"},
		Type:       []string{"VerifiableCredential", "AgentCredential"},
		ID:         c.ID,
		Issuer:     issuer,
		ValidFrom:  now.UTC().Format(time.RFC3339),
		ValidUntil: c.ValidUntil.UTC().Format(time.RFC3339),
		Subject: vcSubject{ID: DIDKey(c.Holder), Agent: c.Agent, Sponsor: c.Sponsor,
			Grant: c.Grant, Act: c.Act},
		Cnf: cnf{JWK: jwk{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(c.Holder)}},
	}
	return sign(key, header{Alg: "EdDSA", Typ: "vc+jwt", Kid: KeyID(pub)}, doc)
}

// Verify checks a credential's signature against the issuer's keys and its
// validity at now, and says what it holds.
func Verify(token string, keys map[string]ed25519.PublicKey, now time.Time) (Credential, error) {
	var c Credential
	h, pb, sig, signed, err := open(token)
	if err != nil {
		return c, err
	}
	if h.Typ != "vc+jwt" {
		return c, errors.New("not an agent credential (typ vc+jwt)")
	}
	pub, ok := keys[h.Kid]
	if !ok {
		return c, fmt.Errorf("signed with key %q, which this store did not issue", h.Kid)
	}
	if !ed25519.Verify(pub, []byte(signed), sig) {
		return c, errors.New("its signature does not verify")
	}
	var doc vc
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return c, errors.New("its payload is not an agent credential")
	}
	if len(doc.Type) != 2 || doc.Type[1] != "AgentCredential" {
		return c, errors.New("not an agent credential")
	}
	from, ferr := time.Parse(time.RFC3339, doc.ValidFrom)
	until, uerr := time.Parse(time.RFC3339, doc.ValidUntil)
	switch {
	case ferr != nil || uerr != nil:
		return c, errors.New("its validity is not dates")
	case now.Before(from.Add(-ProofWindow)):
		return c, errors.New("it is not valid yet")
	case !now.Before(until):
		return c, errors.New("it has expired")
	case until.Sub(from) > MaxValid:
		return c, errors.New("it claims a validity longer than any credential is issued for")
	}
	holder, err := b64.DecodeString(doc.Cnf.JWK.X)
	if err != nil || len(holder) != ed25519.PublicKeySize || doc.Cnf.JWK.Kty != "OKP" || doc.Cnf.JWK.Crv != "Ed25519" {
		return c, errors.New("it is bound to no Ed25519 key")
	}
	if doc.Subject.ID != DIDKey(holder) {
		return c, errors.New("its subject and its bound key disagree")
	}
	if !reName.MatchString(doc.Subject.Agent) || !reGrant.MatchString(doc.Subject.Grant) || doc.Subject.Sponsor == "" {
		return c, errors.New("it names no agent, sponsor or grant this reads")
	}
	sum := sha256.Sum256([]byte(token))
	return Credential{ID: doc.ID, Issuer: doc.Issuer, Agent: doc.Subject.Agent, Sponsor: doc.Subject.Sponsor,
		Grant: doc.Subject.Grant, Act: doc.Subject.Act, Holder: holder, ValidFrom: from, ValidUntil: until,
		Hash: b64.EncodeToString(sum[:])}, nil
}

// proof is what a request's proof says.
type proof struct {
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
	Ath string `json:"ath"`
}

// Prove makes the proof for one request, signed by the agent's key.
func Prove(holder ed25519.PrivateKey, credential, method, url string, now time.Time) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(credential))
	return sign(holder, header{Alg: "EdDSA", Typ: "agent-proof+jwt"}, proof{
		Htm: strings.ToUpper(method), Htu: url, Iat: now.Unix(), Jti: hex.EncodeToString(b[:]),
		Ath: b64.EncodeToString(sum[:])})
}

// Replays remembers the proofs already accepted, for as long as one could
// be presented again.
type Replays struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// first reports whether jti is new, and remembers it.
func (r *Replays) first(jti string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[string]time.Time{}
	}
	for k, at := range r.seen {
		if now.Sub(at) > 2*ProofWindow {
			delete(r.seen, k)
		}
	}
	if _, ok := r.seen[jti]; ok {
		return false
	}
	if len(r.seen) >= 1<<16 {
		return false
	}
	r.seen[jti] = now
	return true
}

// CheckProof checks a request's proof against the credential it goes
// with: signed by the credential's bound key, for this method and
// address, made within the window, naming this credential, and never seen
// before.
func CheckProof(c Credential, token, method, url string, now time.Time, replays *Replays) error {
	h, pb, sig, signed, err := open(token)
	if err != nil {
		return fmt.Errorf("the proof: %w", err)
	}
	if h.Typ != "agent-proof+jwt" {
		return errors.New("the proof is not one (typ agent-proof+jwt)")
	}
	if !ed25519.Verify(c.Holder, []byte(signed), sig) {
		return errors.New("the proof is not signed by the key the credential is bound to")
	}
	var p proof
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return errors.New("the proof's payload is not one this reads")
	}
	at := time.Unix(p.Iat, 0)
	switch {
	case p.Ath != c.Hash:
		return errors.New("the proof is for another credential")
	case !strings.EqualFold(p.Htm, method):
		return fmt.Errorf("the proof is for %s, and this is %s", p.Htm, method)
	case p.Htu != url:
		return errors.New("the proof is for another address")
	case at.Before(now.Add(-ProofWindow)) || at.After(now.Add(ProofWindow)):
		return errors.New("the proof was not made within a minute of now")
	case len(p.Jti) < 16:
		return errors.New("the proof has no one-time identifier")
	case replays == nil || !replays.first(p.Jti, now):
		return errors.New("the proof was seen before")
	}
	return nil
}

// DIDKey is an Ed25519 public key as a did:key.
func DIDKey(pub ed25519.PublicKey) string {
	return "did:key:z" + base58(append([]byte{0xed, 0x01}, pub...))
}

// PublicFromDIDKey reads an Ed25519 did:key back.
func PublicFromDIDKey(did string) (ed25519.PublicKey, error) {
	rest, ok := strings.CutPrefix(did, "did:key:z")
	if !ok {
		return nil, errors.New("not a did:key in base58btc")
	}
	b, err := unbase58(rest)
	if err != nil || len(b) != 2+ed25519.PublicKeySize || b[0] != 0xed || b[1] != 0x01 {
		return nil, errors.New("not an Ed25519 did:key")
	}
	return ed25519.PublicKey(b[2:]), nil
}

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58(in []byte) string {
	zeros := 0
	for zeros < len(in) && in[zeros] == 0 {
		zeros++
	}
	digits := []byte{}
	for _, b := range in[zeros:] {
		carry := int(b)
		for i := range digits {
			carry += int(digits[i]) << 8
			digits[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	out := strings.Repeat("1", zeros)
	for i := len(digits) - 1; i >= 0; i-- {
		out += string(alphabet[digits[i]])
	}
	return out
}

func unbase58(s string) ([]byte, error) {
	if len(s) > 128 {
		return nil, errors.New("too long")
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	bytes := []byte{}
	for _, r := range s[zeros:] {
		v := strings.IndexRune(alphabet, r)
		if v < 0 {
			return nil, fmt.Errorf("%q is not base58", r)
		}
		carry := v
		for i := range bytes {
			carry += int(bytes[i]) * 58
			bytes[i] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			bytes = append(bytes, byte(carry&0xff))
			carry >>= 8
		}
	}
	out := make([]byte, zeros, zeros+len(bytes))
	for i := len(bytes) - 1; i >= 0; i-- {
		out = append(out, bytes[i])
	}
	return out, nil
}
