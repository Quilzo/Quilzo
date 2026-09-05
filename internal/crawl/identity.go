package crawl

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/httpsig"
)

// Proving which crawler is asking, rather than believing a header.
//
// # Web Bot Auth, and what of it is implemented here
//
// The scheme is RFC 9421 HTTP Message Signatures with Ed25519: the crawler
// signs a set of request components, names the key it used, and publishes the
// public key at a directory it controls. The verifier rebuilds the same
// signature base from the request it received and checks it.
//
// Two IETF drafts sit on top of that — one for the key directory, one for the
// crawler-identity fields — and neither is working-group adopted as of
// September 2026. So this implements the part that is settled, RFC 9421 itself,
// and treats the draft-specific fields as data rather than as a contract.
//
// # Keys are supplied, not fetched
//
// A verifier that resolves a key by fetching a URL out of the request it is
// verifying will fetch whatever an attacker names — the same shape as any
// other server-side request forgery, arriving on the one path that runs before
// anybody is authenticated.
//
// So the operator configures which crawlers are known and what their keys are.
// That is more work for them and it is the honest amount: trusting a crawler
// is a decision, and a decision made by whoever configured it is auditable in
// a way that one made by following a link is not.
//
// # The signature itself lives elsewhere
//
// RFC 9421 is not a crawler thing. The fediverse needs the same verification
// for a different reason — Mastodon has verified RFC 9421 signatures since 4.5
// — so the parsing, the signature base and the cryptography are in
// internal/httpsig and this package holds what is specific to crawling: which
// crawlers are known, and what they say they want the content for.

// MaxSignatureAge bounds how old a signed request may be.
//
// A signature over components that do not change authenticates forever without
// one, so a request captured from a log replays indefinitely. Five minutes
// matches what every other signed surface in this program uses.
const MaxSignatureAge = 5 * time.Minute

// Key is a crawler's published verification key.
type Key struct {
	// Name is who this is, for the log and the terms — "ExampleBot".
	Name string
	// ID is the keyid the crawler names in its signature input.
	ID string
	// Public is the Ed25519 key, already decoded.
	Public ed25519.PublicKey
}

// Identity is a crawler that proved who it is.
type Identity struct {
	// Name is the configured name of the key that verified.
	Name string
	// Use is what it says it wants the content for, if it said.
	Use Use
	// Signed is when the signature was made.
	Signed time.Time
}

// Verify checks a Web Bot Auth signature and returns who signed it.
//
// Returns nil with no error for a request that carries no signature at all,
// which is the ordinary case: a person's browser signs nothing, and that is
// not a failure to report.
func Verify(r *http.Request, keys []Key, now time.Time) (*Identity, error) {
	pub := make([]httpsig.PublicKey, 0, len(keys))
	for _, k := range keys {
		pub = append(pub, httpsig.PublicKey{
			ID: k.ID, Alg: httpsig.Ed25519, Ed: k.Public,
		})
	}

	signed, err := httpsig.Verify(r, pub, MaxSignatureAge, now)
	if err != nil {
		return nil, err
	}
	if signed == nil {
		return nil, nil
	}
	// The signature has to name the server it was sent to.
	//
	// Without this a crawler's signature over, say, one header authenticates
	// that crawler anywhere: capture one from a proxy and replay it against
	// another site for as long as the age window allows, and the terms are
	// enforced against the wrong identity. An identity that does not name what
	// it is an identity for is a header again.
	//
	// Destination only, deliberately. Web Bot Auth requires an agent to cover
	// at least one of @authority or @target-uri and no more, and real crawlers
	// sign ("@authority" "signature-agent"); demanding @method here would
	// refuse every one of them while adding nothing -- it is the destination,
	// not the verb, that stops a captured signature being pointed elsewhere.
	if !signed.CoversDestination() {
		return nil, fmt.Errorf(
			"this signature names no destination, so it identifies a key " +
				"rather than a request to this server. Sign @authority or " +
				"@target-uri, as Web Bot Auth requires")
	}

	name := signed.KeyID
	for _, k := range keys {
		if k.ID == signed.KeyID {
			name = k.Name
			break
		}
	}
	return &Identity{Name: name, Use: declaredUse(r), Signed: signed.Created}, nil
}

// declaredUse reads what the crawler says it wants the content for.
//
// Draft fields, so they are read leniently and their absence is not an error:
// the identity is established by the signature, and the purpose is a claim on
// top of it. A crawler that lies about its purpose has still identified
// itself, which is the part that makes the terms actionable.
func declaredUse(r *http.Request) Use {
	for _, name := range []string{"Crawler-Purpose", "Signature-Agent-Purpose"} {
		switch strings.ToLower(strings.TrimSpace(r.Header.Get(name))) {
		case "search", "index", "indexing":
			return Search
		case "train", "training", "ai-train":
			return Train
		case "ai-summarize", "summarize", "summarise", "inference":
			return Summarize
		}
	}
	return Unstated
}

// ParseKey decodes a configured crawler key.
//
// base64 or hex, because both appear in the wild and an operator copying a key
// out of a crawler's documentation should not have to know which they have.
func ParseKey(name, id, encoded string) (Key, error) {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(id) == "" {
		return Key{}, fmt.Errorf("a crawler key needs a name and a key id")
	}
	raw, err := decodeKey(strings.TrimSpace(encoded))
	if err != nil {
		return Key{}, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return Key{}, fmt.Errorf(
			"%s: the key is %d bytes and an Ed25519 public key is %d",
			name, len(raw), ed25519.PublicKeySize)
	}
	return Key{Name: name, ID: id, Public: ed25519.PublicKey(raw)}, nil
}

func decodeKey(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		hexDecode,
	} {
		if raw, err := dec(s); err == nil && len(raw) == ed25519.PublicKeySize {
			return raw, nil
		}
	}
	return nil, fmt.Errorf(
		"the key is not base64 or hex, or is not %d bytes once decoded",
		ed25519.PublicKeySize)
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		n, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(n)
	}
	return out, nil
}
