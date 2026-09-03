package crawl

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
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
	input := r.Header.Get("Signature-Input")
	sig := r.Header.Get("Signature")
	if input == "" && sig == "" {
		return nil, nil
	}
	if input == "" || sig == "" {
		return nil, fmt.Errorf(
			"this request carries one half of a signature. Signature-Input " +
				"and Signature are both required, and half of a proof is not " +
				"a weaker proof, it is none")
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf(
			"a request is signed and no crawler keys are configured, so it " +
				"cannot be checked. Refusing to guess: an unverifiable " +
				"signature is not an identity")
	}

	label, params, err := parseInput(input)
	if err != nil {
		return nil, err
	}
	raw, err := parseSignature(sig, label)
	if err != nil {
		return nil, err
	}

	// Age before cryptography, on a cheap comparison, so a replayed capture
	// does not cost a verification each time.
	created, err := strconv.ParseInt(params["created"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf(
			"this signature has no usable created time, so its age cannot be " +
				"checked and it has to be refused")
	}
	signed := time.Unix(created, 0)
	if age := now.Sub(signed); age > MaxSignatureAge {
		return nil, fmt.Errorf(
			"this signature was made %s ago and the limit is %s",
			age.Round(time.Second), MaxSignatureAge)
	}
	if signed.Sub(now) > time.Minute {
		return nil, fmt.Errorf("this signature is dated in the future")
	}
	if exp := params["expires"]; exp != "" {
		if seconds, perr := strconv.ParseInt(exp, 10, 64); perr == nil &&
			now.After(time.Unix(seconds, 0)) {
			return nil, fmt.Errorf("this signature has expired")
		}
	}

	keyID := params["keyid"]
	if keyID == "" {
		return nil, fmt.Errorf(
			"this signature names no key, so there is nothing to check it with")
	}
	var key *Key
	for i := range keys {
		if keys[i].ID == keyID {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf(
			"this request is signed by key %q, which is not a crawler this "+
				"site has been told about", keyID)
	}

	base, err := signatureBase(r, params["components"], input, label)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key.Public, []byte(base), raw) {
		return nil, fmt.Errorf(
			"the signature does not verify against the key it names. Either " +
				"the request was altered, or it was not signed by that crawler")
	}

	return &Identity{
		Name:   key.Name,
		Use:    declaredUse(r),
		Signed: signed,
	}, nil
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

// parseInput reads the Signature-Input header.
//
// Deliberately small. A full structured-fields parser is a lot of code for a
// header shaped, in every implementation that exists, like:
//
//	sig1=("@method" "@authority" "@path");created=123;keyid="k1";alg="ed25519"
//
// What it must not do is accept something it half-understood: every field it
// needs is required below, so an unparsed one is a refusal rather than a
// default.
func parseInput(header string) (label string, params map[string]string, err error) {
	label, rest, found := strings.Cut(strings.TrimSpace(header), "=")
	if !found || strings.TrimSpace(label) == "" {
		return "", nil, fmt.Errorf("Signature-Input is not label=value")
	}
	label = strings.TrimSpace(label)

	open := strings.Index(rest, "(")
	close := strings.Index(rest, ")")
	if open < 0 || close < open {
		return "", nil, fmt.Errorf(
			"Signature-Input names no covered components")
	}
	params = map[string]string{"components": rest[open+1 : close]}

	for _, p := range strings.Split(rest[close+1:], ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			continue
		}
		params[strings.ToLower(strings.TrimSpace(k))] =
			strings.Trim(strings.TrimSpace(v), `"`)
	}
	return label, params, nil
}

// parseSignature pulls the bytes for this label out of the Signature header.
func parseSignature(header, label string) ([]byte, error) {
	for _, part := range strings.Split(header, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.TrimSpace(name) != label {
			continue
		}
		value = strings.TrimSpace(value)
		// Byte sequences are wrapped in colons in structured fields.
		value = strings.TrimSuffix(strings.TrimPrefix(value, ":"), ":")
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("the signature is not base64: %w", err)
		}
		if len(raw) != ed25519.SignatureSize {
			return nil, fmt.Errorf(
				"the signature is %d bytes and an Ed25519 one is %d",
				len(raw), ed25519.SignatureSize)
		}
		return raw, nil
	}
	return nil, fmt.Errorf("the Signature header has no entry labelled %q", label)
}

// signatureBase rebuilds what the crawler signed, from the request received.
//
// This is the whole of the check: if the request was altered in any covered
// component, the base differs and the signature does not verify. Components
// this program does not understand are refused rather than skipped — skipping
// one would mean verifying a signature over less than the crawler signed, and
// reporting that as a valid proof.
func signatureBase(r *http.Request, components, input, label string) (string, error) {
	var b strings.Builder
	for _, raw := range strings.Fields(components) {
		name := strings.Trim(raw, `"`)
		var value string
		switch strings.ToLower(name) {
		case "@method":
			value = r.Method
		case "@authority":
			value = r.Host
		case "@path":
			value = r.URL.EscapedPath()
		case "@query":
			value = "?" + r.URL.RawQuery
		case "@target-uri":
			value = r.URL.String()
		default:
			if strings.HasPrefix(name, "@") {
				return "", fmt.Errorf(
					"this signature covers %q, which this program does not "+
						"know how to rebuild. Refusing rather than skipping "+
						"it: a signature checked over fewer components than "+
						"were signed is not the signature that was made", name)
			}
			value = r.Header.Get(name)
		}
		fmt.Fprintf(&b, "\"%s\": %s\n", strings.ToLower(name), value)
	}

	// The trailing @signature-params line, which is the parameters exactly as
	// they arrived. Rebuilding them from the parsed map would let a difference
	// between what was parsed and what was sent pass unnoticed.
	_, rest, _ := strings.Cut(strings.TrimSpace(input), "=")
	fmt.Fprintf(&b, "\"@signature-params\": %s", strings.TrimSpace(rest))
	return b.String(), nil
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
