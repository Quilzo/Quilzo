// Package httpsig signs and verifies HTTP requests under RFC 9421.
//
// # Why this is its own package
//
// It was written once for Web Bot Auth, which is RFC 9421 applied to crawler
// traffic, and the fediverse needs the same thing for a different reason:
// Mastodon has verified RFC 9421 signatures since 4.5 and emits them since
// 4.7, so an ActivityPub inbox has to check exactly this and a delivery has to
// produce exactly this.
//
// Two consumers of one wire format is where a shared implementation belongs.
// The alternative — a verifier in each — is two things to keep true, and a
// signature checker that drifts is one that starts accepting what it should
// refuse without anybody noticing.
//
// # What is here and what is not
//
// The signature base, the header parsing, signing and verification, over
// Ed25519 and RSA. Both algorithms because the two consumers need different
// ones: Web Bot Auth is Ed25519, and most of the fediverse is still RSA
// because that is what the older draft used and what the installed base has.
//
// Not here: who a key belongs to, whether that identity may do anything, or
// where a key came from. Those are decisions, they differ per consumer, and a
// package that made them would be making them for a caller that had not been
// asked.
//
// # The rule that makes verification mean anything
//
// A covered component that cannot be rebuilt is refused, never skipped.
//
// Skipping one means checking a signature over less than was signed and
// reporting the result as valid — a forgery the verifier performs on itself,
// and the only one it cannot be warned about by anybody else.
package httpsig

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Algorithm names the signing algorithm, using RFC 9421's own registry names.
type Algorithm string

const (
	// Ed25519 is what Web Bot Auth uses and what Mastodon 4.7 verifies.
	Ed25519 Algorithm = "ed25519"
	// RSAPKCS1SHA256 is what most of the fediverse still signs with, because
	// it is what the pre-RFC draft specified.
	RSAPKCS1SHA256 Algorithm = "rsa-v1_5-sha256"
)

// DefaultMaxAge bounds how old a signature may be.
//
// A signature over components that do not change authenticates forever
// without one, so a request captured from a log replays indefinitely.
const DefaultMaxAge = 5 * time.Minute

// PublicKey is a key a signature can be checked against.
type PublicKey struct {
	// ID is the keyid a signature names.
	ID string
	// Alg is what the key signs with. Held rather than read from the
	// signature: an attacker who could choose the algorithm could choose a
	// weaker one, and "the signature said so" is not a reason to believe it.
	Alg Algorithm
	// Ed and RSA hold whichever one Alg names.
	Ed  ed25519.PublicKey
	RSA *rsa.PublicKey
}

// Signed describes a verified signature.
type Signed struct {
	// KeyID is the key that verified it.
	KeyID string
	// Created is when it was made.
	Created time.Time
	// Covered lists the components the signature was over, so a caller can
	// require that something in particular was signed.
	Covered []string
}

// Covers reports whether a component was part of what was signed.
//
// Worth asking. A signature over "@method" alone is a valid signature and
// proves almost nothing about the request it arrived on, so a caller that
// cares about the body has to check the body was covered.
func (s Signed) Covers(component string) bool {
	for _, c := range s.Covered {
		if strings.EqualFold(c, component) {
			return true
		}
	}
	return false
}

// Verify checks a request's signature against a set of known keys.
//
// Returns nil, nil for a request carrying no signature at all — the ordinary
// case for a browser, and not a failure to report.
func Verify(r *http.Request, keys []PublicKey, maxAge time.Duration,
	now time.Time) (*Signed, error) {

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
			"a request is signed and no keys are configured, so it cannot be " +
				"checked. An unverifiable signature is not an identity")
	}

	label, params, err := parseInput(input)
	if err != nil {
		return nil, err
	}
	raw, err := parseSignature(sig, label)
	if err != nil {
		return nil, err
	}

	// Age before cryptography, on a cheap comparison, so replaying a captured
	// request does not cost a verification each time.
	created, err := strconv.ParseInt(params["created"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf(
			"this signature has no usable created time, so its age cannot be " +
				"checked and it has to be refused")
	}
	when := time.Unix(created, 0)
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if age := now.Sub(when); age > maxAge {
		return nil, fmt.Errorf("this signature was made %s ago, limit %s",
			age.Round(time.Second), maxAge)
	}
	if when.Sub(now) > time.Minute {
		return nil, fmt.Errorf("this signature is dated in the future")
	}
	if exp := params["expires"]; exp != "" {
		if s, perr := strconv.ParseInt(exp, 10, 64); perr == nil &&
			now.After(time.Unix(s, 0)) {
			return nil, fmt.Errorf("this signature has expired")
		}
	}

	keyID := params["keyid"]
	if keyID == "" {
		return nil, fmt.Errorf(
			"this signature names no key, so there is nothing to check it with")
	}
	var key *PublicKey
	for i := range keys {
		if keys[i].ID == keyID {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("key %q is not one this server knows", keyID)
	}

	base, covered, err := Base(r, params["components"], input)
	if err != nil {
		return nil, err
	}
	if err := verifyWith(*key, []byte(base), raw); err != nil {
		return nil, err
	}
	return &Signed{KeyID: keyID, Created: when, Covered: covered}, nil
}

// verifyWith checks the bytes against whichever algorithm the key declares.
//
// The key's algorithm, never the signature's. A verifier that took `alg` from
// the message lets the sender choose how their signature is checked, which is
// the algorithm-confusion bug that has been rediscovered in every signature
// format that allowed it.
func verifyWith(key PublicKey, base, sig []byte) error {
	switch key.Alg {
	case Ed25519:
		if key.Ed == nil {
			return fmt.Errorf("key %q declares ed25519 and carries no ed25519 key", key.ID)
		}
		if !ed25519.Verify(key.Ed, base, sig) {
			return fmt.Errorf(
				"the signature does not verify against the key it names")
		}
		return nil
	case RSAPKCS1SHA256:
		if key.RSA == nil {
			return fmt.Errorf("key %q declares RSA and carries no RSA key", key.ID)
		}
		sum := sha256.Sum256(base)
		if err := rsa.VerifyPKCS1v15(key.RSA, crypto.SHA256, sum[:], sig); err != nil {
			return fmt.Errorf(
				"the signature does not verify against the key it names")
		}
		return nil
	}
	return fmt.Errorf("key %q declares algorithm %q, which is not supported",
		key.ID, key.Alg)
}

// Sign adds a signature to an outbound request.
//
// The caller names which components to cover. There is no default, because a
// sensible default here depends entirely on what the receiver checks, and a
// signature that covers less than the receiver requires is refused with a
// message about signatures rather than about coverage.
func Sign(r *http.Request, keyID string, alg Algorithm, key crypto.Signer,
	components []string, now time.Time) error {

	if len(components) == 0 {
		return fmt.Errorf(
			"a signature covering nothing proves nothing; name the components")
	}
	params := fmt.Sprintf(`("%s");created=%d;keyid=%q;alg=%q`,
		strings.Join(components, `" "`), now.Unix(), keyID, alg)
	input := "sig1=" + params

	base, _, err := Base(r, strings.Join(quoteAll(components), " "), input)
	if err != nil {
		return err
	}

	var sig []byte
	switch alg {
	case Ed25519:
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("ed25519 was named and the key is %T", key)
		}
		sig = ed25519.Sign(priv, []byte(base))
	case RSAPKCS1SHA256:
		sum := sha256.Sum256([]byte(base))
		sig, err = key.Sign(rand.Reader, sum[:], crypto.SHA256)
		if err != nil {
			return fmt.Errorf("cannot sign: %w", err)
		}
	default:
		return fmt.Errorf("algorithm %q is not supported", alg)
	}

	r.Header.Set("Signature-Input", input)
	r.Header.Set("Signature",
		"sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = `"` + s + `"`
	}
	return out
}

// Base rebuilds the signature base from a request, and reports what it covered.
//
// This is the whole of the check: if any covered component differs from what
// was signed, the base differs and the signature does not verify.
func Base(r *http.Request, components, input string) (string, []string, error) {
	var b strings.Builder
	var covered []string

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
				return "", nil, fmt.Errorf(
					"this signature covers %q, which this program cannot "+
						"rebuild. Refusing rather than skipping it: a "+
						"signature checked over fewer components than were "+
						"signed is not the signature that was made", name)
			}
			value = r.Header.Get(name)
		}
		fmt.Fprintf(&b, "\"%s\": %s\n", strings.ToLower(name), value)
		covered = append(covered, strings.ToLower(name))
	}

	// The trailing line is the parameters exactly as they arrived. Rebuilding
	// them from a parsed map would let a difference between what was parsed
	// and what was sent pass unnoticed.
	_, rest, _ := strings.Cut(strings.TrimSpace(input), "=")
	fmt.Fprintf(&b, "\"@signature-params\": %s", strings.TrimSpace(rest))
	return b.String(), covered, nil
}

// parseInput reads the Signature-Input header.
//
// Deliberately small. A full structured-fields parser is a lot of code for a
// header shaped, in every implementation that exists, like
//
//	sig1=("@method" "@authority" "@path");created=123;keyid="k1";alg="ed25519"
//
// What it must not do is accept something it half-understood, so every field
// needed is required by the caller rather than defaulted here.
func parseInput(header string) (label string, params map[string]string, err error) {
	label, rest, found := strings.Cut(strings.TrimSpace(header), "=")
	if !found || strings.TrimSpace(label) == "" {
		return "", nil, fmt.Errorf("Signature-Input is not label=value")
	}
	label = strings.TrimSpace(label)

	open := strings.Index(rest, "(")
	shut := strings.Index(rest, ")")
	if open < 0 || shut < open {
		return "", nil, fmt.Errorf("Signature-Input names no covered components")
	}
	params = map[string]string{"components": rest[open+1 : shut]}
	for _, p := range strings.Split(rest[shut+1:], ";") {
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
		value = strings.TrimSuffix(strings.TrimPrefix(value, ":"), ":")
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("the signature is not base64: %w", err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("the signature is empty")
		}
		return raw, nil
	}
	return nil, fmt.Errorf("the Signature header has no entry labelled %q", label)
}
