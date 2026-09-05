package webauthn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Passkeys, verified here rather than taken on trust.
//
// # What a passkey actually proves
//
// The authenticator holds a private key it will not release, and signs a
// challenge this server generated. So a signature proves three things at once:
// somebody holds the key, they were present when it was used, and the browser
// believed it was talking to this origin. The third is the one that matters
// most and is the one nothing else on a login form provides -- a passkey
// cannot be phished onto another site, because the browser will not offer it
// to another site.
//
// None of that survives a verifier that skips a check. The list below is not
// defensive programming; each item is an attack that works if it is missing.
//
// # No CBOR, deliberately
//
// The usual WebAuthn server parses a CBOR attestation object to find the
// public key. Browsers have exposed getPublicKey() and getAuthenticatorData()
// for years, which hand over SPKI DER and the raw authenticator data -- both
// of which the standard library already reads. So this parses no CBOR at all,
// which removes the largest piece of attacker-facing parsing from a login
// path.
//
// The cost is honest and small: getPublicKey() returns null for an algorithm
// the browser cannot express that way, and this refuses such a registration
// rather than guessing. It is the same set of algorithms in practice.
//
// # No attestation
//
// This does not ask an authenticator to prove what make and model it is.
// Attestation answers "is this an approved brand of key", which is a question
// an enterprise with a hardware inventory asks. Asking it here would mean
// shipping and maintaining a root list to reject somebody's phone, and the
// phone is the point.

// COSE algorithm identifiers, which is how a browser reports what it signed
// with. Named because a bare -7 in a comparison is unreadable.
const (
	AlgES256 = -7   // ECDSA with P-256 and SHA-256
	AlgEdDSA = -8   // Ed25519
	AlgRS256 = -257 // RSASSA-PKCS1-v1_5 with SHA-256
)

// Authenticator data flags, from the WebAuthn specification.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
)

// authDataMinimum is rpIdHash (32) + flags (1) + signCount (4).
const authDataMinimum = 37

// Credential is a registered passkey.
//
// The public key is kept as SPKI DER exactly as the browser produced it, and
// parsed on each use. Storing a parsed key would mean storing this program's
// interpretation of those bytes, and the bytes are the thing that was actually
// registered.
type Credential struct {
	// ID is the raw credential id the authenticator assigned.
	ID []byte `json:"id"`
	// PublicKey is SPKI DER, from the browser's getPublicKey().
	PublicKey []byte `json:"public_key"`
	// Algorithm is the COSE identifier the browser reported.
	Algorithm int `json:"algorithm"`
	// SignCount is the authenticator's counter as of the last use. Zero means
	// the authenticator does not keep one, which is common and not a fault.
	SignCount uint32 `json:"sign_count"`

	// Principal is who this signs in as. A passkey is a credential, and a
	// credential without a subject authenticates nobody.
	Principal string `json:"principal"`
	// Label is what a person calls this key, so a list of three is a list of
	// three things rather than three hashes.
	Label     string `json:"label"`
	CreatedAt int64  `json:"created_at"`
	LastUsed  int64  `json:"last_used,omitempty"`

	// AAGUID is the authenticator's make and model as it reported itself at
	// enrolment, and Identified says whether it reported one at all.
	//
	// Recorded even when no policy required it, because the useful question
	// later is "which of these are hardware keys" and it cannot be answered
	// retrospectively: the authenticator only says at registration.
	AAGUID     string `json:"aaguid,omitempty"`
	Identified bool   `json:"identified,omitempty"`
}

// Registration is what a browser sends after creating a credential.
//
// Every field arrives base64url encoded, because JSON has no byte string and
// the alternative is somebody choosing an encoding per field.
type Registration struct {
	ID                string `json:"id"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	PublicKey         string `json:"publicKey"`
	Algorithm         int    `json:"algorithm"`
}

// Assertion is what a browser sends when signing in.
type Assertion struct {
	ID                string `json:"id"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
}

// Party is the server this is all happening on.
type Party struct {
	// ID is the relying party identifier: the registrable domain. A passkey is
	// bound to it, and it is what stops a credential being usable elsewhere.
	ID string
	// Origin is the exact origin the browser must report, scheme and port
	// included. Checked as a string rather than derived from ID, because
	// "close enough" here is the phishing defence.
	Origin string
	// Enrol constrains which authenticators may register.
	//
	// Empty by default, which is the behaviour described above: any
	// authenticator, no attestation, the phone included. A deployment at AAL3
	// fills it in — see attestation.go for what that does and does not prove.
	Enrol Enrolment
	// RequireUserVerification demands a PIN, fingerprint or face rather than
	// mere presence. Off by default: presence alone still proves possession
	// and origin, and demanding verification from an authenticator that cannot
	// do it locks somebody out of their own account.
	RequireUserVerification bool
}

// clientData is the browser's account of what it was asked to do.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
	// CrossOrigin is true when the ceremony happened inside a frame from
	// another origin, which for a sign-in is never what was wanted.
	CrossOrigin bool `json:"crossOrigin"`
}

// Register checks a new credential and returns it.
func (p Party) Register(challenge string, reg Registration) (Credential, error) {
	raw, err := decodeAll(map[string]string{
		"credential id":      reg.ID,
		"client data":        reg.ClientDataJSON,
		"authenticator data": reg.AuthenticatorData,
		"public key":         reg.PublicKey,
	})
	if err != nil {
		return Credential{}, err
	}

	if err := p.checkClientData(raw["client data"], "webauthn.create",
		challenge); err != nil {
		return Credential{}, err
	}
	count, err := p.checkAuthenticatorData(raw["authenticator data"])
	if err != nil {
		return Credential{}, err
	}

	// The key has to be one this program can actually check a signature with.
	// Storing a key it cannot verify against would produce a passkey that
	// registers and then fails at every sign-in.
	key, err := x509.ParsePKIXPublicKey(raw["public key"])
	if err != nil {
		return Credential{}, fmt.Errorf(
			"the browser sent a public key this cannot read: %w", err)
	}
	if err := matchAlgorithm(key, reg.Algorithm); err != nil {
		return Credential{}, err
	}

	if len(raw["credential id"]) == 0 {
		return Credential{}, fmt.Errorf("the credential has no id")
	}

	// Which authenticator this is, when the deployment cares.
	//
	// Read from the registration only: an assertion's authenticator data
	// stops after the counter, so the model is recorded at enrolment and
	// never re-checked. That is the right shape — a credential cannot move to
	// a different authenticator.
	id, identified := AAGUIDOf(raw["authenticator data"])
	if err := p.Enrol.Check(id, identified); err != nil {
		return Credential{}, err
	}

	return Credential{
		ID: raw["credential id"], PublicKey: raw["public key"],
		Algorithm: reg.Algorithm, SignCount: count,
		AAGUID: id.String(), Identified: identified,
	}, nil
}

// Verify checks an assertion against a stored credential.
//
// Returns the authenticator's new signature counter, which the caller must
// store: the clone check below is only as good as the number it compares to.
func (p Party) Verify(cred Credential, challenge string, a Assertion) (uint32, error) {
	raw, err := decodeAll(map[string]string{
		"credential id":      a.ID,
		"client data":        a.ClientDataJSON,
		"authenticator data": a.AuthenticatorData,
		"signature":          a.Signature,
	})
	if err != nil {
		return 0, err
	}

	// The credential the browser used has to be the one being checked.
	// Without this, an assertion made with any registered key verifies as any
	// other -- the caller looked one up by id, and nothing tied the answer to
	// what actually signed.
	if subtle.ConstantTimeCompare(raw["credential id"], cred.ID) != 1 {
		return 0, fmt.Errorf(
			"this assertion was made with a different credential than the one " +
				"it names")
	}

	if err := p.checkClientData(raw["client data"], "webauthn.get",
		challenge); err != nil {
		return 0, err
	}
	count, err := p.checkAuthenticatorData(raw["authenticator data"])
	if err != nil {
		return 0, err
	}

	// What WebAuthn signs: the authenticator data, then a hash of the client
	// data. Both, in that order. Signing only the challenge would leave the
	// flags and the counter unauthenticated, which is where user presence and
	// the clone check live.
	sum := sha256.Sum256(raw["client data"])
	signed := append(append([]byte{}, raw["authenticator data"]...), sum[:]...)

	key, err := x509.ParsePKIXPublicKey(cred.PublicKey)
	if err != nil {
		return 0, fmt.Errorf("the stored public key cannot be read: %w", err)
	}
	if err := verifySignature(key, cred.Algorithm, signed, raw["signature"]); err != nil {
		return 0, err
	}

	// A counter that has not advanced is the one signal WebAuthn gives that a
	// credential may have been copied off its authenticator: a clone and the
	// original both count up from the value they were copied at, so the second
	// one to be used reports a number that has already been seen.
	//
	// Only meaningful when the authenticator keeps a counter at all. Many do
	// not, and report zero forever -- refusing those would refuse most phones.
	if cred.SignCount != 0 && count != 0 && count <= cred.SignCount {
		return 0, fmt.Errorf(
			"this authenticator's counter went from %d to %d, which it cannot "+
				"do unless the credential exists in two places. Refusing, and "+
				"the key should be removed and registered again",
			cred.SignCount, count)
	}
	return count, nil
}

// checkClientData is the phishing defence, and every line of it is load-bearing.
func (p Party) checkClientData(body []byte, wantType, challenge string) error {
	var cd clientData
	if err := json.Unmarshal(body, &cd); err != nil {
		return fmt.Errorf("the browser's client data is not JSON: %w", err)
	}

	// The ceremony has to be the one that was asked for. Without this a
	// registration signature can be replayed as a sign-in: both are signatures
	// over a challenge by the same key, and only this field separates them.
	if cd.Type != wantType {
		return fmt.Errorf("this is a %q ceremony and %q was expected",
			cd.Type, wantType)
	}

	// The challenge has to be the one this server issued, compared in constant
	// time. It is the proof of freshness: without it a captured assertion
	// signs somebody in forever.
	if challenge == "" {
		return fmt.Errorf("no challenge was issued for this ceremony, so " +
			"nothing here is evidence of freshness")
	}
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(challenge)) != 1 {
		return fmt.Errorf("this signature answers a different challenge")
	}

	// The origin the browser reported has to be this one, exactly. This is the
	// property that makes a passkey unphishable, and it is a string comparison
	// -- any loosening of it, a suffix match or an ignored port, is the whole
	// defence given away.
	if cd.Origin != p.Origin {
		return fmt.Errorf(
			"the browser says it was talking to %q and this server is %q",
			cd.Origin, p.Origin)
	}
	if cd.CrossOrigin {
		return fmt.Errorf("this ceremony happened inside a frame from another " +
			"origin, which is not how somebody signs in")
	}
	return nil
}

// checkAuthenticatorData verifies what the authenticator itself asserted, and
// returns its signature counter.
func (p Party) checkAuthenticatorData(data []byte) (uint32, error) {
	if len(data) < authDataMinimum {
		return 0, fmt.Errorf(
			"the authenticator data is %d bytes and the fixed part is %d",
			len(data), authDataMinimum)
	}

	// The relying party the authenticator believed it was serving. A
	// credential is bound to this hash, so a mismatch means the key belongs to
	// a different site.
	want := sha256.Sum256([]byte(p.ID))
	if subtle.ConstantTimeCompare(data[:32], want[:]) != 1 {
		return 0, fmt.Errorf(
			"this credential is bound to a different site than %q", p.ID)
	}

	flags := data[32]
	// User presence: somebody touched it. Without this a key plugged into a
	// compromised machine can be used silently, whenever the attacker likes.
	if flags&flagUserPresent == 0 {
		return 0, fmt.Errorf("the authenticator does not report that anybody " +
			"was present, so this may be a key being used without its owner")
	}
	if p.RequireUserVerification && flags&flagUserVerified == 0 {
		return 0, fmt.Errorf(
			"this server requires a PIN, fingerprint or face and the " +
				"authenticator reported only that a key was touched")
	}

	return uint32(data[33])<<24 | uint32(data[34])<<16 |
		uint32(data[35])<<8 | uint32(data[36]), nil
}

// matchAlgorithm refuses a key whose type is not the one the browser claimed.
//
// The algorithm decides which verification is applied, so believing a claim
// that does not match the key is how a verifier ends up checking the wrong
// thing -- or checking nothing.
func matchAlgorithm(key any, alg int) error {
	switch alg {
	case AlgES256:
		k, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("the key is not an ECDSA key and ES256 was claimed")
		}
		if k.Curve != elliptic256() {
			return fmt.Errorf("ES256 is P-256 and this key is on another curve")
		}
	case AlgEdDSA:
		if _, ok := key.(ed25519.PublicKey); !ok {
			return fmt.Errorf("the key is not an Ed25519 key and EdDSA was claimed")
		}
	case AlgRS256:
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("the key is not an RSA key and RS256 was claimed")
		}
		if k.N.BitLen() < 2048 {
			return fmt.Errorf(
				"this RSA key is %d bits, and below 2048 a signature proves "+
					"less than it appears to", k.N.BitLen())
		}
	default:
		return fmt.Errorf(
			"COSE algorithm %d is not one this verifies. Supported: ES256 "+
				"(%d), EdDSA (%d), RS256 (%d)",
			alg, AlgES256, AlgEdDSA, AlgRS256)
	}
	return nil
}

// verifySignature checks the signature with the algorithm the credential was
// registered under -- never one named by the message being checked.
func verifySignature(key any, alg int, signed, sig []byte) error {
	switch alg {
	case AlgES256:
		k, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("the stored key is not an ECDSA key")
		}
		sum := sha256.Sum256(signed)
		// WebAuthn's ECDSA signatures are ASN.1 DER, not the fixed-width pair
		// used elsewhere.
		if !ecdsa.VerifyASN1(k, sum[:], sig) {
			return errBadSignature
		}
	case AlgEdDSA:
		k, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("the stored key is not an Ed25519 key")
		}
		if !ed25519.Verify(k, signed, sig) {
			return errBadSignature
		}
	case AlgRS256:
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("the stored key is not an RSA key")
		}
		sum := sha256.Sum256(signed)
		if err := rsaVerify(k, sum[:], sig); err != nil {
			return errBadSignature
		}
	default:
		return fmt.Errorf("COSE algorithm %d is not one this verifies", alg)
	}
	return nil
}

// errBadSignature is one message for every algorithm, on purpose. Which curve
// failed is not information a caller should be handed and is not information
// the person signing in can use.
var errBadSignature = fmt.Errorf(
	"the signature does not verify against this credential's key")

// NewChallenge returns a fresh challenge, encoded the way a browser reports it.
//
// 32 bytes. The challenge's only job is to be unguessable for the seconds it
// is alive, and a value somebody can predict is a signature they can ask for
// in advance.
func NewChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("no entropy for a challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ChallengeLifetime is how long one stays valid. Long enough to find a phone,
// short enough that a captured one is not a spare key.
const ChallengeLifetime = 2 * time.Minute

// decodeAll base64url-decodes a set of fields, naming the one that failed.
func decodeAll(in map[string]string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(in))
	for name, v := range in {
		b, err := decode(v)
		if err != nil {
			return nil, fmt.Errorf("the %s is not base64url: %w", name, err)
		}
		out[name] = b
	}
	return out, nil
}

// decode accepts base64url with or without padding, because browsers and
// hand-written clients disagree about it and the difference carries no meaning.
func decode(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
