package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// Which authenticator, and why a deployment would care.
//
// # The default is deliberate and is wrong for some people
//
// webauthn.go says this asks no authenticator to prove what make and model it
// is, because attestation answers "is this an approved brand of key", which is
// a question an enterprise with a hardware inventory asks -- and the phone is
// the point.
//
// For a deployment at NIST SP 800-63B AAL3 the phone is exactly not the point.
// AAL3 requires a multi-factor cryptographic *hardware* authenticator: the
// private key must be non-exportable and bound to a device validated at FIPS
// 140 Level 2 overall with Level 3 physical security. A passkey synced through
// a platform account is a key that exists in more than one place by design,
// which is the property AAL3 exists to exclude.
//
// A verifier cannot tell those apart from the signature. Both produce a valid
// assertion over the right challenge from the right origin. The only thing
// that distinguishes them is what the authenticator says about itself at
// registration, and whether it is believed.
//
// # So this is opt-in, and off by default
//
// Turning it on means somebody has a list of models they accept and a process
// for keeping it. Turning it on without that list locks everybody out on a
// Tuesday. Off, this changes nothing and the comment in webauthn.go stands.
//
// # What is checked, and what is not
//
// The AAGUID: sixteen bytes an authenticator reports identifying its make and
// model, which the browser hands over in the authenticator data. Checked
// against a list the deployment maintains.
//
// Not the attestation statement's signature chain. That would mean shipping
// and maintaining FIDO metadata -- a signed blob of every certified
// authenticator, refreshed on a schedule -- and this program has no
// dependencies and no way to refresh anything on an isolated network. An
// AAGUID is self-reported: an authenticator that lies about which model it is
// passes this check.
//
// That is worth stating plainly rather than implying more. Against a user
// plugging in a consumer key when policy says otherwise, this works. Against
// an adversary who has built hardware that impersonates an approved model, it
// does not, and nothing short of a verified metadata chain does. A deployment
// that needs the stronger claim pairs this with procurement: keys issued by
// the organisation, and a policy that only issued keys are enrolled.

// aaguidOffset is where the AAGUID sits in the authenticator data: after the
// 32-byte RP ID hash, the flags byte and the four-byte counter.
const aaguidOffset = authDataMinimum

// flagAttestedCredentialData means the authenticator data carries the AAGUID
// and the credential itself. Set on a registration, absent on an assertion.
const flagAttestedCredentialData = 0x40

// AAGUID identifies an authenticator's make and model.
type AAGUID [16]byte

// String renders it the way vendors and the FIDO metadata service do.
func (a AAGUID) String() string {
	h := hex.EncodeToString(a[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// Zero reports whether the authenticator declined to identify itself.
//
// An all-zero AAGUID is what a platform authenticator reports when
// attestation was not requested, and what several report even when it was. It
// is not an error; it is an answer, and the answer is "I am not telling you".
func (a AAGUID) Zero() bool {
	var empty AAGUID
	return subtle.ConstantTimeCompare(a[:], empty[:]) == 1
}

// ParseAAGUID reads the hyphenated form.
func ParseAAGUID(s string) (AAGUID, error) {
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	var out AAGUID
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return out, fmt.Errorf("%q is not an AAGUID: %w", s, err)
	}
	if len(raw) != 16 {
		return out, fmt.Errorf(
			"%q is %d bytes and an AAGUID is 16", s, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// AAGUIDOf reads the authenticator's identifier out of registration data.
//
// Present only on a registration: an assertion's authenticator data stops
// after the counter. So the model is recorded when the credential is enrolled
// and never re-checked, which is the right shape -- a credential cannot change
// which authenticator holds it.
func AAGUIDOf(authData []byte) (AAGUID, bool) {
	var out AAGUID
	if len(authData) < aaguidOffset+16 {
		return out, false
	}
	if authData[32]&flagAttestedCredentialData == 0 {
		return out, false
	}
	copy(out[:], authData[aaguidOffset:aaguidOffset+16])
	return out, true
}

// Enrolment is a deployment's policy on which authenticators may be registered.
type Enrolment struct {
	// Allowed is the set of models that may enrol. Empty means any, which is
	// the default and is what webauthn.go describes.
	Allowed []AAGUID
	// RequireIdentified refuses an authenticator that reports no model.
	//
	// Separate from Allowed because they answer different questions. A
	// deployment may accept any identified hardware key while refusing one
	// that declines to say what it is -- and an all-zero AAGUID is what a
	// synced platform passkey reports.
	RequireIdentified bool
}

// Empty reports whether this policy constrains anything.
func (e Enrolment) Empty() bool {
	return len(e.Allowed) == 0 && !e.RequireIdentified
}

// Check decides whether an authenticator may enrol.
func (e Enrolment) Check(id AAGUID, identified bool) error {
	if e.Empty() {
		return nil
	}
	if !identified || id.Zero() {
		if e.RequireIdentified || len(e.Allowed) > 0 {
			return fmt.Errorf(
				"this authenticator does not say what it is, and this " +
					"deployment enrols only authenticators it recognises. A " +
					"passkey synced through a platform account reports " +
					"nothing here, by design — it is a key that exists in " +
					"more than one place, which is what a hardware " +
					"requirement excludes")
		}
		return nil
	}
	if len(e.Allowed) == 0 {
		return nil
	}
	for _, want := range e.Allowed {
		if subtle.ConstantTimeCompare(id[:], want[:]) == 1 {
			return nil
		}
	}
	return fmt.Errorf(
		"authenticator %s is not one this deployment enrols. The list is "+
			"the deployment's own; add it deliberately if it should be", id)
}

// AttestationPreference is what to ask the browser for at registration.
//
// "none" unless a policy needs the model, because asking for attestation
// shows the person a prompt about sharing information with the site, and a
// prompt shown for no reason is one people learn to dismiss.
func (e Enrolment) AttestationPreference() string {
	if e.Empty() {
		return "none"
	}
	// "indirect" rather than "direct": the deployment needs the model, not a
	// chain it has no way to verify on an isolated network. See the note at
	// the top of this file about what is and is not checked.
	return "indirect"
}

// fingerprint is a stable short name for a credential, for logs that must not
// carry the credential id itself.
func fingerprint(id []byte) string {
	sum := sha256.Sum256(id)
	return hex.EncodeToString(sum[:4])
}
