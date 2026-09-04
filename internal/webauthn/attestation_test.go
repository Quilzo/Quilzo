package webauthn_test

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/webauthn"
)

// A YubiKey 5 series identifier, as an example of the shape.
const yubikey5 = "cb69481e-8ff7-4039-93ec-0a2729a154a8"

func mustAAGUID(t *testing.T, s string) webauthn.AAGUID {
	t.Helper()
	a, err := webauthn.ParseAAGUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// By default nothing is constrained, and that is the documented behaviour: any
// authenticator, the phone included.
func TestAnUnconstrainedDeploymentEnrolsAnything(t *testing.T) {
	var e webauthn.Enrolment
	if !e.Empty() {
		t.Fatal("a zero policy constrains something")
	}
	if err := e.Check(webauthn.AAGUID{}, false); err != nil {
		t.Errorf("an unidentified authenticator was refused by default: %v", err)
	}
	if got := e.AttestationPreference(); got != "none" {
		t.Errorf("attestation preference is %q; asking for attestation shows "+
			"a prompt, and one shown for no reason is one people learn to "+
			"dismiss", got)
	}
}

// A deployment that requires hardware refuses a synced passkey.
//
// This is the AAL3 case. A passkey synced through a platform account is a key
// that exists in more than one place by design, which is the property the
// hardware requirement exists to exclude — and a verifier cannot tell it from
// a hardware key by the signature. It reports no AAGUID, and that is the only
// thing distinguishing them.
func TestASyncedPasskeyIsRefusedWhereHardwareIsRequired(t *testing.T) {
	e := webauthn.Enrolment{RequireIdentified: true}

	err := e.Check(webauthn.AAGUID{}, false)
	if err == nil {
		t.Fatal("an authenticator reporting no model enrolled where hardware " +
			"is required")
	}
	// The refusal has to explain, or an administrator reads "refused" and
	// concludes the key is broken.
	if !strings.Contains(err.Error(), "more than one place") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if got := e.AttestationPreference(); got == "none" {
		t.Error("a deployment that needs the model asks the browser for none")
	}
}

// An allow-list admits what is on it and refuses what is not.
func TestOnlyListedAuthenticatorsEnrol(t *testing.T) {
	allowed := mustAAGUID(t, yubikey5)
	e := webauthn.Enrolment{Allowed: []webauthn.AAGUID{allowed}}

	if err := e.Check(allowed, true); err != nil {
		t.Errorf("a listed authenticator was refused: %v", err)
	}

	other := mustAAGUID(t, "00000000-0000-0000-0000-0000000000ff")
	err := e.Check(other, true)
	if err == nil {
		t.Fatal("an unlisted authenticator enrolled")
	}
	if !strings.Contains(err.Error(), other.String()) {
		t.Errorf("the refusal does not name the model, so nobody can add it "+
			"deliberately: %v", err)
	}
}

// A list also excludes the unidentified, without having to say so twice.
func TestAnAllowListImpliesIdentification(t *testing.T) {
	e := webauthn.Enrolment{
		Allowed: []webauthn.AAGUID{mustAAGUID(t, yubikey5)},
	}
	if err := e.Check(webauthn.AAGUID{}, false); err == nil {
		t.Fatal("an authenticator that named no model satisfied a list of " +
			"models")
	}
}

// The identifier round-trips through the form vendors publish.
func TestAAGUIDsRoundTrip(t *testing.T) {
	a := mustAAGUID(t, yubikey5)
	if a.String() != yubikey5 {
		t.Errorf("%s came back as %s", yubikey5, a.String())
	}
	if a.Zero() {
		t.Error("a real identifier reports as absent")
	}
	for _, bad := range []string{"", "not-an-aaguid", "cb69481e", strings.Repeat("f", 40)} {
		if _, err := webauthn.ParseAAGUID(bad); err == nil {
			t.Errorf("%q was accepted as an AAGUID", bad)
		}
	}
}

// The model is read from registration data and is absent from an assertion.
//
// Which is why it is recorded at enrolment: a credential cannot move to
// another authenticator, and nothing later will say what held it.
func TestTheModelIsReadFromRegistrationOnly(t *testing.T) {
	// A registration: the attested-credential-data flag set, sixteen bytes of
	// AAGUID after the counter.
	reg := make([]byte, 37+16)
	reg[32] = 0x01 | 0x04 | 0x40
	want := mustAAGUID(t, yubikey5)
	copy(reg[37:], want[:])

	got, ok := webauthn.AAGUIDOf(reg)
	if !ok {
		t.Fatal("no model was read from registration data")
	}
	if got != want {
		t.Errorf("read %s, want %s", got, want)
	}

	// An assertion stops after the counter.
	assertion := make([]byte, 37)
	assertion[32] = 0x01 | 0x04
	if _, ok := webauthn.AAGUIDOf(assertion); ok {
		t.Error("a model was read from an assertion, which does not carry one")
	}
}
