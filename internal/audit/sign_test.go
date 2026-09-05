package audit_test

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

func signer(t *testing.T) *audit.HeadSigner {
	t.Helper()
	ed, ml, err := audit.GenerateHeadSeeds()
	if err != nil {
		t.Fatal(err)
	}
	s, err := audit.NewHeadSigner(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func head() audit.Head {
	return audit.Head{
		Size: 42, Root: "a1b2c3",
		At: time.Unix(1787000000, 0).UTC().Format(time.RFC3339),
	}
}

// The control.
func TestASignedHeadVerifies(t *testing.T) {
	s := signer(t)
	sh, err := s.Sign(head())
	if err != nil {
		t.Fatal(err)
	}
	if sh.Ed25519 == "" || sh.MLDSA == "" {
		t.Fatal("a signed head is missing a signature")
	}
	if err := s.Verifier().Verify(sh); err != nil {
		t.Fatalf("a head this program signed does not verify: %v", err)
	}
}

// Changing any field of the head invalidates both signatures. The size matters
// as much as the root: a head that under-counts is a log with entries removed.
func TestChangingTheHeadBreaksIt(t *testing.T) {
	s := signer(t)
	sh, err := s.Sign(head())
	if err != nil {
		t.Fatal(err)
	}

	for name, edit := range map[string]func(*audit.SignedHead){
		"the root": func(x *audit.SignedHead) { x.Root = "deadbeef" },
		"the size": func(x *audit.SignedHead) { x.Size = 41 },
		"the time": func(x *audit.SignedHead) { x.At = "2020-01-01T00:00:00Z" },
	} {
		altered := sh
		edit(&altered)
		if err := s.Verifier().Verify(altered); err == nil {
			t.Errorf("changing %s left the head verifying", name)
		}
	}
}

// Both signatures are required, and neither alone will do. This is the whole
// argument for making two.
func TestOneSignatureIsNotEnough(t *testing.T) {
	s := signer(t)
	sh, err := s.Sign(head())
	if err != nil {
		t.Fatal(err)
	}

	withoutML := sh
	withoutML.MLDSA = ""
	if err := s.Verifier().Verify(withoutML); err == nil {
		t.Error("a head with only an Ed25519 signature verified, so the " +
			"post-quantum half can be dropped by whoever produces the head")
	}

	withoutEd := sh
	withoutEd.Ed25519 = ""
	if err := s.Verifier().Verify(withoutEd); err == nil {
		t.Error("a head with only an ML-DSA signature verified")
	}
}

// A break in one algorithm is not a forged head.
//
// Standing in for "Ed25519 fell": the attacker can produce its signature over
// whatever they like, so here they simply take a genuine one. What they cannot
// produce is the matching ML-DSA signature, and splicing a real one from a
// different head does not help.
func TestBreakingOneAlgorithmDoesNotForgeAHead(t *testing.T) {
	s := signer(t)
	at := time.Unix(1787000000, 0).UTC().Format(time.RFC3339)

	honest, err := s.Sign(audit.Head{Size: 42, Root: "a1b2c3", At: at})
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, err := s.Sign(audit.Head{Size: 1, Root: "00", At: at})
	if err != nil {
		t.Fatal(err)
	}

	// The head the attacker wants believed, with the Ed25519 signature that
	// belongs to it and an ML-DSA signature from another head.
	spliced := honest
	spliced.MLDSA = elsewhere.MLDSA
	if err := s.Verifier().Verify(spliced); err == nil {
		t.Fatal("a head verified with an ML-DSA signature from a different " +
			"head, so the second algorithm is not actually being checked")
	}

	// And the other way round.
	spliced = honest
	spliced.Ed25519 = elsewhere.Ed25519
	if err := s.Verifier().Verify(spliced); err == nil {
		t.Fatal("a head verified with an Ed25519 signature from a different head")
	}
}

// The ambiguity the length prefixes exist to stop.
//
// Size 1 with root "23" and size 12 with root "3" concatenate to the same
// characters. Without length prefixes a signature over one is a signature over
// the other, and an auditor can be shown a log with a different number of
// entries than the one that was signed.
func TestTwoHeadsThatConcatenateAlikeDoNotShareASignature(t *testing.T) {
	s := signer(t)
	at := time.Unix(1787000000, 0).UTC().Format(time.RFC3339)

	one, err := s.Sign(audit.Head{Size: 1, Root: "23", At: at})
	if err != nil {
		t.Fatal(err)
	}
	other := audit.SignedHead{
		Head:    audit.Head{Size: 12, Root: "3", At: at},
		Ed25519: one.Ed25519, MLDSA: one.MLDSA, KeyID: one.KeyID,
	}
	if err := s.Verifier().Verify(other); err == nil {
		t.Fatal("a signature over size 1 root \"23\" also verified size 12 " +
			"root \"3\", so what was signed is not what an auditor reads")
	}
}

// Another site's key must not verify this site's head.
func TestAnotherKeyDoesNotVerify(t *testing.T) {
	mine := signer(t)
	theirs := signer(t)

	sh, err := mine.Sign(head())
	if err != nil {
		t.Fatal(err)
	}
	sh.KeyID = "" // so the failure is the signature, not the fingerprint
	if err := theirs.Verifier().Verify(sh); err == nil {
		t.Fatal("a head verified against a key that did not sign it")
	}
}

// The fingerprint covers both keys, so swapping one is a different identity.
func TestTheKeyIDCoversBothKeys(t *testing.T) {
	edSeed, mlSeed, err := audit.GenerateHeadSeeds()
	if err != nil {
		t.Fatal(err)
	}
	_, otherML, err := audit.GenerateHeadSeeds()
	if err != nil {
		t.Fatal(err)
	}

	a, err := audit.NewHeadSigner(edSeed, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	// Same Ed25519 seed, different ML-DSA seed.
	b, err := audit.NewHeadSigner(edSeed, otherML)
	if err != nil {
		t.Fatal(err)
	}
	if a.Verifier().KeyID() == b.Verifier().KeyID() {
		t.Fatal("two pairs sharing only their Ed25519 key have the same id, " +
			"so the ML-DSA key can be substituted without changing the name")
	}
}

// Seeds regenerate the same keys, which is what makes a 64-byte backup a
// backup of the identity.
func TestSeedsRegenerateTheSameIdentity(t *testing.T) {
	edSeed, mlSeed, err := audit.GenerateHeadSeeds()
	if err != nil {
		t.Fatal(err)
	}
	a, err := audit.NewHeadSigner(edSeed, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := audit.NewHeadSigner(edSeed, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	if a.Verifier().KeyID() != b.Verifier().KeyID() {
		t.Fatal("the same seeds produced a different identity")
	}

	first, err := a.Sign(head())
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.Sign(head())
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic on both halves, so a head signed twice is byte-identical
	// and nobody has to explain which of two signatures is the real one.
	if first.Ed25519 != second.Ed25519 || first.MLDSA != second.MLDSA {
		t.Error("signing the same head twice produced different bytes")
	}
}

// Published public keys round-trip, which is what lets somebody outside verify.
func TestAPublishedKeyVerifies(t *testing.T) {
	s := signer(t)
	sh, err := s.Sign(head())
	if err != nil {
		t.Fatal(err)
	}

	ed, ml := s.Verifier().PublicKeys()
	outside, err := audit.NewHeadVerifier(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	if err := outside.Verify(sh); err != nil {
		t.Fatalf("a head does not verify against this site's published keys: %v", err)
	}
	if outside.KeyID() != sh.KeyID {
		t.Error("the published keys have a different id than the signer")
	}
}

// The refusal has to say which half is missing, or somebody with a
// half-signed head has no idea what to do about it.
func TestTheRefusalNamesTheMissingHalf(t *testing.T) {
	s := signer(t)
	sh, err := s.Sign(head())
	if err != nil {
		t.Fatal(err)
	}
	sh.MLDSA = ""
	err = s.Verifier().Verify(sh)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "ML-DSA") {
		t.Errorf("the refusal does not name the missing half: %v", err)
	}
}
