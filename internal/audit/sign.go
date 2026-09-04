package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Signing the head, twice, with algorithms that fail differently.
//
// # What an unsigned head is worth
//
// A head is three fields: a size, a root and a time. Exported to a SIEM or
// handed to an auditor, it is a claim that anybody with a text editor can
// produce. The Merkle machinery above proves that a log is internally
// consistent with *some* head; it says nothing about where that head came
// from. So a signature is what turns "this root is consistent" into "this
// site said this root", and without it the whole transparency story rests on
// somebody having copied a string correctly.
//
// # Why two signatures rather than one
//
// An audit log is evidence, and evidence is looked at late. A head anchored
// today may be the thing somebody checks in fifteen years, during a dispute
// about what happened this week — which is the one case where "harvest now,
// forge later" is not hypothetical. An adversary with a quantum computer does
// not need to have had one at the time; they need the signature to have been
// forgeable by the time anybody looks.
//
// Ed25519 is the algorithm everything else here already uses, and it is the
// one that falls to that adversary. ML-DSA (FIPS 204) is standardised and in
// the standard library, and it is new: the conservative reading is that a
// lattice scheme published in 2024 has had less time to be broken by ordinary
// cryptanalysis than a curve from 2011.
//
// Neither of those is a reason to pick one. Both signatures are made, and
// verification requires both to pass. A break in Ed25519 does not forge a
// head, because ML-DSA still has to be forged too; a break in ML-DSA does not
// forge one either. The cost is four kilobytes on a value that is produced
// occasionally and read rarely, which is the cheapest insurance in this
// program.
//
// # ML-DSA-65
//
// The middle parameter set, NIST category 3. ML-DSA-44 is the smaller one and
// its margin is the one most likely to look thin later; ML-DSA-87 costs more
// than the threat here justifies. A head is signed once and stored, so the
// signature size is the only cost and it is measured in kilobytes.

// signatureContext separates these signatures from every other use of the same
// key material.
//
// Without domain separation a signature made for one purpose is a signature
// for another: hand somebody a signing oracle over arbitrary bytes in one
// protocol and they can obtain a valid audit head from it. The version is in
// the string so that a change to what gets signed cannot be confused with the
// thing it replaced.
const signatureContext = "quilzo/audit-head/v1"

// SignedHead is a head with proof of who published it.
type SignedHead struct {
	Head
	// Ed25519 and MLDSA are base64. Both are required: a head carrying one is
	// a head with half its argument.
	Ed25519 string `json:"ed25519"`
	MLDSA   string `json:"mldsa"`
	// KeyID identifies the pair that signed, so a verifier that holds several
	// knows which to try rather than trying all of them and reporting the
	// first that works.
	KeyID string `json:"key_id"`
	// Algorithms is what actually signed this head.
	//
	// Stated rather than inferred from which fields are present, because the
	// interesting case is a head that carries fewer signatures than it should
	// and a verifier needs to know whether that was a decision or a
	// truncation. A head signed under the FIPS 140-3 module v1.0.0 carries
	// Ed25519 alone -- ML-DSA is not in that module -- and says so here.
	Algorithms []string `json:"algorithms,omitempty"`
}

// HeadSigner holds both private keys.
type HeadSigner struct {
	ed ed25519.PrivateKey
	ml *mldsa.PrivateKey
	// why records what is missing when ml is nil, so a caller can say so
	// once at startup rather than at every signature.
	why string
}

// PostQuantum reports whether this signer can make the second signature.
//
// False in one situation and it is worth naming: a build against the FIPS
// 140-3 Go Cryptographic Module v1.0.0, which does not contain ML-DSA. That
// is not an error to route around quietly -- it is the exact configuration a
// deployment that cares most about this would choose, and it costs them the
// post-quantum half.
func (s *HeadSigner) PostQuantum() bool { return s.ml != nil }

// Why says what is missing, for a caller reporting it.
func (s *HeadSigner) Why() string { return s.why }

// HeadVerifier holds both public keys.
type HeadVerifier struct {
	ed ed25519.PublicKey
	ml *mldsa.PublicKey
	// AcceptSingle allows a head that declares Ed25519 alone.
	//
	// Off by default, and it has to be: the whole argument for two signatures
	// is that a verifier which will take one has the security of whichever is
	// weaker. A deployment building against a FIPS module without ML-DSA
	// turns it on knowingly, for its own heads.
	AcceptSingle bool
}

// SeedSize is the length of each half of a signing seed.
const SeedSize = 32

// NewHeadSigner derives both keys from two seeds.
//
// Seeds rather than encoded private keys, because an ML-DSA private key is
// several kilobytes and a seed is 32 bytes that regenerate it exactly. What
// gets stored is small enough to put in a vault by hand.
func NewHeadSigner(edSeed, mlSeed []byte) (*HeadSigner, error) {
	if len(edSeed) != SeedSize || len(mlSeed) != SeedSize {
		return nil, fmt.Errorf(
			"a signing seed is two %d-byte halves, and these are %d and %d",
			SeedSize, len(edSeed), len(mlSeed))
	}
	signer := &HeadSigner{ed: ed25519.NewKeyFromSeed(edSeed)}

	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), mlSeed)
	switch {
	case err == nil:
		signer.ml = ml
	case strings.Contains(err.Error(), "unavailable in FIPS"):
		// The one degradation this accepts, and only because refusing would
		// be worse: a FIPS build would lose audit head signing entirely, and
		// an unsigned head is three fields anybody can type. Ed25519 is
		// itself FIPS-approved and in that module, so what is lost is the
		// post-quantum half and nothing else.
		//
		// Recorded on the head, so a verifier is told rather than left to
		// notice. See Verify, which still refuses such a head unless a caller
		// has said it accepts one.
		signer.why = "ML-DSA is not in the FIPS 140-3 Go Cryptographic " +
			"Module v1.0.0, so heads signed by this build carry Ed25519 " +
			"alone. Build without GOFIPS140, or against a module version " +
			"that includes it, to sign both"
	default:
		return nil, fmt.Errorf("the ML-DSA seed is unusable: %w", err)
	}
	return signer, nil
}

// GenerateHeadSeeds returns two fresh seeds.
func GenerateHeadSeeds() (edSeed, mlSeed []byte, err error) {
	edSeed = make([]byte, SeedSize)
	mlSeed = make([]byte, SeedSize)
	if _, err = rand.Read(edSeed); err != nil {
		return nil, nil, fmt.Errorf("no entropy for a signing seed: %w", err)
	}
	if _, err = rand.Read(mlSeed); err != nil {
		return nil, nil, fmt.Errorf("no entropy for a signing seed: %w", err)
	}
	return edSeed, mlSeed, nil
}

// Verifier returns the public half.
func (s *HeadSigner) Verifier() *HeadVerifier {
	v := &HeadVerifier{ed: s.ed.Public().(ed25519.PublicKey)}
	if s.ml != nil {
		v.ml = s.ml.PublicKey()
	}
	return v
}

// KeyID is a short fingerprint over both public keys.
//
// Over both, so that a pair with one key swapped is a different identity. A
// fingerprint of only the Ed25519 half would let somebody substitute an
// ML-DSA key and keep the same name.
func (v *HeadVerifier) KeyID() string {
	h := sha256.New()
	h.Write([]byte(signatureContext))
	writeField(h, string(v.ed))
	if v.ml != nil {
		writeField(h, string(v.ml.Bytes()))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// PublicKeys returns both, for publishing.
func (v *HeadVerifier) PublicKeys() (ed, ml []byte) {
	if v.ml == nil {
		return append([]byte(nil), v.ed...), nil
	}
	return append([]byte(nil), v.ed...), v.ml.Bytes()
}

// NewHeadVerifier reads published public keys.
func NewHeadVerifier(ed, ml []byte) (*HeadVerifier, error) {
	if len(ed) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the Ed25519 key is %d bytes, not %d",
			len(ed), ed25519.PublicKeySize)
	}
	v := &HeadVerifier{ed: ed25519.PublicKey(append([]byte(nil), ed...))}
	if len(ml) == 0 {
		// A published key with no ML-DSA half. It comes from a signer that
		// had none, and such a verifier can check one signature and must be
		// told it may accept a head carrying one.
		return v, nil
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), ml)
	if err != nil {
		if strings.Contains(err.Error(), "unavailable in FIPS") {
			// This build cannot check ML-DSA at all. Returning an Ed25519
			// verifier is honest about that; refusing would leave a FIPS
			// deployment unable to check even the half it can.
			return v, nil
		}
		return nil, fmt.Errorf("the ML-DSA key is unreadable: %w", err)
	}
	v.ml = pk
	return v, nil
}

// Sign produces both signatures over a head.
func (s *HeadSigner) Sign(h Head) (SignedHead, error) {
	msg := headMessage(h)

	// Ed25519 alone, when the module in this build has no ML-DSA. Marked, so
	// the head says what signed it rather than leaving a verifier to infer it
	// from an absent field.
	if s.ml == nil {
		return SignedHead{
			Head:       h,
			Ed25519:    base64.StdEncoding.EncodeToString(ed25519.Sign(s.ed, msg)),
			KeyID:      s.Verifier().KeyID(),
			Algorithms: []string{"ed25519"},
		}, nil
	}

	// Deterministic, so signing the same head twice produces the same bytes.
	// A head is a commitment; two different-looking signatures over one
	// commitment invite the question of which is the real one, and the answer
	// "both" is one more thing to explain to an auditor.
	mlSig, err := s.ml.SignDeterministic(msg, &mldsa.Options{
		Context: signatureContext,
	})
	if err != nil {
		return SignedHead{}, fmt.Errorf("the ML-DSA signature failed: %w", err)
	}

	return SignedHead{
		Head:       h,
		Ed25519:    base64.StdEncoding.EncodeToString(ed25519.Sign(s.ed, msg)),
		MLDSA:      base64.StdEncoding.EncodeToString(mlSig),
		KeyID:      s.Verifier().KeyID(),
		Algorithms: []string{"ed25519", "ml-dsa-65"},
	}, nil
}

// Verify checks a signed head. Both signatures must verify.
//
// Both, with no option to accept one. An option would be taken: the moment a
// verifier can be told "Ed25519 is enough", every deployment under time
// pressure says so, and the property this exists for is gone without anybody
// deciding to give it up.
func (v *HeadVerifier) Verify(sh SignedHead) error {
	if got := v.KeyID(); sh.KeyID != "" && sh.KeyID != got {
		return fmt.Errorf(
			"this head was signed by key %s and the key held here is %s",
			sh.KeyID, got)
	}
	// A head that says it carries one signature is a decision somebody made,
	// and it is still refused by default. AcceptSingle is how a deployment
	// that made that decision -- a FIPS build with no ML-DSA -- says it will
	// take its own heads back.
	if sh.MLDSA == "" && v.AcceptSingle && sh.Ed25519 != "" &&
		len(sh.Algorithms) == 1 && sh.Algorithms[0] == "ed25519" {
		edSig, derr := base64.StdEncoding.DecodeString(sh.Ed25519)
		if derr != nil {
			return fmt.Errorf("the Ed25519 signature is not base64: %w", derr)
		}
		if !ed25519.Verify(v.ed, headMessage(sh.Head), edSig) {
			return fmt.Errorf("the Ed25519 signature does not verify")
		}
		return nil
	}
	if sh.Ed25519 == "" || sh.MLDSA == "" {
		return fmt.Errorf(
			"this head carries %s. Both signatures are required: one of them "+
				"is the half that survives whichever algorithm turns out to "+
				"be broken", whichIsMissing(sh))
	}

	edSig, err := base64.StdEncoding.DecodeString(sh.Ed25519)
	if err != nil {
		return fmt.Errorf("the Ed25519 signature is not base64: %w", err)
	}
	mlSig, err := base64.StdEncoding.DecodeString(sh.MLDSA)
	if err != nil {
		return fmt.Errorf("the ML-DSA signature is not base64: %w", err)
	}

	msg := headMessage(sh.Head)
	if !ed25519.Verify(v.ed, msg, edSig) {
		return fmt.Errorf("the Ed25519 signature does not verify")
	}
	if err := mldsa.Verify(v.ml, msg, mlSig, &mldsa.Options{
		Context: signatureContext,
	}); err != nil {
		return fmt.Errorf("the ML-DSA signature does not verify: %w", err)
	}
	return nil
}

// whichIsMissing names the absent signature, so the message says what to fix.
func whichIsMissing(sh SignedHead) string {
	switch {
	case sh.Ed25519 == "" && sh.MLDSA == "":
		return "neither signature"
	case sh.Ed25519 == "":
		return "no Ed25519 signature"
	default:
		return "no ML-DSA signature"
	}
}

// headMessage is the exact bytes both algorithms sign.
//
// Length-prefixed, through the same writeField the Merkle leaves use, and that
// is the whole point of writing it out rather than joining the fields with a
// separator. A head of size 1 with root "23" and a head of size 12 with root
// "3" concatenate to the same string -- so a signature over one would be a
// signature over the other, and a log could be shown to an auditor with a
// different number of entries than the one that was signed.
func headMessage(h Head) []byte {
	var b bytes.Buffer
	b.WriteString(signatureContext)
	b.WriteByte(0)
	writeField(&b, strconv.Itoa(h.Size))
	writeField(&b, h.Root)
	writeField(&b, h.At)
	return b.Bytes()
}
