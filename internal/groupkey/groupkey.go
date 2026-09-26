// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package groupkey agrees a shared secret among the people in a call.
//
// internal/sframe encrypts media so that a forwarding unit cannot read it,
// and says in as many words that it has nothing to say about where the base
// key came from. RFC 9605 leaves that out deliberately and points at MLS
// (RFC 9420). This is the part that was missing: without it the encryption
// is a function with no caller, and "end-to-end encrypted" is a claim about
// an algorithm rather than about a call.
//
// What it gives:
//
//   - A per-epoch secret, shared by exactly the people in the call at that
//     moment. Membership changes make a new epoch.
//   - Forward secrecy on removal. Somebody who leaves cannot read what is
//     said afterwards, because the new epoch's secret is encapsulated only
//     to the people still there.
//   - Post-compromise security. A member whose device was compromised
//     rotates their key in an Update, and the next epoch is closed to
//     whoever had it.
//   - Post-quantum confidentiality, by encapsulating under ML-KEM-768 and
//     X25519 together. Neither alone: the hybrid is secure if either is,
//     which is the only honest position while one of them is eleven years
//     old and the other is thirty.
//   - Agreement on who is in the call. Every member derives a confirmation
//     tag from the roster; a server that tells Ada the call is {Ada, Bob}
//     and tells Bob it is {Ada, Bob, Eve} produces two tags that do not
//     match, and both clients refuse. This is the property most products
//     that say "end-to-end encrypted group call" do not have, because the
//     server is the only thing that knows who is in the room.
//
// What it is not: it is not MLS. The key schedule follows RFC 9420 Section
// 8 in shape — an init secret chained across epochs, a commit secret
// extracted into it, everything bound to a group context, and secrets
// derived with a labelled expansion — and the SFrame binding follows RFC
// 9605 Section 5.2 exactly, including the KID layout. But the labels carry
// this project's own prefix, the wire encoding is its own, and there is no
// ratchet tree. Two deployments will not interoperate, and the package says
// so rather than implying a compatibility it does not have.
//
// # Why there is no tree
//
// MLS's ratchet tree makes a commit cost log(n) encapsulations instead of
// n. That is what makes a group of fifty thousand possible, and it is the
// most intricate part of the protocol: tree hashes, parent hashes, blank
// nodes, unmerged leaves, and the resolution algorithm that ties them
// together. A call is not a group of fifty thousand.
//
// The arithmetic, measured rather than estimated by `quilzo call cost`: at
// ML-KEM-768 with X25519 one encapsulation is 1120 bytes of encapsulated
// key and 48 of wrapped secret, about 1.2 KB a member once the signatures
// are shared out. A flat commit for a call of twenty is 26 KB and for a
// hundred it is 118 KB — against 92 KB for one key frame of the screen
// codec at 1920x1080. So a membership change costs about one video frame,
// once, when somebody joins or leaves. The tree would make those 6.6 KB and
// 8.2 KB. A real saving on a cost that is already a single frame, bought
// with the part of MLS where implementation bugs actually live.
//
// The trade is stated so it can be revisited rather than assumed. A flat
// commit is O(n), so a group where every member updates frequently and n is
// in the thousands wants the tree. A call does not, and this is for calls.
package groupkey

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

// The cipher suite. One, not a negotiation.
//
// A suite that can be chosen can be chosen badly, and every downgrade
// attack in the history of transport security began with a field saying
// which algorithms the other end would accept. There is one set here. When
// it needs to change, the version in the labels changes with it and the two
// do not share a key.
const (
	// Version prefixes every label, so a secret derived under one version
	// of this schedule can never equal one derived under another.
	Version = "Quilzo GKA 1.0 "

	// SuiteName is what the suite is, spelled out for a reader rather than
	// hidden behind a number.
	SuiteName = "MLKEM768X25519 / HKDF-SHA256 / AES-128-GCM / " +
		"Ed25519 + ML-DSA-65"

	// Nh is the KDF output size, which is the size of every secret here.
	Nh = sha256.Size
)

func kdf() func() hash.Hash { return sha256.New }

func suiteKEM() hpke.KEM { return hpke.MLKEM768X25519() }

func suiteKDF() hpke.KDF { return hpke.HKDFSHA256() }

func suiteAEAD() hpke.AEAD { return hpke.AES128GCM() }

// signatureContext separates these signatures from every other signature
// this program makes, including the ones over audit log heads.
const signatureContext = "quilzo/groupkey/v1"

// expandWithLabel is RFC 9420's ExpandWithLabel with this project's prefix.
//
// The encoding is not MLS's. MLS uses its own variable-length integers, and
// copying them here would buy nothing — the two are not going to interop —
// while inviting a reader to believe they might. What matters is that the
// encoding is unambiguous, so no two distinct (label, context) pairs can
// produce the same bytes: a four-byte length in front of each field does
// that, and does not need a paragraph to explain.
func expandWithLabel(secret []byte, label string, context []byte,
	length int) ([]byte, error) {
	full := Version + label
	info := make([]byte, 0, 2+4+len(full)+4+len(context))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = binary.BigEndian.AppendUint32(info, uint32(len(full)))
	info = append(info, full...)
	info = binary.BigEndian.AppendUint32(info, uint32(len(context)))
	info = append(info, context...)
	return hkdf.Expand(kdf(), secret, string(info), length)
}

// deriveSecret is ExpandWithLabel with an empty context and a full-size
// output.
func deriveSecret(secret []byte, label string) ([]byte, error) {
	return expandWithLabel(secret, label, nil, Nh)
}

// zeros is the all-zero secret MLS uses where a pre-shared key would go.
//
// There is no pre-shared key here. The zeros are kept rather than dropped
// because dropping them would change the schedule's shape without changing
// what it does, and the shape is the thing that has been analysed.
func zeros() []byte { return make([]byte, Nh) }

// schedule is the per-epoch secrets, derived once when an epoch begins.
type schedule struct {
	joiner        []byte
	epoch         []byte
	confirmation  []byte
	exporter      []byte
	authenticator []byte
	init          []byte
}

// advance runs the key schedule for a new epoch.
//
// init is the previous epoch's init secret, commit is the fresh secret the
// committer encapsulated to everybody, and context is the group context for
// the new epoch. All three are required: the first chains epochs together,
// the second is what a removed member does not have, and the third is what
// makes two different views of the group produce two different secrets.
func advance(init, commit, context []byte) (schedule, error) {
	var s schedule
	x, err := hkdf.Extract(kdf(), commit, init)
	if err != nil {
		return s, err
	}
	if s.joiner, err = expandWithLabel(x, "joiner", context, Nh); err != nil {
		return s, err
	}
	return fromJoiner(s.joiner, context)
}

// fromJoiner finishes the schedule from the joiner secret.
//
// Split out because a new member is given the joiner secret and nothing
// before it: the extraction above is one-way, so the joiner secret does not
// reveal the previous epoch's init secret, and a new arrival cannot read
// what was said before they got there.
func fromJoiner(joiner, context []byte) (schedule, error) {
	s := schedule{joiner: joiner}
	y, err := hkdf.Extract(kdf(), zeros(), joiner)
	if err != nil {
		return s, err
	}
	if s.epoch, err = expandWithLabel(y, "epoch", context, Nh); err != nil {
		return s, err
	}
	for _, d := range []struct {
		label string
		into  *[]byte
	}{
		{"confirm", &s.confirmation},
		{"exporter", &s.exporter},
		{"authentication", &s.authenticator},
		{"init", &s.init},
	} {
		v, err := deriveSecret(s.epoch, d.label)
		if err != nil {
			return s, err
		}
		*d.into = v
	}
	return s, nil
}

// Member is somebody in the call, as everybody else sees them.
type Member struct {
	Name string `json:"name"`
	// Index is constant for as long as they are in the group, because the
	// SFrame KID encodes it and a KID that changed meaning mid-epoch would
	// decrypt to the wrong sender.
	Index int `json:"index"`
	// KEM is the HPKE public key a commit is encapsulated to.
	KEM []byte `json:"kem"`
	// Ed25519 and MLDSA are both verification keys, and both signatures
	// have to check. One of them will outlive the other and nobody knows
	// which.
	Ed25519 []byte `json:"ed25519"`
	MLDSA   []byte `json:"mldsa"`
}

// Validate refuses a member who cannot be spoken to or checked.
func (m Member) Validate() error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("a member needs a name somebody can recognise")
	}
	if m.Index < 0 {
		return fmt.Errorf("a member index cannot be negative")
	}
	if _, err := suiteKEM().NewPublicKey(m.KEM); err != nil {
		return fmt.Errorf("%s has no usable encapsulation key: %w",
			m.Name, err)
	}
	if len(m.Ed25519) != ed25519.PublicKeySize {
		return fmt.Errorf("%s has a %d-byte Ed25519 key, want %d",
			m.Name, len(m.Ed25519), ed25519.PublicKeySize)
	}
	if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), m.MLDSA); err != nil {
		return fmt.Errorf("%s has no usable ML-DSA key: %w", m.Name, err)
	}
	return nil
}

// Fingerprint is a short, stable name for a member's keys.
//
// Over the keys and not the name, because the name is what an attacker
// would choose and the keys are what they would have to steal.
func (m Member) Fingerprint() string {
	h := sha256.New()
	h.Write(m.KEM)
	h.Write(m.Ed25519)
	h.Write(m.MLDSA)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Same reports whether two members are the same keys under the same name.
func (m Member) Same(o Member) bool {
	return m.Name == o.Name && m.Index == o.Index &&
		m.Fingerprint() == o.Fingerprint()
}

// Identity is the private side of a member.
type Identity struct {
	Name string

	kem hpke.PrivateKey
	ed  ed25519.PrivateKey
	ml  *mldsa.PrivateKey
}

// NewIdentity generates the three keys a member needs.
func NewIdentity(name string) (*Identity, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("an identity needs a name")
	}
	kem, err := suiteKEM().GenerateKey()
	if err != nil {
		return nil, err
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		return nil, err
	}
	return &Identity{Name: name, kem: kem, ed: ed, ml: ml}, nil
}

// Member is how this identity appears to the group at a given index.
func (i *Identity) Member(index int) Member {
	return Member{
		Name: i.Name, Index: index,
		KEM:     i.kem.PublicKey().Bytes(),
		Ed25519: i.ed.Public().(ed25519.PublicKey),
		MLDSA:   i.ml.PublicKey().Bytes(),
	}
}

// Rotate replaces the encapsulation key.
//
// This is what post-compromise security costs. An attacker who took a copy
// of the old key can read every commit encapsulated to it, including the
// ones that were supposed to lock them out — so locking them out means a
// new key, committed by somebody, and the Update change is how that key
// reaches the group.
func (i *Identity) Rotate() error {
	kem, err := suiteKEM().GenerateKey()
	if err != nil {
		return err
	}
	i.kem = kem
	return nil
}

// sign produces both signatures over a message.
func (i *Identity) sign(msg []byte) (edSig, mlSig []byte, err error) {
	mlSig, err = i.ml.SignDeterministic(msg,
		&mldsa.Options{Context: signatureContext})
	if err != nil {
		return nil, nil, err
	}
	return ed25519.Sign(i.ed, bound(msg)), mlSig, nil
}

// bound prefixes a message with the context string.
//
// ML-DSA takes the context as a parameter and Ed25519 does not, so for
// Ed25519 it goes in front of the message. Both signatures then cover the
// same statement about what the bytes are for, which is the point of having
// a context at all.
func bound(msg []byte) []byte {
	out := make([]byte, 0, len(signatureContext)+len(msg))
	out = append(out, signatureContext...)
	return append(out, msg...)
}

// verify checks both signatures. Both, with no option to accept one.
func (m Member) verify(msg, edSig, mlSig []byte) error {
	if !ed25519.Verify(ed25519.PublicKey(m.Ed25519), bound(msg), edSig) {
		return fmt.Errorf("the Ed25519 signature from %s does not verify",
			m.Name)
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), m.MLDSA)
	if err != nil {
		return err
	}
	if err := mldsa.Verify(pk, msg, mlSig,
		&mldsa.Options{Context: signatureContext}); err != nil {
		return fmt.Errorf("the ML-DSA signature from %s does not verify: %w",
			m.Name, err)
	}
	return nil
}

// equal is a constant-time comparison, for anything an attacker can retry.
func equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
