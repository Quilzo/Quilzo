// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package sframe is RFC 9605 end-to-end encryption for real-time media.
//
// # Why this layer exists at all
//
// A call between more than two people goes through a selective forwarding
// unit. The SFU has to see RTP headers to route packets, drop layers when a
// link degrades and rewrite sequence numbers, and SRTP — the usual answer —
// is hop-by-hop: the SFU holds the keys, so it can read everything.
//
// Every product that says "end-to-end encrypted group calls" and runs an SFU
// is resolving that tension somehow, and most of them resolve it by not
// meaning what the phrase says. SFrame is the resolution: the media is
// encrypted once by the sender and decrypted only by the receivers, the SFU
// forwards ciphertext it cannot read, and the RTP layer underneath goes on
// working because SFrame sits above it.
//
// # This implements a standard rather than inventing one
//
// RFC 9605, published August 2024, with the working group's own test vectors.
// Every cipher suite here is checked against them — all five suites, the
// derived keys and salts, the nonces, the AAD and the ciphertext, plus 289
// header encodings. A cryptographic implementation tested only against itself
// proves that it is self-consistent, which is the one property that does not
// matter.
//
// Nothing about the construction is this project's. The one thing worth
// saying is what it does not do.
//
// # What SFrame does not protect
//
// The media, and only the media. The SFU still sees who is in the call, who
// is speaking — from the size and timing of frames, which encryption does not
// hide — when they joined and how long they stayed. For most threat models
// that metadata is the more sensitive half, and no frame encryption addresses
// any of it.
//
// It also says nothing about how the key got there. RFC 9605 is explicit that
// key management is out of scope, and the security of a deployment is
// entirely the security of whatever distributes base_key. That part is the
// next piece rather than this one.
//
// # Truncated tags are a real trade and are stated as one
//
// Three of the five suites have tags shorter than the usual 16 bytes: 10, 8
// and 4. They exist because per-frame overhead matters at thirty frames a
// second, and a 4-byte tag gives a forgery one chance in 2^32 per attempt.
// For a video frame discarded 33 milliseconds later that is a defensible
// trade; for anything durable it is not, and AES_128_CTR_HMAC_SHA256_32 is
// not a suite to reach for because the numbers look similar.
package sframe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

// Suite is an SFrame cipher suite, as registered by RFC 9605.
type Suite uint16

const (
	// AES128CTRHMACSHA25680 is suite 1: a 10-byte tag.
	AES128CTRHMACSHA25680 Suite = 1
	// AES128CTRHMACSHA25664 is suite 2: an 8-byte tag.
	AES128CTRHMACSHA25664 Suite = 2
	// AES128CTRHMACSHA25632 is suite 3: a 4-byte tag.
	//
	// One forgery in 2^32 attempts. Defensible for a video frame that is
	// discarded in 33 milliseconds and not for anything else.
	AES128CTRHMACSHA25632 Suite = 3
	// AES128GCMSHA256128 is suite 4, and the one to use unless frame
	// overhead is genuinely the constraint.
	AES128GCMSHA256128 Suite = 4
	// AES256GCMSHA512128 is suite 5.
	AES256GCMSHA512128 Suite = 5
)

// Suites lists them.
func Suites() []Suite {
	return []Suite{AES128CTRHMACSHA25680, AES128CTRHMACSHA25664,
		AES128CTRHMACSHA25632, AES128GCMSHA256128, AES256GCMSHA512128}
}

// params are a suite's sizes, from RFC 9605 table 1.
type params struct {
	name string
	// nk is the total key length the KDF produces, nn the nonce length and
	// nt the tag length.
	nk, nn, nt int
	// nka is the encryption key length for the composite suites, and zero
	// for the AEAD ones.
	nka  int
	hash func() hash.Hash
}

func (s Suite) params() (params, bool) {
	switch s {
	case AES128CTRHMACSHA25680:
		return params{"AES_128_CTR_HMAC_SHA256_80", 48, 12, 10, 16,
			sha256.New}, true
	case AES128CTRHMACSHA25664:
		return params{"AES_128_CTR_HMAC_SHA256_64", 48, 12, 8, 16,
			sha256.New}, true
	case AES128CTRHMACSHA25632:
		return params{"AES_128_CTR_HMAC_SHA256_32", 48, 12, 4, 16,
			sha256.New}, true
	case AES128GCMSHA256128:
		return params{"AES_128_GCM_SHA256_128", 16, 12, 16, 0,
			sha256.New}, true
	case AES256GCMSHA512128:
		return params{"AES_256_GCM_SHA512_128", 32, 12, 16, 0,
			sha512.New}, true
	}
	return params{}, false
}

// Known reports whether this is a registered suite.
func (s Suite) Known() bool {
	_, ok := s.params()
	return ok
}

// String names the suite.
func (s Suite) String() string {
	if p, ok := s.params(); ok {
		return p.name
	}
	return fmt.Sprintf("suite(%d)", uint16(s))
}

// Overhead is how many bytes a frame grows by, for a given header length.
//
// Worth being able to ask: at thirty frames a second the difference between a
// 4-byte tag and a 16-byte one is 360 bytes a second per stream, which is why
// the truncated suites exist.
func (s Suite) Overhead(header int) int {
	p, ok := s.params()
	if !ok {
		return 0
	}
	return header + p.nt
}

// TagBytes is the authentication tag length.
func (s Suite) TagBytes() int {
	p, _ := s.params()
	return p.nt
}

// Header is SFrame's own header: which key, and which frame under it.
type Header struct {
	// KID identifies the key. In a group call it identifies the sender,
	// because each sender has their own key derived from the group secret.
	KID uint64
	// CTR counts frames under that key and must never repeat: the nonce is
	// the salt XOR the counter, and a repeat under AES-GCM loses the key.
	CTR uint64
}

// MarshalBinary encodes the header, per RFC 9605 section 4.3.
//
// A value of 0 through 7 rides in the config byte; anything larger is
// appended in the fewest bytes that hold it, KID first. The compact form
// matters because this is per frame.
func (h Header) MarshalBinary() ([]byte, error) {
	var config byte
	var extra []byte

	if h.KID < 8 {
		config |= byte(h.KID) << 4
	} else {
		kid := trim(h.KID)
		config |= 0x80
		config |= byte(len(kid)-1) << 4
		extra = append(extra, kid...)
	}
	if h.CTR < 8 {
		config |= byte(h.CTR)
	} else {
		ctr := trim(h.CTR)
		config |= 0x08
		config |= byte(len(ctr) - 1)
		extra = append(extra, ctr...)
	}
	return append([]byte{config}, extra...), nil
}

// trim encodes a value big-endian in the fewest bytes that hold it.
func trim(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	i := 0
	for i < 7 && b[i] == 0 {
		i++
	}
	return b[i:]
}

// ParseHeader reads a header and returns how many bytes it used.
func ParseHeader(in []byte) (Header, int, error) {
	if len(in) == 0 {
		return Header{}, 0, fmt.Errorf("an SFrame frame needs a header")
	}
	config := in[0]
	at := 1
	var h Header

	read := func(extended bool, bits byte, what string) (uint64, error) {
		if !extended {
			return uint64(bits), nil
		}
		n := int(bits) + 1
		if at+n > len(in) {
			return 0, fmt.Errorf(
				"the header says the %s is %d bytes and the frame has %d "+
					"left", what, n, len(in)-at)
		}
		var v uint64
		for _, b := range in[at : at+n] {
			v = v<<8 | uint64(b)
		}
		at += n
		return v, nil
	}

	kid, err := read(config&0x80 != 0, (config>>4)&0x07, "key identifier")
	if err != nil {
		return Header{}, 0, err
	}
	ctr, err := read(config&0x08 != 0, config&0x07, "counter")
	if err != nil {
		return Header{}, 0, err
	}
	h.KID, h.CTR = kid, ctr
	return h, at, nil
}

// The two label prefixes, verbatim from RFC 9605 section 4.4.2.
const (
	keyLabel  = "SFrame 1.0 Secret key "
	saltLabel = "SFrame 1.0 Secret salt "
	// ratchetLabel derives the next base key from the current one.
	ratchetLabel = "SFrame 1.0 Ratchet "
)

// Key is a sender's derived key material for one KID.
type Key struct {
	Suite Suite
	KID   uint64
	// Key and Salt are what encryption uses. The salt is XORed with the
	// counter to make the nonce, so it is not a secret that may be reused
	// across senders: each KID gets its own.
	Key  []byte
	Salt []byte
}

// Derive expands a base key into the material for one sender.
//
// The base key is whatever the group agreed. RFC 9605 says nothing about how
// it got there, and neither does this.
func Derive(suite Suite, kid uint64, base []byte) (Key, error) {
	p, ok := suite.params()
	if !ok {
		return Key{}, fmt.Errorf("%s is not a registered cipher suite",
			suite)
	}
	if len(base) == 0 {
		return Key{}, fmt.Errorf("the base key is empty")
	}
	secret, err := hkdf.Extract(p.hash, base, nil)
	if err != nil {
		return Key{}, err
	}
	key, err := hkdf.Expand(p.hash, secret, label(keyLabel, kid, suite), p.nk)
	if err != nil {
		return Key{}, err
	}
	salt, err := hkdf.Expand(p.hash, secret, label(saltLabel, kid, suite),
		p.nn)
	if err != nil {
		return Key{}, err
	}
	return Key{Suite: suite, KID: kid, Key: key, Salt: salt}, nil
}

// label builds an expansion label: the text, the KID as eight bytes, and the
// suite as two.
//
// The KID is the full eight bytes here and not the compact form the header
// uses. Two different encodings of one value in one specification is a trap,
// and it is called out rather than left to be discovered.
func label(prefix string, kid uint64, suite Suite) string {
	var b [10]byte
	binary.BigEndian.PutUint64(b[:8], kid)
	binary.BigEndian.PutUint16(b[8:], uint16(suite))
	return prefix + string(b[:])
}

// Ratchet advances a base key, so that a key compromised now does not read
// what was sent before.
func Ratchet(suite Suite, base []byte) ([]byte, error) {
	p, ok := suite.params()
	if !ok {
		return nil, fmt.Errorf("%s is not a registered cipher suite", suite)
	}
	secret, err := hkdf.Extract(p.hash, base, nil)
	if err != nil {
		return nil, err
	}
	return hkdf.Expand(p.hash, secret, ratchetLabel, len(base))
}

// nonce is the salt XORed with the counter.
func (k Key) nonce(ctr uint64) []byte {
	out := make([]byte, len(k.Salt))
	copy(out, k.Salt)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], ctr)
	// Right-aligned: the counter occupies the last eight bytes of the salt.
	for i := range c {
		out[len(out)-8+i] ^= c[i]
	}
	return out
}

// Seal encrypts a frame.
//
// The metadata is authenticated and not encrypted: it is whatever the
// application needs the forwarding unit to read, and putting anything
// sensitive there is putting it in the clear.
func (k Key) Seal(ctr uint64, plaintext, metadata []byte) ([]byte, error) {
	header := Header{KID: k.KID, CTR: ctr}
	encoded, err := header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	aad := append(append([]byte{}, encoded...), metadata...)
	ct := aead.Seal(nil, k.nonce(ctr), plaintext, aad)
	return append(encoded, ct...), nil
}

// Open decrypts a frame, and reports which key it was sealed under.
func Open(suite Suite, base []byte, frame, metadata []byte) ([]byte, Header,
	error) {

	h, n, err := ParseHeader(frame)
	if err != nil {
		return nil, Header{}, err
	}
	k, err := Derive(suite, h.KID, base)
	if err != nil {
		return nil, h, err
	}
	aead, err := k.aead()
	if err != nil {
		return nil, h, err
	}
	aad := append(append([]byte{}, frame[:n]...), metadata...)
	pt, err := aead.Open(nil, k.nonce(h.CTR), frame[n:], aad)
	if err != nil {
		// Deliberately not saying which key or which check failed. A
		// decryption oracle that distinguishes "wrong key" from "wrong tag"
		// is a decryption oracle.
		return nil, h, fmt.Errorf("this frame does not authenticate")
	}
	return pt, h, nil
}

// aead builds the cipher for this key's suite.
func (k Key) aead() (cipher.AEAD, error) {
	p, ok := k.Suite.params()
	if !ok {
		return nil, fmt.Errorf("%s is not a registered cipher suite",
			k.Suite)
	}
	if len(k.Key) != p.nk {
		return nil, fmt.Errorf(
			"%s takes a %d-byte key and this one is %d", k.Suite, p.nk,
			len(k.Key))
	}
	if p.nka == 0 {
		block, err := aes.NewCipher(k.Key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	return &composite{p: p, enc: k.Key[:p.nka], auth: k.Key[p.nka:]}, nil
}
