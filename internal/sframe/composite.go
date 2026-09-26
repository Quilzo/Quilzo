// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sframe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// The AES-CTR and HMAC composite, from RFC 9605 section 4.5.2.
//
// # Why a composite at all
//
// The three suites built this way exist to make the tag shorter than a
// 16-byte GCM tag. AES-GCM's tag length is not a free parameter — truncating
// it weakens the authentication in ways that are specific to GHASH and that
// the GCM specification warns about — so the RFC builds encrypt-then-MAC out
// of CTR and HMAC instead, where truncating an HMAC to N bits costs exactly
// the N bits and nothing more.
//
// That is the whole reason this file exists. A reader who assumed the
// composite was there for compatibility, or because somebody preferred it,
// would be missing the one thing it is for.
//
// # Encrypt-then-MAC, in that order
//
// The tag covers the ciphertext and the associated data, and it is checked
// before a single byte is decrypted. The other order — decrypt, then check —
// is how padding oracles happen, and it is worth writing down here because
// this file is short enough that somebody will one day be tempted to
// rearrange it.
type composite struct {
	p    params
	enc  []byte
	auth []byte
}

// NonceSize is the nonce length.
func (c *composite) NonceSize() int { return c.p.nn }

// Overhead is the tag length.
func (c *composite) Overhead() int { return c.p.nt }

// Seal encrypts and then authenticates.
func (c *composite) Seal(dst, nonce, plaintext, aad []byte) []byte {
	ct := make([]byte, len(plaintext))
	c.stream(nonce).XORKeyStream(ct, plaintext)
	tag := c.tag(nonce, aad, ct)
	out := append(dst, ct...)
	return append(out, tag...)
}

// Open authenticates and then decrypts, in that order.
func (c *composite) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < c.p.nt {
		return nil, fmt.Errorf("the frame is shorter than its own tag")
	}
	split := len(ciphertext) - c.p.nt
	ct, tag := ciphertext[:split], ciphertext[split:]

	want := c.tag(nonce, aad, ct)
	// Constant time, because a comparison that returns early leaks how much
	// of the tag was right, and enough of those leak the whole thing.
	if subtle.ConstantTimeCompare(want, tag) != 1 {
		return nil, fmt.Errorf("this frame does not authenticate")
	}
	pt := make([]byte, len(ct))
	c.stream(nonce).XORKeyStream(pt, ct)
	return append(dst, pt...), nil
}

// stream builds the counter-mode keystream.
//
// The nonce is the first twelve bytes of the sixteen-byte counter block and
// the rest is zero, so the block counter starts at zero and runs upwards.
func (c *composite) stream(nonce []byte) cipher.Stream {
	block, err := aes.NewCipher(c.enc)
	if err != nil {
		// Unreachable: the key length is checked by the caller against the
		// suite's own parameters before this is built.
		panic("sframe: " + err.Error())
	}
	iv := make([]byte, block.BlockSize())
	copy(iv, nonce)
	return cipher.NewCTR(block, iv)
}

// tag authenticates the associated data and the ciphertext.
//
// The three lengths go in first, as eight-byte big-endian integers. Without
// them a byte moved from the end of the associated data to the start of the
// ciphertext would produce the same tag, which is the canonical way a
// concatenation-based MAC is broken.
func (c *composite) tag(nonce, aad, ct []byte) []byte {
	mac := hmac.New(c.p.hash, c.auth)
	var lengths [24]byte
	binary.BigEndian.PutUint64(lengths[0:8], uint64(len(aad)))
	binary.BigEndian.PutUint64(lengths[8:16], uint64(len(ct)))
	binary.BigEndian.PutUint64(lengths[16:24], uint64(c.p.nt))
	mac.Write(lengths[:])
	mac.Write(nonce)
	mac.Write(aad)
	mac.Write(ct)
	return mac.Sum(nil)[:c.p.nt]
}
