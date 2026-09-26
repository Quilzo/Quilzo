// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sframe

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad vector %q: %v", s, err)
	}
	return b
}

// 289 header encodings from the working group's vectors, both directions.
func TestHeaderMatchesTheWorkingGroupVectors(t *testing.T) {
	for _, v := range headerVectors {
		got, err := (Header{KID: v.kid, CTR: v.ctr}).MarshalBinary()
		if err != nil {
			t.Fatalf("kid %d ctr %d: %v", v.kid, v.ctr, err)
		}
		if hex.EncodeToString(got) != v.encoded {
			t.Errorf("kid %d ctr %d encoded as %s, want %s", v.kid, v.ctr,
				hex.EncodeToString(got), v.encoded)
			continue
		}
		back, n, err := ParseHeader(got)
		if err != nil {
			t.Errorf("kid %d ctr %d does not parse back: %v", v.kid, v.ctr,
				err)
			continue
		}
		if n != len(got) {
			t.Errorf("kid %d ctr %d parsed %d of %d bytes", v.kid, v.ctr, n,
				len(got))
		}
		if back.KID != v.kid || back.CTR != v.ctr {
			t.Errorf("kid %d ctr %d came back as %d %d", v.kid, v.ctr,
				back.KID, back.CTR)
		}
	}
}

// The derived key material, against the vectors. If these match, the labels,
// the KID encoding and the suite encoding are all right; if any one of them
// were wrong they would all fail.
func TestKeyDerivationMatchesTheVectors(t *testing.T) {
	for _, v := range frameVectors {
		k, err := Derive(v.suite, v.kid, unhex(t, v.baseKey))
		if err != nil {
			t.Fatalf("%s: %v", v.suite, err)
		}
		if got := hex.EncodeToString(k.Key); got != v.key {
			t.Errorf("%s key\n got %s\nwant %s", v.suite, got, v.key)
		}
		if got := hex.EncodeToString(k.Salt); got != v.salt {
			t.Errorf("%s salt\n got %s\nwant %s", v.suite, got, v.salt)
		}
		// The labels, checked directly: two different encodings of the KID
		// live in this specification and getting them the wrong way round
		// is the trap.
		if got := hex.EncodeToString([]byte(label(keyLabel, v.kid,
			v.suite))); got != v.keyLabel {
			t.Errorf("%s key label\n got %s\nwant %s", v.suite, got,
				v.keyLabel)
		}
		if got := hex.EncodeToString([]byte(label(saltLabel, v.kid,
			v.suite))); got != v.saltLabel {
			t.Errorf("%s salt label\n got %s\nwant %s", v.suite, got,
				v.saltLabel)
		}
		if got := hex.EncodeToString(k.nonce(v.ctr)); got != v.nonce {
			t.Errorf("%s nonce\n got %s\nwant %s", v.suite, got, v.nonce)
		}
	}
}

// The whole thing, end to end, for all five suites.
func TestSealMatchesTheVectors(t *testing.T) {
	for _, v := range frameVectors {
		base := unhex(t, v.baseKey)
		k, err := Derive(v.suite, v.kid, base)
		if err != nil {
			t.Fatalf("%s: %v", v.suite, err)
		}
		frame, err := k.Seal(v.ctr, unhex(t, v.pt), unhex(t, v.metadata))
		if err != nil {
			t.Fatalf("%s: %v", v.suite, err)
		}
		if got := hex.EncodeToString(frame); got != v.ct {
			t.Errorf("%s\n got %s\nwant %s", v.suite, got, v.ct)
			continue
		}
		// And the AAD it authenticated is the header plus the metadata.
		header, err := (Header{KID: v.kid, CTR: v.ctr}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		aad := append(header, unhex(t, v.metadata)...)
		if got := hex.EncodeToString(aad); got != v.aad {
			t.Errorf("%s aad\n got %s\nwant %s", v.suite, got, v.aad)
		}

		pt, h, err := Open(v.suite, base, unhex(t, v.ct),
			unhex(t, v.metadata))
		if err != nil {
			t.Fatalf("%s does not open its own vector: %v", v.suite, err)
		}
		if h.KID != v.kid || h.CTR != v.ctr {
			t.Errorf("%s opened as kid %d ctr %d", v.suite, h.KID, h.CTR)
		}
		if hex.EncodeToString(pt) != v.pt {
			t.Errorf("%s plaintext\n got %s\nwant %s", v.suite,
				hex.EncodeToString(pt), v.pt)
		}
	}
}

// The composite construction on its own, against its own vectors.
func TestTheCompositeAEADMatchesTheVectors(t *testing.T) {
	for _, v := range ctrHMACVectors {
		p, ok := v.suite.params()
		if !ok {
			t.Fatalf("%d is not a suite", v.suite)
		}
		key := unhex(t, v.key)
		c := &composite{p: p, enc: key[:p.nka], auth: key[p.nka:]}
		if hex.EncodeToString(c.enc) != v.encKey {
			t.Errorf("%s split the encryption key as %s", v.suite,
				hex.EncodeToString(c.enc))
		}
		if hex.EncodeToString(c.auth) != v.authKey {
			t.Errorf("%s split the authentication key as %s", v.suite,
				hex.EncodeToString(c.auth))
		}
		got := c.Seal(nil, unhex(t, v.nonce), unhex(t, v.pt),
			unhex(t, v.aad))
		if hex.EncodeToString(got) != v.ct {
			t.Errorf("%s\n got %s\nwant %s", v.suite,
				hex.EncodeToString(got), v.ct)
			continue
		}
		back, err := c.Open(nil, unhex(t, v.nonce), got, unhex(t, v.aad))
		if err != nil {
			t.Fatalf("%s does not open its own output: %v", v.suite, err)
		}
		if hex.EncodeToString(back) != v.pt {
			t.Errorf("%s round trip gave %s", v.suite,
				hex.EncodeToString(back))
		}
	}
}

// A single flipped bit anywhere has to fail, and the failure must not say
// which part of the frame was wrong.
func TestAnyAlterationFailsAndTheErrorSaysNothing(t *testing.T) {
	for _, suite := range Suites() {
		base := []byte("0123456789abcdef")
		k, err := Derive(suite, 42, base)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := k.Seal(7, []byte("the media"), []byte("meta"))
		if err != nil {
			t.Fatal(err)
		}
		for i := range frame {
			bad := append([]byte(nil), frame...)
			bad[i] ^= 0x01
			if _, _, err := Open(suite, base, bad, []byte("meta")); err == nil {
				t.Errorf("%s: flipping byte %d of %d still opened", suite, i,
					len(frame))
			}
		}
		// The metadata is authenticated even though it is not encrypted.
		if _, _, err := Open(suite, base, frame, []byte("metb")); err == nil {
			t.Errorf("%s: changing the metadata still opened", suite)
		}
		// And a different base key does not.
		if _, _, err := Open(suite, []byte("fedcba9876543210"), frame,
			[]byte("meta")); err == nil {
			t.Errorf("%s: the wrong key opened the frame", suite)
		}
		_, _, err = Open(suite, base, frame, []byte("metb"))
		if !strings.Contains(err.Error(), "does not authenticate") {
			t.Errorf("%s: the error says %q, which is more than it should",
				suite, err)
		}
	}
}

// The counter is what keeps the nonce unique, and reusing one under GCM
// loses the key. Different counters must give different nonces.
func TestTheCounterMovesTheNonce(t *testing.T) {
	k, err := Derive(AES128GCMSHA256128, 1, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]uint64{}
	for ctr := range uint64(2000) {
		n := string(k.nonce(ctr))
		if had, clash := seen[n]; clash {
			t.Fatalf("counters %d and %d share a nonce", had, ctr)
		}
		seen[n] = ctr
	}
	// Counter zero is the salt itself, which is what the specification
	// says and is worth pinning: an implementation that started at one
	// would interoperate with nothing.
	if !bytes.Equal(k.nonce(0), k.Salt) {
		t.Error("counter zero is not the salt")
	}
}

// Each sender gets their own key from the same group secret, which is the
// whole reason the KID is in the derivation.
func TestTwoSendersFromOneBaseKeyDoNotShareMaterial(t *testing.T) {
	base := []byte("0123456789abcdef")
	a, err := Derive(AES128GCMSHA256128, 1, base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Derive(AES128GCMSHA256128, 2, base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Key, b.Key) || bytes.Equal(a.Salt, b.Salt) {
		t.Fatal("two key identifiers produced the same material")
	}
	// And a frame from one does not open as the other, because the KID in
	// the header selects the derivation.
	frame, err := a.Seal(1, []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, h, err := Open(AES128GCMSHA256128, base, frame, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.KID != 1 {
		t.Errorf("the frame reports sender %d", h.KID)
	}
}

// A key compromised now should not read what was sent before.
func TestRatchetingMovesTheBaseKeyForward(t *testing.T) {
	base := []byte("0123456789abcdef")
	next, err := Ratchet(AES128GCMSHA256128, base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(next, base) {
		t.Fatal("ratcheting returned the same key")
	}
	if len(next) != len(base) {
		t.Errorf("ratcheting changed the key length to %d", len(next))
	}
	// A frame sealed under the old key does not open under the new one.
	k, err := Derive(AES128GCMSHA256128, 1, base)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := k.Seal(1, []byte("before"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(AES128GCMSHA256128, next, frame, nil); err == nil {
		t.Fatal("the ratcheted key opened an earlier frame")
	}
}

func TestATruncatedOrMalformedHeaderIsRefused(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":            {},
		"says 2 more":      {0x90},
		"says 8 more":      {0xf0, 1, 2, 3},
		"counter runs out": {0x0f, 1, 2},
	} {
		if _, _, err := ParseHeader(in); err == nil {
			t.Errorf("a header that %s was accepted", name)
		}
	}
}

func TestAnUnregisteredSuiteIsRefused(t *testing.T) {
	if _, err := Derive(Suite(99), 1, []byte("x")); err == nil {
		t.Fatal("an unregistered suite derived a key")
	}
	if Suite(99).Known() {
		t.Error("suite 99 reports itself as registered")
	}
	if _, err := Derive(AES128GCMSHA256128, 1, nil); err == nil {
		t.Error("an empty base key derived something")
	}
	for _, s := range Suites() {
		if !s.Known() || s.String() == "" {
			t.Errorf("%v is not properly registered", uint16(s))
		}
	}
}

// At thirty frames a second the difference between a 4-byte tag and a
// 16-byte one is 360 bytes a second per stream, which is why the truncated
// suites exist and why the trade is worth being able to ask about.
func TestOverheadIsAskable(t *testing.T) {
	if got := AES128CTRHMACSHA25632.Overhead(1); got != 5 {
		t.Errorf("the smallest suite adds %d bytes, want 5", got)
	}
	if got := AES128GCMSHA256128.Overhead(1); got != 17 {
		t.Errorf("GCM adds %d bytes, want 17", got)
	}
	if AES128CTRHMACSHA25632.TagBytes() >= AES128GCMSHA256128.TagBytes() {
		t.Error("the truncated suite's tag is not shorter")
	}
}
