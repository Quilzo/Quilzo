// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package httpsig_test

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/httpsig"
)

// A sender signs only the older Digest; somebody on the way replaces the
// body and adds a Content-Digest of their own for it. The unsigned header
// matches the new body and the signed one does not, and only the signed
// one counts.
func TestOnlyTheDigestThatWasSignedIsChecked(t *testing.T) {
	priv, pub := edPair(t, 9)
	sent := []byte(`{"type":"Follow"}`)
	r := req()
	sum := sha256.Sum256(sent)
	r.Header.Set(httpsig.LegacyDigest, "SHA-256="+base64.StdEncoding.EncodeToString(sum[:]))
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, append(cover, "digest"), at()); err != nil {
		t.Fatal(err)
	}
	signed, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at())
	if err != nil {
		t.Fatal(err)
	}
	if err := httpsig.CheckSignedDigest(r, sent, signed); err != nil {
		t.Fatalf("the body as sent was refused: %v", err)
	}

	swapped := []byte(`{"type":"Delete"}`)
	other := sha256.Sum256(swapped)
	r.Header.Set(httpsig.ContentDigest, "sha-256=:"+base64.StdEncoding.EncodeToString(other[:])+":")
	if err := httpsig.CheckSignedDigest(r, swapped, signed); err == nil {
		t.Fatal("a body swapped under an unsigned Content-Digest was accepted")
	}

	// A signature over a digest header the request then lacks proves
	// nothing, and one over no digest says nothing about the body.
	r.Header.Del(httpsig.LegacyDigest)
	if err := httpsig.CheckSignedDigest(r, sent, signed); err == nil || !strings.Contains(err.Error(), "has none") {
		t.Errorf("a signed digest header that is gone: %v", err)
	}
	r2 := req()
	if err := httpsig.Sign(r2, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
		t.Fatal(err)
	}
	s2, err := httpsig.Verify(r2, []httpsig.PublicKey{pub}, 0, at())
	if err != nil {
		t.Fatal(err)
	}
	if err := httpsig.CheckSignedDigest(r2, sent, s2); err == nil {
		t.Error("a signature over no digest vouched for a body")
	}
}
