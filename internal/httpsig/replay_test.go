// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package httpsig_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/httpsig"
)

// A timestamp the signature does not cover cannot be used to judge its age.
//
// draft-cavage carries created= and expires= as parameters in the Signature
// header, and they enter the signing base only when (created) or (expires) is
// named in headers=. A parameter that is not named there is unsigned data
// sitting inside the signature header — and it was read anyway.
//
// So: capture any signed inbox POST, append `,created=<now>` to its Signature
// header, and replay it. headers= is untouched, so the base is byte-identical
// and the signature still verifies, while the age check reads the number the
// attacker just supplied. The five-minute window bounded nothing at all on
// this path. For a fediverse inbox that is a replayed Follow, Undo or Delete,
// executed as the actor whose request was captured, years later.
func TestAnUncoveredCreatedCannotRefreshASignature(t *testing.T) {
	priv, pub := edPair(t, 7)
	signed := at().Add(-90 * 24 * time.Hour) // three months old

	r := req()
	r.Header.Set("Date", signed.UTC().Format(http.TimeFormat))
	if err := httpsig.SignCavage(r, pub.ID, pub.Alg, priv,
		[]string{"(request-target)", "host", "date"}, signed); err != nil {
		t.Fatal(err)
	}

	// It is stale, and it is refused for being stale.
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err == nil {
		t.Fatal("a three-month-old signature verified")
	}

	// Now forge the freshness, without touching headers= or the signature.
	before := r.Header.Get("Signature")
	r.Header.Set("Signature", before+`,created=`+
		itoa(at().Add(-time.Second).Unix()))
	if got := r.Header.Get("Signature"); !strings.Contains(got, "created=") {
		t.Fatal("the test did not manage to append the parameter")
	}

	if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err == nil {
		t.Error("a stale signature was refreshed by a created= parameter " +
			"that it does not cover, so any captured request can be replayed " +
			"forever by appending one")
	}
}

// The Date header is only a bound when the signature covers it.
//
// Some fediverse implementations sign (request-target), host and digest and
// leave date out. Reading the header regardless meant anyone holding a copy of
// such a request could rewrite its Date and replay it.
func TestAnUncoveredDateCannotBeTrusted(t *testing.T) {
	priv, pub := edPair(t, 9)
	signed := at().Add(-90 * 24 * time.Hour)

	r := req()
	r.Header.Set("Date", signed.UTC().Format(http.TimeFormat))
	if err := httpsig.SignCavage(r, pub.ID, pub.Alg, priv,
		[]string{"(request-target)", "host"}, signed); err != nil {
		t.Fatal(err)
	}
	// The attacker rewrites the unsigned Date to now.
	r.Header.Set("Date", at().UTC().Format(http.TimeFormat))

	_, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at())
	if err == nil {
		t.Fatal("a signature covering neither (created) nor date verified " +
			"with an attacker-supplied Date")
	}
	if !strings.Contains(err.Error(), "neither") {
		t.Errorf("refused, but for the wrong reason: %v", err)
	}
}

// A signature that does cover its date still works.
//
// The fix must refuse unsigned timestamps, not timestamps.
func TestACoveredDateStillVerifies(t *testing.T) {
	priv, pub := edPair(t, 11)
	r := req()
	if err := httpsig.SignCavage(r, pub.ID, pub.Alg, priv,
		[]string{"(request-target)", "host", "date"}, at()); err != nil {
		t.Fatal(err)
	}
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err != nil {
		t.Fatalf("a properly signed, fresh request was refused: %v", err)
	}
}

// expires was parsed and never compared to anything.
//
// The signature here is built by hand rather than with SignCavage, which does
// not emit an expires parameter. The first version of this test used SignCavage
// and then edited the headers list in the finished header — which changes the
// signing base, so verification failed on the signature rather than on the
// expiry, and the test passed against the unfixed code for the wrong reason.
// A test that cannot fail is worse than no test, so this one signs the base it
// actually means.
func TestACoveredExpiresIsEnforced(t *testing.T) {
	priv, pub := edPair(t, 13)
	r := req()
	date := at().UTC().Format(http.TimeFormat)
	r.Header.Set("Date", date)

	expired := itoa(at().Add(-time.Hour).Unix())
	const list = "(request-target) host date (expires)"
	base := strings.Join([]string{
		"(request-target): post /inbox",
		"host: example.test",
		"date: " + date,
		"(expires): " + expired,
	}, "\n")
	r.Header.Set("Signature", `keyId="`+pub.ID+`",algorithm="ed25519",headers="`+
		list+`",signature="`+
		base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(base)))+
		`",expires=`+expired)

	// Refused, and refused for the expiry rather than for a bad signature —
	// which is the difference between this test and the one it replaced.
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err == nil {
		t.Error("a signature that says it expired an hour ago was accepted")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Errorf("refused, but not for expiry: %v", err)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
