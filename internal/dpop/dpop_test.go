// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The thumbprint is RFC 7638's, checked against the example in its
// section 3.1.
func TestTheThumbprintIsRFC7638s(t *testing.T) {
	key := `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`
	got, err := Thumbprint([]byte(key))
	if err != nil || got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("%q %v", got, err)
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A proof made for one request holds for that request, once, and names
// the key that made it.
func TestAProofHoldsForItsRequestOnce(t *testing.T) {
	key := newKey(t)
	now := time.Now()
	proof, err := Prove(key, "POST", "https://admin.example/mcp", "qz_token", now)
	if err != nil {
		t.Fatal(err)
	}
	var replays Replays
	thumb, err := Check(proof, "POST", "https://ADMIN.example:443/mcp?x=1", "qz_token", now, &replays)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := PublicJWK(&key.PublicKey)
	if want, _ := Thumbprint(pub); thumb != want {
		t.Errorf("thumbprint %q, want %q", thumb, want)
	}
	if _, err := Check(proof, "POST", "https://admin.example/mcp", "qz_token", now, &replays); err == nil {
		t.Error("a proof was used twice")
	}
}

// Every check RFC 9449 lists for a resource server refuses what it should.
func TestAProofThatDoesNotHoldIsRefused(t *testing.T) {
	key := newKey(t)
	now := time.Now()
	good := func(at time.Time) string {
		p, err := Prove(key, "POST", "https://admin.example/mcp", "qz_token", at)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	tamper := func(p string, edit func(h, c map[string]any)) string {
		parts := strings.Split(p, ".")
		var h, c map[string]any
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
		json.Unmarshal(hb, &h)
		json.Unmarshal(cb, &c)
		edit(h, c)
		hb, _ = json.Marshal(h)
		cb, _ = json.Marshal(c)
		return base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb) + "." + parts[2]
	}
	for name, c := range map[string]struct {
		proof, method, url, token string
	}{
		"another method":  {good(now), "GET", "https://admin.example/mcp", "qz_token"},
		"another address": {good(now), "POST", "https://admin.example/v1/messages", "qz_token"},
		"another token":   {good(now), "POST", "https://admin.example/mcp", "qz_other"},
		"too old":         {good(now.Add(-6 * time.Minute)), "POST", "https://admin.example/mcp", "qz_token"},
		"from the future": {good(now.Add(3 * time.Minute)), "POST", "https://admin.example/mcp", "qz_token"},
		"another type":    {tamper(good(now), func(h, c map[string]any) { h["typ"] = "JWT" }), "POST", "https://admin.example/mcp", "qz_token"},
		"no algorithm":    {tamper(good(now), func(h, c map[string]any) { h["alg"] = "none" }), "POST", "https://admin.example/mcp", "qz_token"},
		"a shared secret": {tamper(good(now), func(h, c map[string]any) { h["alg"] = "HS256" }), "POST", "https://admin.example/mcp", "qz_token"},
		"a private key":   {tamper(good(now), func(h, c map[string]any) { h["jwk"].(map[string]any)["d"] = "AAAA" }), "POST", "https://admin.example/mcp", "qz_token"},
		"a changed claim": {tamper(good(now), func(h, c map[string]any) { c["htu"] = "https://admin.example/a2a" }), "POST", "https://admin.example/a2a", "qz_token"},
		"another key in the head": {tamper(good(now), func(h, c map[string]any) {
			pub, _ := PublicJWK(&newKey(t).PublicKey)
			var m map[string]any
			json.Unmarshal(pub, &m)
			h["jwk"] = m
		}), "POST", "https://admin.example/mcp", "qz_token"},
		"not a JWT": {"abc", "POST", "https://admin.example/mcp", "qz_token"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Check(c.proof, c.method, c.url, c.token, now, &Replays{}); !errors.Is(err, ErrProof) {
				t.Errorf("accepted, or refused for another reason: %v", err)
			}
		})
	}
}

// The proofs remembered are bounded, and remembering one does not walk the
// rest. Any valid proof is remembered for the window, and anybody can make
// a valid proof with a key of their own before a token is looked at, so the
// cache once grew with whatever was sent, and every request swept all of it
// under one lock.
func TestTheProofsRememberedAreBounded(t *testing.T) {
	var r Replays
	now := time.Unix(1787000000, 0)
	const max = 1 << 16
	accepted := 0
	start := time.Now()
	for i := 0; i < max+100; i++ {
		if r.first(fmt.Sprintf("thumb|%012d", i), now) {
			accepted++
		}
	}
	if accepted > max {
		t.Errorf("%d proofs remembered at once", accepted)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("remembering %d proofs took %s", max+100, took)
	}
	if r.first("thumb|000000000001", now.Add(time.Second)) {
		t.Error("a proof was accepted twice within the window")
	}
	// Once the window has passed they are forgotten, and there is room.
	if !r.first("thumb|later-proof", now.Add(Window+Skew+time.Second)) {
		t.Error("no room once the window passed")
	}
}

// What a DPoP proof is held to, pinned before it shares a verifier with
// agent proofs: five minutes old at most and a minute ahead, the address
// compared as RFC 9449 section 4.3 says (no query or fragment, the scheme
// and host in any case, a default port the same as none, the path
// exactly), the method exactly, and a proof remembered for as long as one
// could still be presented, so even one dated a minute ahead is good once.
func TestADPoPProofKeepsItsFiveMinuteWindowAndItsRFC9449Address(t *testing.T) {
	key := newKey(t)
	now := time.Unix(1787000000, 0)
	url := "https://admin.example/mcp"
	at := func(made time.Time, method, url string) string {
		p, err := Prove(key, method, url, "qz_token", made)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if Window != 5*time.Minute || Skew != time.Minute {
		t.Errorf("the window is %s and the skew %s", Window, Skew)
	}
	for _, w := range []struct {
		name string
		made time.Time
		ok   bool
	}{
		{"five minutes old", now.Add(-Window), true},
		{"five minutes and a second old", now.Add(-Window - time.Second), false},
		{"a minute ahead", now.Add(Skew), true},
		{"a minute and a second ahead", now.Add(Skew + time.Second), false},
	} {
		_, err := Check(at(w.made, "POST", url), "POST", url, "qz_token", now, &Replays{})
		if (err == nil) != w.ok {
			t.Errorf("a proof %s: %v", w.name, err)
		}
	}

	for _, same := range []string{
		"https://admin.example/mcp?x=1", "https://admin.example/mcp#f", "HTTPS://ADMIN.EXAMPLE/mcp",
		"https://admin.example:443/mcp",
	} {
		if _, err := Check(at(now, "POST", url), "POST", same, "qz_token", now, &Replays{}); err != nil {
			t.Errorf("a proof for %s was refused at %s: %v", url, same, err)
		}
	}
	for _, other := range []string{
		"https://admin.example/MCP", "https://admin.example/mcp/", "http://admin.example/mcp",
		"https://admin.example:8443/mcp", "https://other.example/mcp",
	} {
		if _, err := Check(at(now, "POST", url), "POST", other, "qz_token", now, &Replays{}); err == nil {
			t.Errorf("a proof for %s was accepted at %s", url, other)
		}
	}
	if _, err := Check(at(now, "post", url), "POST", url, "qz_token", now, &Replays{}); err == nil {
		t.Error("the method is compared exactly, and post was accepted for POST")
	}

	// Dated a minute ahead, it is in its window until six minutes from
	// now; the replays remember it that long.
	replays := &Replays{}
	ahead := at(now.Add(Skew), "POST", url)
	if _, err := Check(ahead, "POST", url, "qz_token", now, replays); err != nil {
		t.Fatal(err)
	}
	later := now.Add(Window + Skew)
	if _, err := Check(ahead, "POST", url, "qz_token", later, &Replays{}); err != nil {
		t.Fatalf("six minutes on, the proof is out of its window, so this test proves nothing: %v", err)
	}
	if _, err := Check(ahead, "POST", url, "qz_token", later, replays); err == nil {
		t.Error("a proof was accepted twice, the second time on the last moment of its window")
	}
}
