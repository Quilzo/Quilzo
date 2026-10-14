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
