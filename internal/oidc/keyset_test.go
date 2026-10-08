// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package oidc

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
)

func rsaJWKS(t *testing.T, s *signer, kid string) []byte {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid, "use": "sig",
		"n": b64(s.rsaKey.PublicKey.N.Bytes()),
		"e": b64(big.NewInt(int64(s.rsaKey.PublicKey.E)).Bytes()),
	}}})
	return b
}

// A key set on its own verifies a token signed the same way as an ID token
// and meaning something else, with the same refusals.
func TestAKeySetVerifiesASecurityEventToken(t *testing.T) {
	s := newSigner(t)
	ks, err := NewKeySet("https://transmitter.example/jwks", func(context.Context, string) ([]byte, error) {
		return rsaJWKS(t, s, "k1"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	typ := func(v string) bool { return v == "secevent+jwt" }
	good := s.sign(t, "RS256", map[string]any{"kid": "k1", "typ": "secevent+jwt"}, map[string]any{"jti": "1"})
	payload, err := VerifyJWS(good, []Algorithm{RS256}, ks, "https://transmitter.example", "a security event token", typ)
	if err != nil || !strings.Contains(string(payload), `"jti":"1"`) {
		t.Fatalf("a good token: %s, %v", payload, err)
	}
	for name, tok := range map[string]string{
		"wrong type": s.sign(t, "RS256", map[string]any{"kid": "k1", "typ": "JWT"}, map[string]any{"jti": "1"}),
		"alg none":   s.sign(t, "none", map[string]any{"kid": "k1", "typ": "secevent+jwt"}, map[string]any{"jti": "1"}),
		"hmac":       s.sign(t, "HS256", map[string]any{"kid": "k1", "typ": "secevent+jwt"}, map[string]any{"jti": "1"}),
		"altered":    good[:len(good)-4] + "AAAA",
	} {
		if _, err := VerifyJWS(tok, []Algorithm{RS256}, ks, "https://transmitter.example", "a security event token", typ); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := NewKeySet("http://transmitter.example/jwks", func(context.Context, string) ([]byte, error) { return nil, nil }); err == nil {
		t.Error("a key set over plain http was accepted")
	}
}

// Invented key ids do not each cost the provider a request.
func TestUnknownKeyIDsDoNotFetchTheSetEachTime(t *testing.T) {
	s := newSigner(t)
	var fetches atomic.Int32
	ks, _ := NewKeySet("https://transmitter.example/jwks", func(context.Context, string) ([]byte, error) {
		fetches.Add(1)
		return rsaJWKS(t, s, "k1"), nil
	})
	for i := 0; i < 50; i++ {
		_, _ = ks.Key("invented-" + string(rune('a'+i%26)))
	}
	if n := fetches.Load(); n != 1 {
		t.Errorf("50 unknown key ids fetched the key set %d times", n)
	}
	if _, err := ks.Key("k1"); err != nil {
		t.Errorf("the real key is not found after them: %v", err)
	}
}
