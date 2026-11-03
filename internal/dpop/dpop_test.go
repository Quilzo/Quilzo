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
	"sync"
	"sync/atomic"
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

// The proofs remembered are bounded, by time and by number.
//
// Replays kept every proof it was shown for the window with no limit, and
// walked them all on every request. The token exchange checks a proof
// before the token that comes with it, so anybody can make a key and have
// proof after proof remembered. Measured before the bound: 65,537 proofs
// remembered of 65,537 offered, and a minute and a half to remember them.
func TestTheProofsRememberedAreBounded(t *testing.T) {
	var r Replays
	now := time.Now()
	start := time.Now()
	for i := 0; i < MaxReplays; i++ {
		if err := r.first(fmt.Sprintf("k|%012d", i), now); err != nil {
			t.Fatalf("proof %d of %d was refused: %v", i, MaxReplays, err)
		}
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("remembering %d proofs took %s: each one is walking the rest", MaxReplays, took)
	}
	// Full: a new proof is refused, rather than remembered or let through
	// unremembered, and a used one is still a replay.
	if err := r.first("k|one-more-proof", now); err == nil {
		t.Errorf("with %d proofs remembered another was taken, and %d are remembered", MaxReplays, len(r.seen))
	}
	if err := r.first("k|000000000000", now); !errors.Is(err, errReplayed) {
		t.Errorf("a proof used before was not refused as one when the list was full: %v", err)
	}
	if len(r.seen) > MaxReplays {
		t.Errorf("%d proofs are remembered; the limit is %d", len(r.seen), MaxReplays)
	}
	// Within the window nothing is forgotten; past it, everything is, and
	// there is room again.
	if err := r.first("k|one-more-proof", now.Add(Window+Skew)); err == nil {
		t.Error("a proof was taken while the list was full and none had aged out")
	}
	later := now.Add(Window + Skew + time.Second)
	if err := r.first("k|one-more-proof", later); err != nil {
		t.Errorf("once the window had passed a new proof was refused: %v", err)
	}
	if len(r.seen) != 1 || len(r.order) != 1 {
		t.Errorf("%d proofs (%d in order) are remembered after the window; want only the newest", len(r.seen), len(r.order))
	}
	if err := r.first("k|000000000000", later); err != nil {
		t.Errorf("a proof's identifier was still remembered after the window: %v", err)
	}
}

// And a full list refuses through Check, as a proof that does not hold.
func TestAFullListRefusesAProof(t *testing.T) {
	key := newKey(t)
	now := time.Now()
	r := Replays{seen: map[string]time.Time{}}
	for i := 0; i < MaxReplays; i++ {
		k := fmt.Sprintf("k|%012d", i)
		r.seen[k] = now
		r.order = append(r.order, seenAt{k, now})
	}
	proof, err := Prove(key, "POST", "https://admin.example/mcp", "qz_token", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(proof, "POST", "https://admin.example/mcp", "qz_token", now, &r); !errors.Is(err, ErrProof) {
		t.Fatalf("a proof was taken with the list full: %v", err)
	}
}

// One proof sent many times at once is taken once.
func TestAProofSentAtOnceIsTakenOnce(t *testing.T) {
	var r Replays
	now := time.Now()
	var wg sync.WaitGroup
	var taken atomic.Int32
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if r.first("k|the-same-proof", now) == nil {
				taken.Add(1)
			}
			_ = r.first(fmt.Sprintf("k|%012d", i), now.Add(time.Duration(i)*time.Second))
		}(i)
	}
	wg.Wait()
	if n := taken.Load(); n != 1 {
		t.Errorf("one proof sent 64 times at once was taken %d times", n)
	}
}
