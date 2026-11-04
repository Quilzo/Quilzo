// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentcred

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func keys(t *testing.T) (ed25519.PrivateKey, map[string]ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	_, issuer, _ := ed25519.GenerateKey(rand.Reader)
	_, holder, _ := ed25519.GenerateKey(rand.Reader)
	pub := issuer.Public().(ed25519.PublicKey)
	return issuer, map[string]ed25519.PublicKey{KeyID(pub): pub}, holder
}

func credentialFor(holder ed25519.PrivateKey, now time.Time) Credential {
	return Credential{Agent: "buyer", Sponsor: "dana", Grant: "browser:shop", Act: true,
		Holder: holder.Public().(ed25519.PublicKey), ValidUntil: now.Add(24 * time.Hour)}
}

// A credential the store issued verifies, says what it holds, and is
// bound to the agent's own key.
func TestACredentialVerifiesAndSaysWhatItHolds(t *testing.T) {
	now := time.Now()
	issuer, pubs, holder := keys(t)
	tok, err := Issue(issuer, "https://quilzo.example.com", credentialFor(holder, now), now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Verify(tok, pubs, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Agent != "buyer" || c.Sponsor != "dana" || c.Grant != "browser:shop" || !c.Act ||
		!c.Holder.Equal(holder.Public()) || !strings.HasPrefix(c.ID, "urn:uuid:") {
		t.Fatalf("the credential says %+v", c)
	}
}

// Nothing about a credential can be changed, borrowed or stretched.
func TestACredentialCannotBeForgedOrStretched(t *testing.T) {
	now := time.Now()
	issuer, pubs, holder := keys(t)
	tok, _ := Issue(issuer, "iss", credentialFor(holder, now), now)
	parts := strings.Split(tok, ".")
	payload, _ := b64.DecodeString(parts[1])
	forged := parts[0] + "." + b64.EncodeToString([]byte(strings.Replace(string(payload), `"grant":"browser:shop"`, `"grant":"browser:bank"`, 1))) + "." + parts[2]
	if _, err := Verify(forged, pubs, now); err == nil {
		t.Error("a changed grant verified")
	}
	other, _, _ := keys(t)
	stranger, _ := Issue(other, "iss", credentialFor(holder, now), now)
	if _, err := Verify(stranger, pubs, now); err == nil {
		t.Error("a credential another issuer signed verified")
	}
	if _, err := Verify(tok, pubs, now.Add(25*time.Hour)); err == nil {
		t.Error("an expired credential verified")
	}
	long := credentialFor(holder, now)
	long.ValidUntil = now.Add(MaxValid + time.Hour)
	if _, err := Issue(issuer, "iss", long, now); err == nil {
		t.Error("a credential longer than the maximum was issued")
	}
	bad := credentialFor(holder, now)
	bad.Grant = "everything"
	if _, err := Issue(issuer, "iss", bad, now); err == nil {
		t.Error("a credential with no grant this reads was issued")
	}
	h := parts[0]
	hb, _ := b64.DecodeString(h)
	none := b64.EncodeToString([]byte(strings.Replace(string(hb), `"EdDSA"`, `"none"`, 1))) + "." + parts[1] + "."
	if _, err := Verify(none, pubs, now); err == nil {
		t.Error("an unsigned credential verified")
	}
}

// A proof is good for one request, by the key the credential is bound to,
// within a minute, once.
func TestAProofIsGoodForOneRequestOnce(t *testing.T) {
	now := time.Now()
	issuer, pubs, holder := keys(t)
	tok, _ := Issue(issuer, "iss", credentialFor(holder, now), now)
	c, _ := Verify(tok, pubs, now)
	url := "https://quilzo.example.com/mcp/browser/shop"
	replays := &Replays{}
	p, err := Prove(holder, tok, "POST", url, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckProof(c, p, "POST", url, now, replays); err != nil {
		t.Fatal(err)
	}
	if err := CheckProof(c, p, "POST", url, now, replays); err == nil {
		t.Error("a proof was accepted twice")
	}
	fresh := func() string { p, _ := Prove(holder, tok, "POST", url, now); return p }
	for _, c2 := range []struct {
		name, method, url string
		at                time.Time
	}{
		{"another method", "GET", url, now},
		{"another address", "POST", url + "x", now},
		{"too old", "POST", url, now.Add(2 * time.Minute)},
	} {
		if err := CheckProof(c, fresh(), c2.method, c2.url, c2.at, replays); err == nil {
			t.Errorf("a proof was accepted for %s", c2.name)
		}
	}
	_, thief, _ := ed25519.GenerateKey(rand.Reader)
	stolen, _ := Prove(thief, tok, "POST", url, now)
	if err := CheckProof(c, stolen, "POST", url, now, replays); err == nil {
		t.Error("a proof signed by another key was accepted: a copied credential worked")
	}
	otherTok, _ := Issue(issuer, "iss", credentialFor(holder, now), now)
	forOther, _ := Prove(holder, otherTok, "POST", url, now)
	if err := CheckProof(c, forOther, "POST", url, now, replays); err == nil {
		t.Error("a proof made for another credential was accepted")
	}
}

// did:key round-trips, and an Ed25519 one looks like every other.
func TestDIDKeyRoundTrips(t *testing.T) {
	_, holder, _ := ed25519.GenerateKey(rand.Reader)
	pub := holder.Public().(ed25519.PublicKey)
	did := DIDKey(pub)
	if !strings.HasPrefix(did, "did:key:z6Mk") {
		t.Fatalf("%s is not shaped as an Ed25519 did:key", did)
	}
	back, err := PublicFromDIDKey(did)
	if err != nil || !back.Equal(pub) {
		t.Fatalf("the did:key did not come back: %v", err)
	}
	if _, err := PublicFromDIDKey("did:key:z0OIl"); err == nil {
		t.Error("characters outside base58 were read")
	}
}

// What an agent's proof is held to, pinned before it shares a verifier
// with DPoP: a minute either side of now, the address exactly as the
// request reached it (no query, case or port forgiven, unlike DPoP's), the
// method in any case, and a proof remembered for as long as one could
// still be presented, so even one dated a minute ahead is good once.
func TestAnAgentProofKeepsItsOneMinuteWindowAndItsExactAddress(t *testing.T) {
	now := time.Unix(1787000000, 0)
	issuer, pubs, holder := keys(t)
	tok, _ := Issue(issuer, "iss", credentialFor(holder, now), now)
	c, err := Verify(tok, pubs, now)
	if err != nil {
		t.Fatal(err)
	}
	url := "https://quilzo.example.com/mcp/browser/shop"
	at := func(made time.Time, method, url string) string {
		p, err := Prove(holder, tok, method, url, made)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, w := range []struct {
		name string
		made time.Time
		ok   bool
	}{
		{"a minute old", now.Add(-ProofWindow), true},
		{"a minute and a second old", now.Add(-ProofWindow - time.Second), false},
		{"a minute ahead", now.Add(ProofWindow), true},
		{"a minute and a second ahead", now.Add(ProofWindow + time.Second), false},
	} {
		err := CheckProof(c, at(w.made, "POST", url), "POST", url, now, &Replays{})
		if (err == nil) != w.ok {
			t.Errorf("a proof %s: %v", w.name, err)
		}
	}
	if ProofWindow != time.Minute {
		t.Errorf("the window is %s", ProofWindow)
	}

	for _, other := range []string{
		url + "?x=1", url + "/", "https://QUILZO.example.com/mcp/browser/shop",
		"https://quilzo.example.com:443/mcp/browser/shop", "http://quilzo.example.com/mcp/browser/shop",
		"https://quilzo.example.com/mcp/browser/bank",
	} {
		if err := CheckProof(c, at(now, "POST", other), "POST", url, now, &Replays{}); err == nil {
			t.Errorf("a proof for %s was accepted at %s", other, url)
		}
	}
	if err := CheckProof(c, at(now, "post", url), "POST", url, now, &Replays{}); err != nil {
		t.Errorf("the method is compared in any case, and was refused: %v", err)
	}
	if err := CheckProof(c, at(now, "GET", url), "POST", url, now, &Replays{}); err == nil {
		t.Error("a proof for GET was accepted for POST")
	}

	// Dated a minute ahead, it is in its window until two minutes from
	// now; the replays remember it that long.
	replays := &Replays{}
	ahead := at(now.Add(ProofWindow), "POST", url)
	if err := CheckProof(c, ahead, "POST", url, now, replays); err != nil {
		t.Fatal(err)
	}
	if err := CheckProof(c, ahead, "POST", url, now.Add(2*ProofWindow), &Replays{}); err != nil {
		t.Fatalf("two minutes on, the proof is out of its window, so this test proves nothing: %v", err)
	}
	if err := CheckProof(c, ahead, "POST", url, now.Add(2*ProofWindow), replays); err == nil {
		t.Error("a proof was accepted twice, the second time on the last moment of its window")
	}
	if err := CheckProof(c, at(now, "POST", url), "POST", url, now, nil); err == nil {
		t.Error("a proof was accepted with nothing to remember it")
	}
}
