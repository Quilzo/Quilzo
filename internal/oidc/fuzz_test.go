package oidc

import (
	"crypto"
	"testing"
	"time"
)

type nilKey struct{}

func (nilKey) Key(string) (crypto.PublicKey, error) { return nil, nil }

// An ID token is attacker-supplied until its signature verifies, and the
// parsing that happens before verification is the part that has to survive
// anything.
func FuzzVerify(f *testing.F) {
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln", "nonce")
	f.Add("a.b.c", "n")
	f.Add("....", "n")
	f.Add("", "")
	f.Add("eyJhbGciOiJub25lIn0..", "n")

	v := &Verifier{
		Issuer: "https://idp.example", ClientID: "c",
		Algorithms: []Algorithm{RS256, ES256},
		Keys:       nilKey{},
		Now:        func() time.Time { return time.Unix(1786000000, 0) },
	}
	f.Fuzz(func(t *testing.T, token, nonce string) {
		claims, err := v.Verify(token, nonce)
		if err == nil && claims == nil {
			t.Fatal("Verify returned no claims and no error")
		}
		if err == nil {
			// Nothing should ever verify against a nil key.
			t.Fatalf("a token verified with no key: %q", token)
		}
	})
}
