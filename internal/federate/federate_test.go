// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package federate

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oidc"
)

type keyOf struct{ k crypto.PublicKey }

func (k keyOf) Key(string) (crypto.PublicKey, error) { return k.k, nil }

func signer(t *testing.T) (*rsa.PrivateKey, Keys) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key, func(_ context.Context, issuer string) (oidc.KeySource, []oidc.Algorithm, error) {
		if issuer != GitHub {
			return nil, nil, errors.New("unknown issuer")
		}
		return keyOf{&key.PublicKey}, []oidc.Algorithm{oidc.RS256}, nil
	}
}

func sign(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func job(now time.Time) map[string]any {
	return map[string]any{
		"iss": GitHub, "aud": "https://admin.example", "sub": "repo:octo/docs:ref:refs/heads/main",
		"repository": "octo/docs", "ref": "refs/heads/main", "repository_id": "456789",
		"run_id": "9876", "jti": "jti-" + now.Format("150405.000000000"),
		"iat": float64(now.Add(-time.Minute).Unix()), "nbf": float64(now.Add(-time.Minute).Unix()),
		"exp": float64(now.Add(5 * time.Minute).Unix()),
	}
}

var docs = Trust{Name: "docs-ci", Issuer: GitHub, Audience: "https://admin.example",
	Claims:    map[string]string{"repository": "octo/docs", "ref": "refs/heads/*"},
	Principal: "ci:docs", Role: auth.RoleAuthor, Resource: "/docs", TTL: "15m"}

// A job whose token names the repository and branch a trust pins is
// admitted, once.
func TestAJobIsAdmittedByTheTrustItsClaimsMatch(t *testing.T) {
	key, keys := signer(t)
	now := time.Now()
	token := sign(t, key, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"}, job(now))
	var seen Replays
	got, claims, err := Admit(context.Background(), token, []Trust{docs}, keys, now, &seen)
	if err != nil || got.Name != "docs-ci" || claims["run_id"] != "9876" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, _, err := Admit(context.Background(), token, []Trust{docs}, keys, now, &seen); err == nil {
		t.Error("the same token was exchanged twice")
	}
}

// Every claim, the audience, the times, the issuer and the signature are
// held to what the trust says.
func TestATokenNoTrustAdmitsIsRefused(t *testing.T) {
	key, keys := signer(t)
	other, _ := signer(t)
	now := time.Now()
	head := map[string]any{"alg": "RS256", "typ": "JWT"}
	with := func(edit func(map[string]any)) map[string]any {
		c := job(now)
		edit(c)
		return c
	}
	for name, token := range map[string]string{
		"another repository":  sign(t, key, head, with(func(c map[string]any) { c["repository"] = "octo/payroll" })),
		"a tag, not a branch": sign(t, key, head, with(func(c map[string]any) { c["ref"] = "refs/tags/v1" })),
		"another audience":    sign(t, key, head, with(func(c map[string]any) { c["aud"] = "https://github.com/octo" })),
		"expired":             sign(t, key, head, with(func(c map[string]any) { c["exp"] = float64(now.Add(-2 * time.Minute).Unix()) })),
		"issued long ago":     sign(t, key, head, with(func(c map[string]any) { c["iat"] = float64(now.Add(-2 * time.Hour).Unix()) })),
		"another issuer":      sign(t, key, head, with(func(c map[string]any) { c["iss"] = "https://evil.example" })),
		"no repository":       sign(t, key, head, with(func(c map[string]any) { delete(c, "repository") })),
		"signed by another":   sign(t, other, head, job(now)),
		"no algorithm":        strings.Join(strings.Split(sign(t, key, map[string]any{"alg": "none"}, job(now)), ".")[:2], ".") + ".",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Admit(context.Background(), token, []Trust{docs}, keys, now, &Replays{}); err == nil {
				t.Error("admitted")
			}
		})
	}
}

// A trust names the workload exactly, never makes an administrator, and
// gives a short life.
func TestATrustIsNarrowByDeclaration(t *testing.T) {
	if err := docs.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Trust){
		"no workload pinned":  func(t *Trust) { t.Claims = map[string]string{"ref": "refs/heads/main"} },
		"a wildcard workload": func(t *Trust) { t.Claims = map[string]string{"repository": "octo/*"} },
		"an administrator":    func(t *Trust) { t.Role = auth.RoleAdmin },
		"a day's token":       func(t *Trust) { t.TTL = "24h" },
		"plain http":          func(t *Trust) { t.Issuer = "http://token.example" },
		"no audience":         func(t *Trust) { t.Audience = "" },
	} {
		t.Run(name, func(t *testing.T) {
			tr := docs
			tr.Claims = map[string]string{"repository": "octo/docs"}
			edit(&tr)
			if err := tr.Validate(); err == nil {
				t.Error("accepted")
			}
		})
	}
}
