// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dpop"
	"github.com/quilzo/quilzo/internal/federate"
)

// A trust for a GitHub repository pins the repository, is never an
// administrator, and is kept until removed.
func TestATrustNamesTheRepositoryItAdmits(t *testing.T) {
	root := featureSite(t)
	if err := cmdTrust(root, []string{"add", "docs-ci", "--github", "octo/docs", "--ref", "refs/heads/main",
		"--as", "ci:docs", "--role", "author", "--on", "/docs", "--audience", "https://admin.example"}); err != nil {
		t.Fatal(err)
	}
	trusts, err := loadTrusts(root)
	if err != nil || len(trusts) != 1 {
		t.Fatalf("%+v %v", trusts, err)
	}
	got := trusts[0]
	if got.Issuer != federate.GitHub || got.Claims["repository"] != "octo/docs" || got.Claims["ref"] != "refs/heads/main" ||
		got.TTL != "15m0s" {
		t.Errorf("%+v", got)
	}
	for _, bad := range [][]string{
		{"add", "docs-ci", "--github", "octo/docs", "--as", "x", "--role", "author", "--audience", "https://a.example"},
		{"add", "admin-ci", "--github", "octo/docs", "--as", "x", "--role", "admin", "--audience", "https://a.example"},
		{"add", "any-ci", "--issuer", federate.GitHub, "--claim", "ref=refs/heads/main", "--as", "x", "--role", "author", "--audience", "https://a.example"},
		{"add", "long-ci", "--github", "octo/docs", "--as", "x", "--role", "author", "--for", "3h", "--audience", "https://a.example"},
	} {
		if err := cmdTrust(root, bad); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
	if err := cmdTrust(root, []string{"remove", "docs-ci"}); err != nil {
		t.Fatal(err)
	}
	if trusts, _ := loadTrusts(root); len(trusts) != 0 {
		t.Error("the trust was not removed")
	}
}

// A key made here binds a token issued here: the token then works only
// with the key's proofs, and the key itself never reaches the store.
func TestATokenIsBoundToAProgramsKey(t *testing.T) {
	root := featureSite(t)
	keyFile := filepath.Join(t.TempDir(), "program.key")
	if err := tokenKeygen([]string{keyFile}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(keyFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the key is not private to its owner: %v %v", info, err)
	}
	if err := tokenKeygen([]string{keyFile}); err == nil {
		t.Error("an existing key was overwritten")
	}
	if err := cmdToken(root, []string{"issue", "bad", "--principal", "dana", "--key", keyFile}); err == nil {
		t.Error("a private key was taken for binding")
	}
	if err := cmdToken(root, []string{"issue", "program", "--principal", "dana", "--key", keyFile + ".pub"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	var tok auth.Token
	for _, x := range ts.Snapshot() {
		if x.Name == "program" {
			tok = x
		}
	}
	thumb, _ := publicKeyThumbprint(keyFile + ".pub")
	if tok.Key == "" || tok.Key != thumb {
		t.Fatalf("the token is not bound to the key: %+v", tok)
	}
	if time.Unix(tok.ExpiresAt, 0).Sub(time.Unix(tok.CreatedAt, 0)) != 7*24*time.Hour {
		t.Errorf("a program's token lasts %s by default", time.Unix(tok.ExpiresAt, 0).Sub(time.Unix(tok.CreatedAt, 0)))
	}
	key, err := readKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dpop.Prove(key, "POST", "https://admin.example/mcp", "qz_x", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := dpop.Check(proof, "POST", "https://admin.example/mcp", "qz_x", time.Now(), nil); err != nil || got != thumb {
		t.Errorf("the key's proof names %q: %v", got, err)
	}
	raw, _ := os.ReadFile(tokensPath(root))
	if strings.Contains(string(raw), `"d"`) {
		t.Error("the private key reached the store")
	}
	if _, err := ts.Authenticate("qz_not-it", time.Now()); err == nil || errors.Is(err, auth.ErrKeyBound) {
		t.Errorf("%v", err)
	}
}

// From another machine, what a stolen token could do that cannot be undone
// takes a token bound to a key, or a short one; reading and drafting do not.
func TestRiskyActsFromAnotherMachineNeedAProofOrAShortToken(t *testing.T) {
	root := featureSite(t)
	long := &Caller{Name: "dana", Role: auth.RoleAdmin, Remote: true, Verified: true, Life: 7 * 24 * time.Hour}
	if err := remoteRefusal(root, long, auth.RolePublisher); err == nil || !strings.Contains(err.Error(), "DPoP") {
		t.Errorf("a week-long bearer token published from another machine: %v", err)
	}
	if err := remoteRefusal(root, long, auth.RoleAuthor); err != nil {
		t.Errorf("drafting with a bearer token was refused: %v", err)
	}
	bound := *long
	bound.Bound = true
	short := *long
	short.Life = 15 * time.Minute
	for name, c := range map[string]*Caller{"bound to a key": &bound, "a fifteen-minute session": &short} {
		if err := remoteRefusal(root, c, auth.RoleAdmin); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	if err := cmdConfig(root, []string{"set", "token.proof_for_risky", "false", "--accept-risk", "test"}); err != nil {
		t.Fatal(err)
	}
	if err := remoteRefusal(root, long, auth.RolePublisher); err != nil {
		t.Errorf("turned off, the rule still refused: %v", err)
	}
}
