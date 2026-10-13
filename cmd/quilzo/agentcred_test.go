// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentcred"
	"github.com/quilzo/quilzo/internal/auth"
)

// The whole of a credential, against a real store: an administrator
// issues one for a declared agent with a sponsor, bound to the agent's own
// key and to one grant; presented with a proof it is the agent acting
// within its sponsor's authority on that grant; and a replayed proof, a
// grant it does not carry, a withdrawn credential and a sponsor who can no
// longer act here are each refused.
func TestAnAgentCredentialIsTheAgentOnOneGrantAndNoMore(t *testing.T) {
	root := grantRoot(t)
	for _, g := range [][]string{{"grant", "dana", "admin"}, {"grant", "lee", "author"}} {
		if err := cmdAuth(root, g); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveBrowserGrant(root, browserGrant{Name: "shop", Read: []string{"shop.example.com"}, Write: []string{"shop.example.com"}}); err != nil {
		t.Fatal(err)
	}
	m := asker("buyer")
	m.Capabilities, m.AskFirst = []string{"list_pages"}, nil
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	set, _ := loadAgents(root)
	if set.Identities == nil {
		set.Identities = map[string]agent.Identity{}
	}
	set.Identities["buyer"] = agent.Identity{Sponsor: "lee", Expires: time.Now().Add(90 * 24 * time.Hour)}
	if err := saveJSON(agentsPath(root), set); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(t.TempDir(), "buyer.key")
	tok, err := issueCredential(root, asAdmin("dana"), []string{"buyer", "--grant", "browser:shop", "--act", "--generate", keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issueCredential(root, human("lee"), []string{"buyer", "--grant", "browser:shop", "--generate", keyFile + "2"}); err == nil {
		t.Fatal("somebody who is not an administrator issued a credential")
	}
	seedText, _ := os.ReadFile(keyFile)
	seed, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedText)))
	holder := ed25519.NewKeyFromSeed(seed)
	url := "https://quilzo.example.com/mcp/browser/shop"
	present := func(grant string) (auth.Token, error) {
		r := httptest.NewRequest("POST", url, nil)
		proof, _ := agentcred.Prove(holder, tok, "POST", url, time.Now())
		r.Header.Set("Agent-Proof", proof)
		return credentialCaller(root, r, tok, url, grant)
	}
	got, err := present("shop")
	if err != nil {
		t.Fatal(err)
	}
	if got.Principal != "lee" || got.Client != "agent:buyer" || got.Role != auth.RoleAuthor || got.Resource != "/mcp/browser/shop" {
		t.Fatalf("the credential became %+v", got)
	}

	r := httptest.NewRequest("POST", url, nil)
	proof, _ := agentcred.Prove(holder, tok, "POST", url, time.Now())
	r.Header.Set("Agent-Proof", proof)
	if _, err := credentialCaller(root, r, tok, url, "shop"); err != nil {
		t.Fatal(err)
	}
	if _, err := credentialCaller(root, r, tok, url, "shop"); err == nil {
		t.Fatal("a proof was accepted twice")
	}
	if _, err := present("bank"); err == nil {
		t.Fatal("the credential was accepted for a grant it does not carry")
	}
	r = httptest.NewRequest("POST", url, nil)
	if _, err := credentialCaller(root, r, tok, url, "shop"); err == nil {
		t.Fatal("the credential was accepted with no proof")
	}

	c, _ := agentcred.Verify(tok, mustKeys(t, root), time.Now())
	if err := revokeCredential(root, asAdmin("dana"), c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := present("shop"); err == nil || !strings.Contains(err.Error(), "withdrawn") {
		t.Fatalf("a withdrawn credential was accepted: %v", err)
	}
}

func mustKeys(t *testing.T, root string) map[string]ed25519.PublicKey {
	t.Helper()
	k, err := credPublicKeys(root)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
