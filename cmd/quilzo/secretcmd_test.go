// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/vault"
)

// keyedStore is a store with a keyring, its key supplied the way an
// operator would.
func keyedStore(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	kr, err := vault.NewKeyring("k1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(keyEnv, vault.EncodeKey(kr.Keys["k1"].Key))
	if err := saveJSON(keyringPath(root), kr); err != nil {
		t.Fatal(err)
	}
	return root
}

// An agent's credential is kept sealed: the file alone gives nobody the
// value, an integration reads it by name, and the environment still wins.
func TestAnAgentsCredentialIsKeptSealed(t *testing.T) {
	root := keyedStore(t)
	if err := setAgentSecret(root, "crm-login", "hunter2-correct-horse", "dana", time.Now()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(agentSecretsPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hunter2") {
		t.Fatal("the credential is in the file as it was given")
	}
	if fi, _ := os.Stat(agentSecretsPath(root)); fi.Mode().Perm() != 0o600 {
		t.Errorf("the file is mode %v", fi.Mode().Perm())
	}
	got, err := readSecret(root, "crm-login")
	if err != nil || got != "hunter2-correct-horse" {
		t.Fatalf("read %q, %v", got, err)
	}
	t.Setenv(secretEnvName("crm-login"), "from-the-environment")
	if got, _ := readSecret(root, "crm-login"); got != "from-the-environment" {
		t.Errorf("the environment did not win: %q", got)
	}
	// Sealed for its own name: moved under another, it does not open.
	f, _ := loadAgentSecrets(root)
	f.Sealed["other"] = f.Sealed["crm-login"]
	if err := saveAgentSecrets(root, f); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sealedSecret(root, "other"); err == nil {
		t.Error("a credential copied to another name opened under it")
	}
}

// Without a keyring nothing is kept, rather than kept readable.
func TestAnAgentsCredentialIsRefusedWithoutAKeyring(t *testing.T) {
	root := t.TempDir()
	err := setAgentSecret(root, "crm-login", "hunter2", "dana", time.Now())
	if err == nil || !strings.Contains(err.Error(), "vault enable") {
		t.Fatalf("kept without a keyring: %v", err)
	}
	if _, err := os.Stat(agentSecretsPath(root)); !os.IsNotExist(err) {
		t.Error("a file was written")
	}
	if _, err := readSecret(root, "crm-login"); err == nil || !strings.Contains(err.Error(), "quilzo secret set") {
		t.Errorf("a missing credential says %v", err)
	}
}

func TestACredentialsNameAndValueAreChecked(t *testing.T) {
	for _, bad := range []string{"", "Upper", "../x", "a b", strings.Repeat("a", 65)} {
		if reSecretName.MatchString(bad) {
			t.Errorf("%q was taken as a name", bad)
		}
	}
	if _, err := checkSecretValue(""); err == nil {
		t.Error("an empty value was kept")
	}
	if _, err := checkSecretValue(strings.Repeat("x", MaxSecretBytes+1)); err == nil {
		t.Error("an oversized value was kept")
	}
}
