// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
)

// quilzo oidc status says where it looked for the client secret. It said
// "QUILZO_OIDC_SECRET is not set" about the shell it ran in, in yellow,
// while the server, started elsewhere with the secret in its environment,
// signed people in: an operator checking a working setup was told it was
// missing a credential, and nothing said the answer was about this shell.
func TestOIDCStatusSaysWhereItLookedForTheSecret(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(oidcPath(root), &oidcConfig{Issuer: "https://idp.example/realms/q", ClientID: "quilzo",
		RedirectURI: "https://admin.example/oidc/callback", Claim: "email", RequireVerifiedEmail: true}); err != nil {
		t.Fatal(err)
	}
	old := w
	t.Cleanup(func() { w = old })
	status := func(jsonMode bool) string {
		t.Helper()
		var buf bytes.Buffer
		w = out.New(jsonMode)
		w.Out = &buf
		if err := oidcStatus(root); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}

	t.Setenv(oidcSecretEnv, "")
	got := status(false)
	if !strings.Contains(got, oidcSecretEnv+" is not set in this shell") ||
		!strings.Contains(got, "quilzo serve reads it from its own environment") {
		t.Errorf("the line does not say where it looked:\n%s", got)
	}

	t.Setenv(oidcSecretEnv, "a-value-for-this-test")
	if got := status(false); !strings.Contains(got, oidcSecretEnv+" is set in this shell") ||
		!strings.Contains(got, "quilzo serve reads it from its own environment") {
		t.Errorf("with the secret set here, nothing says the server needs its own:\n%s", got)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(status(true)), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["secret_set"] != true || doc["secret_checked_in"] == nil {
		t.Errorf("the JSON does not say where secret_set was looked for: %v", doc)
	}
}
