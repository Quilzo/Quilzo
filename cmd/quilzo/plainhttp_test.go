// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// An http:// issuer, metadata address or webhook is refused with its own
// reason, not with content import's: "imported content gets published"
// told somebody setting up sign-in, or a webhook, about somebody else's
// risk.
func TestPlainHTTPIsRefusedWithTheReasonThatApplies(t *testing.T) {
	root := connectStore(t)
	for name, try := range map[string]func() error{
		"an http issuer": func() error {
			return oidcConfigure(root, []string{"--issuer", "http://localhost:18080/realms/quilzo",
				"--client-id", "x", "--redirect-uri", "http://localhost:18090/auth/callback"})
		},
		"http metadata": func() error {
			_, err := samlAdd(root, []string{"kc", "--metadata",
				"http://localhost:18080/realms/quilzo/protocol/saml/descriptor", "--url", "http://localhost:18090"})
			return err
		},
		"an http webhook": func() error {
			return hookAdd(root, []string{"http://receiver.example/hook"})
		},
	} {
		err := try()
		if err == nil || !strings.Contains(err.Error(), "only https") {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(err.Error(), "Imported content") || strings.Contains(err.Error(), "publish") {
			t.Errorf("%s is refused with content import's reason: %v", name, err)
		}
	}
}
