// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/dual"
)

// An identity provider on the organisation's own network, the usual
// Keycloak, AD FS or Authentik, could not be used: an issuer or metadata
// address on a private or loopback address was refused, and nothing could
// say otherwise. sso.reach names the ranges it may be at. It is weaker than
// the default, so it takes a reason and a second administrator, and it
// opens those ranges and nothing else.
func TestAnIdentityProviderOnThePrivateNetworkIsReachedOnlyWhereDeclared(t *testing.T) {
	root := connectStore(t)
	configure := func(issuer string) error {
		return oidcConfigure(root, []string{"--issuer", issuer, "--client-id", "x",
			"--redirect-uri", "https://admin.qz.test/auth/callback"})
	}
	err := configure("https://172.18.0.4:8443/realms/quilzo")
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("a private issuer with nothing declared: %v", err)
	}
	if !strings.Contains(err.Error(), "sso.reach") {
		t.Errorf("the refusal does not say how to reach a provider on the network: %v", err)
	}

	if s, ok := config.Lookup("sso.reach"); !ok {
		t.Fatal("there is no sso.reach setting")
	} else if weaker, _ := s.IsWeaker("172.18.0.0/16"); !weaker {
		t.Error("opening a private range is not weaker than the default")
	}
	if second, _ := dual.SettingNeedsSecond(config.New(), "sso.reach", "172.18.0.0/16"); !second {
		t.Error("opening a private range to sign-in does not wait for a second administrator")
	}
	for _, bad := range []string{"169.254.169.254", "169.254.0.0/16", "0.0.0.0/0", "8.8.8.0/24", "nonsense"} {
		if err := configSet(root, []string{"sso.reach", bad, "--accept-risk", "test"}); err == nil {
			t.Errorf("sso.reach %s was accepted", bad)
		}
	}
	if err := configSet(root, []string{"sso.reach", "172.18.0.0/16"}); err == nil {
		t.Error("sso.reach was set with no reason given")
	}
	if err := configSet(root, []string{"sso.reach", "172.18.0.0/16,127.0.0.1",
		"--accept-risk", "Keycloak runs on the internal network"}); err != nil {
		t.Fatal(err)
	}

	if err := configure("https://172.18.0.4:8443/realms/quilzo"); err != nil {
		t.Errorf("an issuer inside the declared range: %v", err)
	}
	if err := configure("https://10.1.2.3/realms/quilzo"); err == nil {
		t.Error("an issuer outside the declared range was accepted")
	}
	if err := configure("https://169.254.169.254/latest"); err == nil {
		t.Error("the metadata endpoint was accepted")
	}

	// The metadata is fetched through the same rule: loopback, declared,
	// is dialled (and nothing answers on port 1), where before it was
	// refused before anything was dialled.
	_, err = samlAdd(root, []string{"kc", "--metadata", "https://127.0.0.1:1/descriptor",
		"--url", "https://admin.qz.test"})
	if err == nil || strings.Contains(err.Error(), "refusing to") {
		t.Errorf("metadata on a declared address: %v", err)
	}
	_, err = samlAdd(root, []string{"kc", "--metadata", "https://10.1.2.3/descriptor",
		"--url", "https://admin.qz.test"})
	if err == nil || !strings.Contains(err.Error(), "refusing to") {
		t.Errorf("metadata outside the declared range: %v", err)
	}
	if strings.Count(err.Error(), "sso.reach") != 1 {
		t.Errorf("the refusal does not say how to reach the provider, once: %v", err)
	}
	// The Single sign-on screen fetches through samlFetch, and its refusal
	// said nothing of sso.reach, so somebody adding a provider there was
	// refused with no word of the way through.
	if _, err := samlFetch(root, "https://10.1.2.3/descriptor"); err == nil ||
		!strings.Contains(err.Error(), "sso.reach") {
		t.Errorf("the screen's fetch is refused without saying how to reach the provider: %v", err)
	}
}
