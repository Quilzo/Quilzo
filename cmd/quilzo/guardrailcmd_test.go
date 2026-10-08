// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"strings"
	"testing"
)

func TestAGuardrailIsConfiguredOrRefusedWithTheReason(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	set := func(kind, url string) {
		t.Helper()
		cfg := mustConfig(root)
		for k, v := range map[string]string{"guardrail.kind": kind, "guardrail.url": url} {
			if err := cfg.Set(k, v, "a guardrail is tried", "test"); err != nil {
				t.Fatal(err)
			}
		}
		if err := saveConfig(root, cfg); err != nil {
			t.Fatal(err)
		}
	}
	if s, err := guardrailService(root); s != nil || err != nil {
		t.Fatalf("none set: %v %v", s, err)
	}
	set("lakera", "")
	t.Setenv("QUILZO_GUARDRAIL_KEY", "k")
	if s, err := guardrailService(root); err != nil || s == nil || s.URL != "https://api.lakera.ai/v2/guard" {
		t.Fatalf("%+v %v", s, err)
	}
	set("generic", "http://guard.example/check")
	if _, err := guardrailService(root); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("a key over http: %v", err)
	}
	t.Setenv("QUILZO_GUARDRAIL_KEY", "")
	if s, err := guardrailService(root); err != nil || s == nil {
		t.Fatalf("a keyless classifier on this network: %v", err)
	}
	set("openai", "https://x.example/")
	if _, err := guardrailService(root); err == nil {
		t.Fatal("an unknown kind was accepted")
	}
	set("model-armor", "")
	if _, err := guardrailService(root); err == nil {
		t.Fatal("Model Armor with no address was accepted")
	}
}
