// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/quilzo/quilzo/internal/webhook"
)

// Every event an endpoint can subscribe to is sent from somewhere. Two of
// them — rolled-back and scheduled — were offered, accepted and never sent,
// so a receiver configured for them was told it was configured and then
// heard nothing: the silent subscription the closed list was made to stop.
func TestEveryWebhookEventIsSentFromSomewhere(t *testing.T) {
	sent := map[string]bool{}
	call := regexp.MustCompile(`(?:fireWebhooks\(root,\s*|Told\(|s\.tell\(|Type:\s*)"([a-z-]+)"`)
	for _, dir := range []string{".", filepath.Join("..", "..", "internal", "admin")} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if regexp.MustCompile(`_test\.go$`).MatchString(f) {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range call.FindAllStringSubmatch(string(b), -1) {
				sent[m[1]] = true
			}
		}
	}
	for _, e := range webhook.EventTypes {
		if !sent[e] {
			t.Errorf("%q can be subscribed to and is sent from nowhere", e)
		}
	}
}
