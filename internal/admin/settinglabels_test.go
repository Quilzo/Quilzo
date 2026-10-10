// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/config"
)

// Every group on Settings is named in words. A group whose heading is its
// raw key (mcp, a2a, guardrail) sat beside "Signing in" and "API tokens", and
// the one that was weaker than its default was the one labelled "mcp".
func TestEverySettingsGroupHasALabel(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range config.New().Effectives() {
		g, _, _ := strings.Cut(e.Setting.Key, ".")
		if seen[g] {
			continue
		}
		seen[g] = true
		if settingGroupLabel(g) == g {
			t.Errorf("the settings group %q has no label: add it to settingGroupLabel", g)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no settings were listed")
	}
}
