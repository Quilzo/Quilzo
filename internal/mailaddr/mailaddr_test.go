// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mailaddr

import (
	"strings"
	"testing"
)

func TestAnAddressIsJudgedOneWay(t *testing.T) {
	for addr, want := range map[string]bool{
		"you@example.com":                        true,
		"First.Last+tag@shop.example.co.uk":      true,
		"a@b.c":                                  true,
		"x@a.b.":                                 true,
		strings.Repeat("a", 64) + "@x.org":       true,
		strings.Repeat("a", 65) + "@x.org":       false,
		"a@" + strings.Repeat("d", 248) + ".org": true,
		"a@" + strings.Repeat("d", 249) + ".org": false,
		"":                                       false,
		"you":                                    false,
		"@example.com":                           false,
		"you@":                                   false,
		"you@example":                            false,
		"you@example.":                           false,
		"you@.example.com":                       false,
		"you@ex@ample.com":                       false,
		`"you"@example.com`:                      false,
		"<you@example.com>":                      false,
		"You <you@example.com>":                  false,
		"you @example.com":                       false,
		"you@example.com\n":                      false,
		"you@exa mple.com":                       false,
		"you\x00@example.com":                    false,
	} {
		if got := Valid(addr); got != want {
			t.Errorf("Valid(%q) = %v, want %v", addr, got, want)
		}
	}
}
