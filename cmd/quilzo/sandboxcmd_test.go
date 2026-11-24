// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/quilzo/quilzo/internal/sandbox"
)

// An extension reads of /etc what a C library reads there, as an agent's
// box does, and not the directory: granted whole, an extension run by a
// Quilzo started as root could read /etc/shadow.
func TestAnExtensionIsNotGrantedTheWholeOfEtc(t *testing.T) {
	wrap := sandboxWrap()
	if wrap == nil {
		t.Skip("this kernel confines nothing")
	}
	argv := wrap([]string{"/usr/bin/true"})
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "--allow" && (argv[i+1] == "/etc" || argv[i+1] == "/etc/") {
			t.Fatalf("an extension may read the whole of /etc: %v", argv)
		}
		if argv[i] == "--allow" && argv[i+1] != "/usr/bin/true" && !sandbox.SystemReadCovers(argv[i+1]) {
			t.Errorf("an extension may read %s, which is not a system read", argv[i+1])
		}
	}
}
