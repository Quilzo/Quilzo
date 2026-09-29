// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
)

// TestEveryDetailNamingAPersonIsPseudonymised, read from the source.
//
// The audit log pseudonymises values under audit.IdentityKeys. A writer that
// puts a person's name under a key not on that list writes it in clear, and
// nothing at runtime can tell — so this reads every audit detail in the
// program for a map entry whose value is a principal and checks its key.
func TestEveryDetailNamingAPersonIsPseudonymised(t *testing.T) {
	re := regexp.MustCompile(`"([a-z_]+)":\s*(caller\.Name|p\.Name|tok\.Principal|d\.By|\*author|who\.Name)\b`)
	var files []string
	for _, dir := range []string{".", "../../internal"} {
		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(path, ".go") &&
				!strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		})
	}
	found := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			// WebAuthn's user entity and the SIEM export's own schema are not
			// audit details.
			if strings.HasSuffix(f, "passkeys.go") || strings.HasSuffix(f, "siem.go") {
				continue
			}
			found++
			if !audit.IdentityKeys[m[1]] {
				t.Errorf("%s writes a person under %q, which the audit log does "+
					"not pseudonymise; add it to audit.IdentityKeys or rename it",
					f, m[1])
			}
		}
	}
	if found < 10 {
		t.Fatalf("found %d identity details; the scan is looking in the wrong place", found)
	}
}
