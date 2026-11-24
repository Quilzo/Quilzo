// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An address given to a command with a password in it is recorded, and
// exported, without the password: `quilzo config set site.base_url` for a
// staging site behind a login wrote the address whole into the record of
// the change, so the auditor who reads the log, and the SIEM that takes
// `quilzo siem`, could sign in to it.
func TestASettingsAddressIsRecordedWithoutItsPassword(t *testing.T) {
	root, _ := exportStore(t)
	const address = "https://staging:pa55wordSECRET@staging.example.com"
	if err := cmdConfig(root, []string{"set", "site.base_url", address}); err != nil {
		t.Fatal(err)
	}
	export := filepath.Join(t.TempDir(), "siem.jsonl")
	if err := cmdSiem(root, []string{"jsonl", "-o", export}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{auditPath(root), export} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "pa55wordSECRET") {
			t.Errorf("%s holds the password", filepath.Base(f))
		}
		if !strings.Contains(string(b), "staging.example.com") {
			t.Errorf("%s does not say which site was set", filepath.Base(f))
		}
	}
}
