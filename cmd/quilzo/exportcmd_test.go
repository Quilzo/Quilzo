// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An OCSF or CEF export is named for what it is, not called altered: the
// check needs each event whole, which only JSON Lines carries.
func TestSiemVerifyNamesAFormatItCannotCheck(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "envelope.json")
	if err := os.WriteFile(env, []byte(`{"first_seq":1,"last_seq":1,"hashes":["ab"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, line := range map[string]string{
		"OCSF": `{"class_uid":3002,"metadata":{"uid":"ab"}}`,
		"CEF":  `CEF:0|rsh1k|quilzo|1|auth.granted|auth.granted|3|cs3Label=eventHash cs3=ab cs4Label=sequence cs4=1`,
	} {
		file := filepath.Join(dir, name+".log")
		if err := os.WriteFile(file, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := cmdSiemVerify(dir, []string{file, "--envelope", env})
		if err == nil || !strings.Contains(err.Error(), name+" export") || strings.Contains(err.Error(), "altered") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if exportFormatOf(`{"seq":1,"hash":"ab","prev":""}`) != "" {
		t.Error("a JSON Lines audit event was taken for another format")
	}
}
