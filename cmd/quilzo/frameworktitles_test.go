// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// quilzo posture frameworks lists NIS2 and OWASP's agentic list, and names
// each NIS2 point it reads beside its number.
func TestPostureFrameworksNamesNIS2Points(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	tpl := t.TempDir()
	var all, nis2 string
	if _, err := humanOutput(t, func() error {
		_, read := captureStdout(t)
		err := postureFrameworks(root, []string{"--templates", tpl})
		all = read()
		if err != nil {
			return err
		}
		_, read = captureStdout(t)
		err = postureFrameworks(root, []string{"nis2", "--templates", tpl})
		nis2 = read()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"nis2", "NIS2 Directive", "owasp-asi", "OWASP Top 10 for Agentic Applications"} {
		if !strings.Contains(all, want) {
			t.Errorf("posture frameworks does not list %q:\n%s", want, all)
		}
	}
	for _, want := range []string{"Art. 21(2)(i)", "human resources security, access control policies and asset management"} {
		if !strings.Contains(nis2, want) {
			t.Errorf("posture frameworks nis2 does not say %q:\n%s", want, nis2)
		}
	}
}
