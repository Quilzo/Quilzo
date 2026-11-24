// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Every command that names a page takes the pages the store holds.
//
// `quilzo add About_Us=… docs/v1.2=…` wrote them, and then `quilzo
// experiment add` said "About_Us" is not a page name and `quilzo
// personalise add` said its rule needed two different pages, when it had
// two: each kept its own idea of a page name.
func TestEverySurfaceAcceptsThePagesTheStoreHolds(t *testing.T) {
	root := newStoreWithDraft(t)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	if err := os.WriteFile(a, []byte(`{"title":"About us","body":"Who we are."}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(`{"title":"About us B","body":"Who we are, again."}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCmd(t, root, "add", "About_Us="+a, "About_Us-b="+b, "docs/v1.2="+a, "-m", "x7"); err != nil {
		t.Fatal(err)
	}
	if err := cmdExperiment(root, []string{"add", "x7test", "--page", "About_Us", "--variant", "b=About_Us-b",
		"--goal", "page:/contact"}); err != nil {
		t.Errorf("an experiment on About_Us: %v", err)
	}
	if err := cmdPersonalise(root, []string{"add", "x7p", "--page", "docs/v1.2", "--variant", "About_Us-b",
		"--when", "campaign=spring"}); err != nil {
		t.Errorf("a rule serving About_Us-b at docs/v1.2: %v", err)
	}
}
