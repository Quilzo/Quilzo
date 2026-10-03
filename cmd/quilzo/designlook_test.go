// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"strings"
	"testing"
)

// A store with nothing drafted says so when asked to publish, rather than
// failing a gate on the absence of a commit: "not an object id" sent a first
// publish off looking for a broken image.
func TestPublishingNothingSaysThereIsNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	err := cmdPublish(root, []string{"-templates", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "nothing to publish") || strings.Contains(err.Error(), "object id") {
		t.Errorf("publishing an empty store: %v", err)
	}
}
