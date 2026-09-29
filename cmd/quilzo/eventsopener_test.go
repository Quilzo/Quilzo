// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// TestViewingTheEventsScreenDoesNotCreateAStore.
//
// spool.Open makes its directory. A read-only screen that called it on a
// site that had never collected anything would leave an empty store behind,
// and from then on "never collected" and "collected nothing" look the same.
func TestViewingTheEventsScreenDoesNotCreateAStore(t *testing.T) {
	root := t.TempDir()
	_, _, err := eventsOpener(root)()
	if !errors.Is(err, admin.ErrNeverCollected) {
		t.Fatalf("opening an absent store answered %v", err)
	}
	if _, serr := os.Stat(spoolDir(root)); !os.IsNotExist(serr) {
		t.Fatalf("viewing the screen created %s", spoolDir(root))
	}
}

// TestTheEventsScreenReadsWhatWasStored, and closing the reader seals
// nothing.
//
// A reader holds no open segment, so Close has nothing to seal and must not
// rewrite the index another process owns.
func TestTheEventsScreenReadsWhatWasStored(t *testing.T) {
	root := t.TempDir()
	w, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := w.Append(telemetry.Event{Source: "idp", Time: now,
		Class: telemetry.ClassAuthentication}); err != nil {
		t.Fatal(err)
	}
	// Still open: the writer has not sealed.
	idx := filepath.Join(spoolDir(root), "index.json")
	before, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}

	sp, closer, err := eventsOpener(root)()
	if err != nil {
		t.Fatal(err)
	}
	if sp.Events() != 1 {
		t.Fatalf("read %d events, want 1", sp.Events())
	}
	if err := closer(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("closing a reader rewrote the store's index")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
