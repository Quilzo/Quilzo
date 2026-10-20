// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/posture"
)

// The provisioning token works for the days it was made for and not
// after; one kept from before tokens ended is given an end, no sooner
// than a month away, and still works until then.
func TestTheProvisioningTokenEnds(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if _, _, err := newSCIMToken(root, scimTokenMaxDays+1); err == nil {
		t.Error("a token longer than a year was made")
	}
	token, kept, err := newSCIMToken(root, 10)
	if err != nil {
		t.Fatal(err)
	}
	if d := kept.Expires.Sub(kept.Created); d != 10*24*time.Hour {
		t.Errorf("a ten-day token lasts %s", d)
	}
	if !scimAuthenticate(root, token) {
		t.Fatal("a fresh token was refused")
	}
	if scimAuthenticate(root, token+"x") {
		t.Fatal("another token was accepted")
	}
	kept.Expires = time.Now().Add(-time.Minute)
	if err := saveSCIMToken(root, kept); err != nil {
		t.Fatal(err)
	}
	if scimAuthenticate(root, token) {
		t.Error("a token that had ended was accepted")
	}
	if f := Observe(root, t.TempDir(), posture.ServerFacts{}).SSO.SCIMTokenEnds; !f.Equal(kept.Expires) {
		t.Errorf("posture sees the token ending %s", f)
	}

	old := "qzscim_from-before"
	sum := sha256.Sum256([]byte(old))
	if err := os.WriteFile(scimTokenPath(root), []byte(hex.EncodeToString(sum[:])), 0o600); err != nil {
		t.Fatal(err)
	}
	year := time.Now().AddDate(-1, 0, 0)
	if err := os.Chtimes(scimTokenPath(root), year, year); err != nil {
		t.Fatal(err)
	}
	if !scimAuthenticate(root, old) {
		t.Fatal("a token kept from before tokens ended stopped working at once")
	}
	got, ok, err := readSCIMToken(root, time.Now())
	if err != nil || !ok || got.Expires.Before(time.Now().Add(scimTokenGrace-time.Hour)) {
		t.Errorf("the old token was given an end of %s: %v", got.Expires, err)
	}
	if b, _ := os.ReadFile(scimTokenPath(root)); len(b) == 0 || b[0] != '{' {
		t.Error("the end given to the old token was not kept")
	}
}
