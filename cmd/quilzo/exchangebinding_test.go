// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Exchanging a copied long-lived bearer token for a fifteen-minute session
// gets round nothing: from another machine the session may do what the
// token may, and publishing and administering take a key its holder chose
// or a credential that is short from the start.
func TestASessionExchangedFromABearerTokenCannotDoWhatTheTokenCannot(t *testing.T) {
	root := featureSite(t)
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	long, _, err := ts.Issue("ci", "dana", auth.RoleAdmin, "/", 30*24*time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for _, thumb := range []string{"", "copiers-key"} {
		_, sess, err := ts.ExchangeProved(long, auth.RoleNone, "", 0, thumb, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := remoteRefusal(root, remoteCaller(sess), auth.RolePublisher); err == nil ||
			!strings.Contains(err.Error(), "session exchanged") {
			t.Errorf("a session exchanged from a bearer token (proved by %q) published: %v", thumb, err)
		}
		if err := riskyNeedsProof(root, programCaller(sess), auth.RoleAdmin); err == nil {
			t.Errorf("a session exchanged from a bearer token (proved by %q) installed a feature", thumb)
		}
		if err := remoteRefusal(root, remoteCaller(sess), auth.RoleAuthor); err != nil {
			t.Errorf("drafting with an exchanged session was refused: %v", err)
		}
	}

	owned, ot, err := ts.Issue("program", "dana", auth.RoleAdmin, "/", 7*24*time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.BindKey(ot.ID, "owners-key"); err != nil {
		t.Fatal(err)
	}
	_, fromBound, err := ts.ExchangeProved(owned, auth.RoleNone, "", 0, "owners-key", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := remoteRefusal(root, remoteCaller(fromBound), auth.RoleAdmin); err != nil {
		t.Errorf("a session from a bound token was refused: %v", err)
	}
	_, job, err := ts.IssueFederated("deploy", "ci", auth.RolePublisher, "/", auth.Scope{}, 10*time.Minute, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := remoteRefusal(root, remoteCaller(job), auth.RolePublisher); err != nil {
		t.Errorf("a CI job's own short token was refused: %v", err)
	}
}
