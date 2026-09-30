// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package auth

import (
	"testing"
	"time"
)

// TestASignInSessionIsASession.
//
// OIDC and passkey sign-in minted their credentials with Issue, which gave
// them no parent, so IsSession said false and signing out left them working
// for eight hours. IssueSession marks them.
func TestASignInSessionIsASession(t *testing.T) {
	ts := &TokenStore{}
	_, tok, err := ts.IssueSession("oidc:dana", "dana", RoleAuthor, "/",
		8*time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if !tok.IsSession() {
		t.Fatal("a sign-in session does not report itself as one")
	}
	// And an ordinary token still is not.
	_, own, err := ts.Issue("laptop", "dana", RoleAuthor, "/", 30*24*time.Hour,
		RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if own.IsSession() {
		t.Fatal("somebody's own long-lived token reports as a session")
	}
	// A session cannot be exchanged for another, whichever way it was made.
	secret, _, err := ts.IssueSession("passkey:dana", "dana", RoleAuthor, "/",
		time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ts.Exchange(secret, RoleNone, "", time.Hour,
		time.Now()); err == nil {
		t.Fatal("a sign-in session was exchanged for a fresh one")
	}
}

// TestASessionCannotBeAskedToLastADay.
func TestASessionCannotBeAskedToLastADay(t *testing.T) {
	ts := &TokenStore{}
	_, tok, err := ts.IssueSession("oidc:dana", "dana", RoleAuthor, "/",
		72*time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if life := time.Duration(tok.ExpiresAt-tok.CreatedAt) * time.Second; life > MaxSessionTTL {
		t.Fatalf("a session lasts %s, over the %s cap", life, MaxSessionTTL)
	}
}

// TestOldSessionsAreClearedAndTokensAreNot.
//
// Every sign-in adds a session. Those that ended more than a day ago are
// removed when the next one is minted; nothing else is — not a live session,
// not a recently ended one, and never somebody's own token, however long ago
// it expired.
func TestOldSessionsAreClearedAndTokensAreNot(t *testing.T) {
	ts := &TokenStore{}
	now := time.Now()
	long := now.Add(-30 * 24 * time.Hour).Unix()
	ts.Tokens = []Token{
		{ID: "own-expired", Principal: "dana", Role: RoleAuthor,
			ExpiresAt: long},
		{ID: "old-session", Principal: "dana", Role: RoleAuthor,
			Session: true, ExpiresAt: long},
		{ID: "old-exchanged", Principal: "dana", Role: RoleAuthor,
			Parent: "own-expired", ExpiresAt: long},
		{ID: "recent-session", Principal: "dana", Role: RoleAuthor,
			Session: true, ExpiresAt: now.Add(-time.Hour).Unix()},
		{ID: "live-session", Principal: "dana", Role: RoleAuthor,
			Session: true, ExpiresAt: now.Add(time.Hour).Unix()},
	}
	if _, _, err := ts.IssueSession("oidc:dana", "dana", RoleAuthor, "/",
		time.Hour, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tok := range ts.Tokens {
		have[tok.ID] = true
	}
	for id, want := range map[string]bool{
		"own-expired": true, "old-session": false, "old-exchanged": false,
		"recent-session": true, "live-session": true,
	} {
		if have[id] != want {
			t.Errorf("%s kept=%v, want %v", id, have[id], want)
		}
	}
	if len(ts.Tokens) != 4 {
		t.Fatalf("%d tokens, want the three kept and the new one", len(ts.Tokens))
	}
}
