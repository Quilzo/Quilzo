// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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

// Re-reading the store from disk keeps a use this copy has seen and the
// file has not, and takes everything else from the file.
//
// Replace took the file whole. A server notes a use only in its own copy,
// so whenever the file changed, a sign-in elsewhere or any command, the
// uses since its last save went with the copy: People said of somebody
// who had signed in with a passkey and was working that they had never
// used a credential, while their session was in use that minute.
func TestReplaceKeepsAUseTheFileHasNotSeen(t *testing.T) {
	ts := &TokenStore{}
	secret, tok, err := ts.IssueSession("passkey:dana", "dana", RoleAuthor, "/", 8*time.Hour, RoleAdmin, MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := ts.Issue("ci", "dana", RoleAuthor, "/", 8*time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	onDisk := ts.Snapshot()
	used := time.Now()
	if _, err := ts.Authenticate(secret, used); err != nil {
		t.Fatal(err)
	}
	// The file as another process wrote it since: the use not in it, and
	// the other token revoked there.
	for i := range onDisk {
		if onDisk[i].ID == other.ID {
			onDisk[i].Revoked = true
		}
	}
	ts.Replace(onDisk)
	for _, got := range ts.Snapshot() {
		switch got.ID {
		case tok.ID:
			if got.LastUsed != used.Unix() {
				t.Errorf("re-reading the store lost the session's use: last used %d, not %d", got.LastUsed, used.Unix())
			}
		case other.ID:
			if !got.Revoked {
				t.Error("re-reading the store did not take a revocation from the file")
			}
		}
	}
}

// A token minted for a program another issuer vouched for is a program's,
// whatever the run it was minted for is called.
//
// IssueFederated recorded no kind, so the token was judged by its name as
// one issued before kinds were recorded is: "trust:ci run " and the run's
// id, or the assertion's jti, which the other issuer writes. An id with an
// @ in it made a CI job's token a person's, which could decide an access
// review and was written into the record as a human.
func TestAFederatedTokenIsAProgramsWhateverItsRunIsCalled(t *testing.T) {
	ts := &TokenStore{}
	now := time.Now()
	_, tok, err := ts.IssueFederated("trust:ci run build@main", "svc-ci", RoleAuthor, "/", Scope{}, time.Hour, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Person() || tok.Kind != KindProgram {
		t.Errorf("a federated token is a person's for its name: kind %q", tok.Kind)
	}
}

// A session exchanged from a token issued before kinds were recorded is
// whoever's that token is judged to be.
//
// It took the parent's Kind, which such a token does not have, and was
// judged by its own name: "cli (session)" is not "cli", so the session of
// somebody's own token was a program's, and could not decide the access
// review its parent could.
func TestASessionFromATokenWithNoKindIsJudgedAsItsParent(t *testing.T) {
	ts := &TokenStore{}
	now := time.Now()
	secret, parent, err := ts.Issue("cli", "dana", RoleAdmin, "/", 8*time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if parent.Kind != "" || !parent.Person() {
		t.Fatalf("control: an unrecorded token named cli is a person's: kind %q", parent.Kind)
	}
	_, sess, err := ts.Exchange(secret, RoleNone, "", 10*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if !sess.Person() {
		t.Errorf("the session of a person's token is a program's: %q, kind %q", sess.Name, sess.Kind)
	}

	secret, _, err = ts.Issue("nightly", "svc-ci", RoleAuthor, "/", 8*time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, sess, err = ts.Exchange(secret, RoleNone, "", 10*time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if sess.Person() {
		t.Errorf("the session of a program's token is a person's: %q, kind %q", sess.Name, sess.Kind)
	}
}

// A person's last use of a session, which the admin's idle clock starts a
// session it has not seen from, is written down at most every so often,
// and neither re-reading the store nor writing another copy over it puts
// back an earlier one: either would give a session idle since then a fresh
// period after the admin restarts.
func TestAPersonsUseOfASessionIsKeptWhereverTheStoreGoes(t *testing.T) {
	ts := &TokenStore{}
	_, tok, err := ts.IssueSession("passkey:dana", "dana", RoleAuthor, "/", 8*time.Hour, RoleAdmin, MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	if !ts.NoteActive(tok.ID, at, time.Minute) {
		t.Fatal("the first use was not written down")
	}
	if ts.NoteActive(tok.ID, at.Add(30*time.Second), time.Minute) {
		t.Error("a use thirty seconds later was written down again, so every page rewrites the file")
	}
	if !ts.NoteActive(tok.ID, at.Add(time.Minute), time.Minute) {
		t.Error("a use a minute later was not written down")
	}
	latest := at.Add(time.Minute).Unix()
	active := func(s *TokenStore) int64 {
		for _, k := range s.Snapshot() {
			if k.ID == tok.ID {
				return k.Active
			}
		}
		return -1
	}

	// The file as it was before the last use.
	onDisk := ts.Snapshot()
	for i := range onDisk {
		onDisk[i].Active = at.Unix()
	}
	ts.Replace(append([]Token(nil), onDisk...))
	if got := active(ts); got != latest {
		t.Errorf("re-reading the store put the person's use back to %d, not %d", got, latest)
	}

	// A copy read before the last use, written over the store.
	stale := &TokenStore{Tokens: onDisk}
	stale.MergeInto(ts, time.Now())
	if got := active(ts); got != latest {
		t.Errorf("writing an older copy put the person's use back to %d, not %d", got, latest)
	}
}
