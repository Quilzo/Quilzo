// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package member

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/webauthn"
)

func newStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "members"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	return s, &now
}

func key(id string) webauthn.Credential {
	return webauthn.Credential{ID: []byte(id), PublicKey: []byte("spki-" + id), Algorithm: -7}
}

func TestAnAccountIsMadeWithAPasskeyAndRecoveryCodes(t *testing.T) {
	s, _ := newStore(t)
	for _, bad := range []string{"", "   ", strings.Repeat("x", MaxName+1), "bell\a"} {
		if _, _, err := s.Create(bad, key("k1")); err == nil {
			t.Errorf("the name %q was accepted", bad)
		}
	}
	if _, _, err := s.Create("Ada", webauthn.Credential{}); err == nil {
		t.Error("an account was made with no passkey")
	}
	m, codes, err := s.Create("  Ada  ", key("k1"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "Ada" || len(m.Passkeys) != 1 || m.Recovery != RecoveryCodes || len(codes) != RecoveryCodes {
		t.Fatalf("the account is %+v with %d codes", m, len(codes))
	}
	if m.Passkeys[0].Principal != m.ID {
		t.Error("the passkey does not name the account it signs in to")
	}
	if _, _, err := s.Create("Eve", key("k1")); err == nil {
		t.Error("one passkey was made to sign in to two accounts")
	}
	got, cred, err := s.ByCredential([]byte("k1"))
	if err != nil || got.ID != m.ID || string(cred.ID) != "k1" {
		t.Errorf("finding the account by its passkey: %v %v", got.ID, err)
	}
	if _, _, err := s.ByCredential([]byte("nobody")); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown passkey: %v", err)
	}
}

// Only hashes of secrets are kept, and nothing is readable by others.
//
// A copy of the directory must sign nobody in: not the session tokens, not
// the recovery codes, not the invitations.
func TestTheStoreHoldsNoSecretAnybodyCouldUse(t *testing.T) {
	s, _ := newStore(t)
	m, codes, _ := s.Create("Ada", key("k1"))
	token, err := s.StartSession(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	invite, _, _ := s.NewInvite("staff", "for Bo")
	secrets := append([]string{token, invite, normaliseCode(invite)}, codes...)
	for _, c := range codes {
		secrets = append(secrets, normaliseCode(c))
	}
	err = filepath.WalkDir(s.Dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, _ := d.Info()
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s is %v", path, info.Mode().Perm())
		}
		b, _ := os.ReadFile(path)
		for _, secret := range secrets {
			if strings.Contains(string(b), secret) || strings.Contains(path, secret) {
				t.Errorf("%s holds a secret in the clear", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestARecoveryCodeWorksOnceHoweverItIsTyped(t *testing.T) {
	s, _ := newStore(t)
	m, codes, _ := s.Create("Ada", key("k1"))
	typed := strings.ToLower(strings.ReplaceAll(codes[0], "-", " "))
	got, err := s.Recover(typed)
	if err != nil || got.ID != m.ID || got.Recovery != RecoveryCodes-1 {
		t.Fatalf("recovering with %q: %+v %v", typed, got, err)
	}
	if _, err := s.Recover(codes[0]); !errors.Is(err, ErrNoCode) {
		t.Errorf("a code worked twice: %v", err)
	}
	if _, err := s.Recover("0000-0000-0000-0000"); !errors.Is(err, ErrNoCode) {
		t.Errorf("a made-up code: %v", err)
	}
	// New codes replace the old ones entirely.
	fresh, err := s.NewRecoveryCodes(m.ID)
	if err != nil || len(fresh) != RecoveryCodes {
		t.Fatal(err)
	}
	if _, err := s.Recover(codes[1]); !errors.Is(err, ErrNoCode) {
		t.Error("an old code still worked after new ones were made")
	}
	if _, err := s.Recover(fresh[0]); err != nil {
		t.Errorf("a new code: %v", err)
	}
	// A disabled account cannot be recovered into.
	_ = s.SetDisabled(m.ID, true)
	if _, err := s.Recover(fresh[1]); !errors.Is(err, ErrDisabled) {
		t.Errorf("recovering a disabled account: %v", err)
	}
}

func TestASessionEndsWhenIdleOldDisabledOrSignedOut(t *testing.T) {
	s, now := newStore(t)
	m, _, _ := s.Create("Ada", key("k1"))
	start := *now
	token, _ := s.StartSession(m.ID)
	if got, err := s.SessionMember(token); err != nil || got.ID != m.ID {
		t.Fatalf("a new session: %v", err)
	}
	for _, bad := range []string{"", "x", token + "x", strings.Repeat("A", 43)} {
		if _, err := s.SessionMember(bad); err == nil {
			t.Errorf("the token %q signed somebody in", bad)
		}
	}

	// Used every week, it lives until its maximum, and then it does not.
	for *now = start; now.Sub(start) < SessionMax-7*24*time.Hour; *now = now.Add(7 * 24 * time.Hour) {
		if _, err := s.SessionMember(token); err != nil {
			t.Fatalf("a session in use ended after %v", now.Sub(start))
		}
	}
	*now = start.Add(SessionMax + time.Minute)
	if _, err := s.SessionMember(token); err == nil {
		t.Error("a session outlived its maximum")
	}

	// Left alone, it ends when idle.
	*now = start
	idle, _ := s.StartSession(m.ID)
	*now = start.Add(SessionIdle + time.Minute)
	if _, err := s.SessionMember(idle); err == nil {
		t.Error("an idle session was still good")
	}

	*now = start
	a, _ := s.StartSession(m.ID)
	b, _ := s.StartSession(m.ID)
	s.EndSession(a)
	if _, err := s.SessionMember(a); err == nil {
		t.Error("signing out did not end the session")
	}
	if _, err := s.SessionMember(b); err != nil {
		t.Error("signing out of one browser signed out another")
	}
	_ = s.SetDisabled(m.ID, true)
	if _, err := s.SessionMember(b); err == nil {
		t.Error("a disabled account's session still signed it in")
	}
	if _, err := s.StartSession(m.ID); !errors.Is(err, ErrDisabled) {
		t.Errorf("a disabled account was signed in: %v", err)
	}
}

func TestPasskeysAreAddedAndRemovedButNeverTheLastOne(t *testing.T) {
	s, _ := newStore(t)
	m, _, _ := s.Create("Ada", key("k1"))
	if err := s.RemovePasskey(m.ID, []byte("k1")); err == nil {
		t.Error("the only passkey was removed")
	}
	if err := s.AddPasskey(m.ID, key("k2")); err != nil {
		t.Fatal(err)
	}
	other, _, _ := s.Create("Bo", key("k3"))
	if err := s.AddPasskey(m.ID, key("k3")); err == nil {
		t.Error("another account's passkey was added")
	}
	if err := s.RemovePasskey(m.ID, []byte("k1")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ByCredential([]byte("k1")); err == nil {
		t.Error("a removed passkey still finds the account")
	}
	if got, _, _ := s.ByCredential([]byte("k3")); got.ID != other.ID {
		t.Error("the refused passkey was taken from its owner")
	}
}

// Deleting an account leaves nothing that points at it.
func TestDeletingAnAccountErasesEverythingAboutIt(t *testing.T) {
	s, _ := newStore(t)
	m, codes, _ := s.Create("Ada", key("k1"))
	_ = s.AddPasskey(m.ID, key("k2"))
	token, _ := s.StartSession(m.ID)
	keep, _, _ := s.Create("Bo", key("k9"))
	keepToken, _ := s.StartSession(keep.ID)

	if err := s.Delete(m.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(m.ID); !errors.Is(err, ErrNotFound) {
		t.Error("the account is still there")
	}
	if _, err := s.SessionMember(token); err == nil {
		t.Error("a deleted account's session still works")
	}
	if _, err := s.Recover(codes[0]); err == nil {
		t.Error("a deleted account's recovery code still works")
	}
	_ = filepath.WalkDir(s.Dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(path); strings.Contains(string(b), m.ID) {
				t.Errorf("%s still names the deleted account", path)
			}
		}
		return nil
	})
	if _, err := s.SessionMember(keepToken); err != nil {
		t.Error("deleting one account signed out another")
	}
}

func TestAnInvitationIsUsedOnceAndExpires(t *testing.T) {
	s, now := newStore(t)
	code, inv, err := s.NewInvite("staff", "for Bo")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckInvite(strings.ToLower(code)); err != nil {
		t.Errorf("checking a live code: %v", err)
	}
	if err := s.UseInvite(code); err != nil {
		t.Fatal(err)
	}
	if err := s.UseInvite(code); !errors.Is(err, ErrNoCode) {
		t.Error("an invitation was used twice")
	}
	late, _, _ := s.NewInvite("staff", "")
	*now = now.Add(InviteLife + time.Hour)
	if err := s.CheckInvite(late); !errors.Is(err, ErrNoCode) {
		t.Error("an expired invitation was accepted")
	}
	s.Sweep()
	if len(s.Invites()) != 0 {
		t.Errorf("sweeping left %d invitations", len(s.Invites()))
	}
	_, keep, _ := s.NewInvite("staff", "")
	if err := s.RevokeInvite(keep.Hash[:8]); err != nil {
		t.Fatal(err)
	}
	if len(s.Invites()) != 0 {
		t.Error("revoking did not remove the invitation")
	}
	_ = inv
}
