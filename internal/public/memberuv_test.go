// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"strings"
	"testing"
)

// A member's passkey has to ask for their PIN, fingerprint or face. One that
// was only touched makes no account, and the person is told what to set up.
func TestAMemberPasskeyWithoutUserVerificationMakesNoAccount(t *testing.T) {
	st, store := memberSite(t, "open")
	v := &visitor{t: t, st: st, site: "same-origin"}
	d := newDevice(t)
	d.flags = 0x01 // present, not verified

	w, out := signUp(t, v, d, "Ada", "")
	if w.Code == 200 || v.cookie != "" {
		t.Fatalf("a touch-only passkey made an account: %d %v", w.Code, out)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "PIN") {
		t.Errorf("the refusal does not say what to set up: %v", out)
	}
	if all, _ := store.List(); len(all) != 0 {
		t.Errorf("%d accounts exist after a refused sign-up", len(all))
	}
}

// Signing in is refused the same way, and the same key works once it asks.
// The record keeps what the device said about backing the key up.
func TestAMemberPasskeyWithoutUserVerificationSignsNobodyIn(t *testing.T) {
	st, store := memberSite(t, "open")
	v := &visitor{t: t, st: st, site: "same-origin"}
	d := newDevice(t)
	if w, out := signUp(t, v, d, "Ada", ""); w.Code != 200 {
		t.Fatalf("signing up: %d %v", w.Code, out)
	}
	id := v.memberID(t)
	v.form("/account/signout", nil)

	d.flags = 0x01
	_, start := v.json("/account/signin/start", nil)
	w, out := v.json("/account/signin/finish", d.assertion(t, start["challenge"].(string)))
	if w.Code == 200 || v.cookie != "" {
		t.Fatalf("a touch-only passkey signed a member in: %d", w.Code)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "PIN") {
		t.Errorf("the refusal does not say what to set up: %v", out)
	}

	d.flags = 0x01 | 0x04 | 0x08 | 0x10
	if w := signIn(t, v, d); w.Code != 200 {
		t.Fatalf("the same passkey with user verification: %d %s", w.Code, w.Body)
	}
	m, err := store.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if k := m.Passkeys[0]; !k.UserVerified || !k.BackupState || k.SignCount != d.count {
		t.Errorf("after signing in the passkey is recorded as verified %v, backed up %v, counter %d (device at %d)",
			k.UserVerified, k.BackupState, k.SignCount, d.count)
	}
}

// Adding a second passkey to an account asks the same of it.
func TestAMemberCannotAddAPasskeyWithoutUserVerification(t *testing.T) {
	st, store := memberSite(t, "open")
	v := &visitor{t: t, st: st, site: "same-origin"}
	if w, out := signUp(t, v, newDevice(t), "Ada", ""); w.Code != 200 {
		t.Fatalf("signing up: %d %v", w.Code, out)
	}
	second := newDevice(t)
	second.flags = 0x01
	_, start := v.json("/account/passkey/start", nil)
	w, out := v.json("/account/passkey/finish", second.registration(t, start["challenge"].(string)))
	if w.Code == 200 {
		t.Fatal("a touch-only passkey was added to an account")
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "PIN") {
		t.Errorf("the refusal does not say what to set up: %v", out)
	}
	m, err := store.Get(v.memberID(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Passkeys) != 1 {
		t.Errorf("the account has %d passkeys", len(m.Passkeys))
	}
}
