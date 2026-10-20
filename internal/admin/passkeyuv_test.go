// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// A passkey that was only touched signs nobody in, and the person whose key
// it is hears what to do about it rather than the answer a stranger gets.
func TestAnAdminPasskeyWithoutUserVerificationIsRefused(t *testing.T) {
	srv, token := fullyWired(t)
	f := newFake(t, "credential-uv")
	f.register(t, srv, token)

	f.flags = 0x01 // present, not verified
	f.count++
	w := f.signIn(t, srv)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a touch-only passkey answered %d: %s", w.Code, w.Body)
	}
	if sessionOf(w) != nil {
		t.Fatal("a touch-only passkey was given a session")
	}
	if !strings.Contains(w.Body.String(), "PIN") {
		t.Errorf("the refusal does not say the key needs a PIN, fingerprint or face: %s", w.Body)
	}

	// The same key, verified, still works: the refusal was about the flag.
	f.flags = 0
	f.count++
	if w := f.signIn(t, srv); w.Code != http.StatusOK {
		t.Fatalf("the same key with user verification answered %d: %s", w.Code, w.Body)
	}
}

// Refused while it is being added, with nothing stored.
func TestAnAdminPasskeyRegisteredWithoutUserVerificationIsRefused(t *testing.T) {
	srv, token := fullyWired(t)
	f := newFake(t, "credential-touch")
	f.flags = 0x01

	start := decodeBody(t, postJSON(t, srv, "/passkeys/challenge", token, nil))
	challenge, _ := start["challenge"].(string)
	der, err := x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	w := postJSON(t, srv, "/passkeys/register", token, map[string]any{
		"id": enc(f.id), "challenge": challenge, "label": "a touch-only key",
		"clientDataJSON":    enc(f.clientData(t, "webauthn.create", challenge)),
		"authenticatorData": enc(f.authData()),
		"publicKey":         enc(der),
		"algorithm":         -7,
	})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "PIN") {
		t.Fatalf("a touch-only registration answered %d: %s", w.Code, w.Body)
	}
	if n := len(srv.Passkeys.Credentials); n != 0 {
		t.Fatalf("%d credentials were stored from a touch-only registration", n)
	}
}

// What the authenticator said is kept on the credential, and the backup state
// follows each sign-in.
func TestAnAdminPasskeyRecordsWhetherItIsSynced(t *testing.T) {
	srv, token := fullyWired(t)
	var started map[string]string
	srv.Audit = func(action, _ string, d map[string]string) {
		if action == "session.start" && d["how"] == "passkey" {
			started = d
		}
	}
	f := newFake(t, "credential-synced")
	f.flags = 0x01 | 0x04 | 0x08 // eligible, not yet backed up
	f.register(t, srv, token)
	c := srv.Passkeys.Credentials[0]
	if !c.UserVerified || !c.BackupEligible || c.BackupState {
		t.Fatalf("registered as verified %v, eligible %v, backed up %v",
			c.UserVerified, c.BackupEligible, c.BackupState)
	}

	f.flags = 0x01 | 0x04 | 0x08 | 0x10
	f.count++
	if w := f.signIn(t, srv); w.Code != http.StatusOK {
		t.Fatalf("signing in answered %d: %s", w.Code, w.Body)
	}
	if !srv.Passkeys.Credentials[0].BackupState {
		t.Error("the sign-in reported a backup and the record still says none")
	}
	if started == nil || started["backed_up"] != "true" || started["user_verified"] != "true" {
		t.Errorf("the sign-in's audit record does not carry what the authenticator said: %v", started)
	}
}

// A passkey kept from before verification was required keeps working with
// it, and has its flags recorded then.
func TestAnOlderAdminPasskeyWorksOnlyWithUserVerification(t *testing.T) {
	srv, token := fullyWired(t)
	f := newFake(t, "credential-older")
	f.register(t, srv, token)
	c := &srv.Passkeys.Credentials[0]
	c.UserVerified, c.BackupEligible, c.BackupState = false, false, false

	f.flags = 0x01
	f.count++
	if w := f.signIn(t, srv); w.Code == http.StatusOK {
		t.Fatal("an older passkey signed in without user verification")
	}
	f.flags = 0x01 | 0x04 | 0x08 | 0x10
	f.count++
	if w := f.signIn(t, srv); w.Code != http.StatusOK {
		t.Fatalf("an older passkey with user verification answered %d: %s", w.Code, w.Body)
	}
	if c := srv.Passkeys.Credentials[0]; !c.UserVerified || !c.BackupEligible || !c.BackupState {
		t.Errorf("its first verified sign-in recorded verified %v, eligible %v, backed up %v",
			c.UserVerified, c.BackupEligible, c.BackupState)
	}
}

// Somebody provisioning suspended is refused at the passkey, as single
// sign-on refuses them: no session, no exemption from the shield, and an
// answer that says why.
func TestASuspendedPersonsPasskeySignsNobodyIn(t *testing.T) {
	srv, token := fullyWired(t)
	f := newFake(t, "credential-suspended")
	f.register(t, srv, token)
	who := srv.Passkeys.Credentials[0].Principal
	if err := srv.Policy.Grant(auth.Binding{Principal: who, Role: auth.RoleReader, Resource: "/", Deny: true,
		Note: "suspended: the identity provider deactivated or removed them"}); err != nil {
		t.Fatal(err)
	}
	vouched := false
	srv.OnStrongSignIn = func(*http.Request, string) { vouched = true }
	sessions := len(srv.Tokens.Snapshot())

	f.count++
	w := f.signIn(t, srv)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "suspended") {
		t.Fatalf("a suspended person's passkey answered %d: %s", w.Code, w.Body)
	}
	if sessionOf(w) != nil || len(srv.Tokens.Snapshot()) != sessions {
		t.Fatal("a suspended person was given a session")
	}
	if vouched {
		t.Fatal("a suspended person's address was exempted from the shield")
	}
}

// A deny that leaves the person something, or that has ended, is not a
// suspension: their passkey still signs them in.
func TestAPartialOrEndedDenyOnTheWholeSiteDoesNotSuspendAPasskey(t *testing.T) {
	for name, deny := range map[string]auth.Binding{
		"a deny of publishing":    {Role: auth.RolePublisher},
		"a deny of one action":    {Permission: auth.ActApprove},
		"a deny of their own":     {Role: auth.RoleReader, OwnOnly: true},
		"a deny that has expired": {Role: auth.RoleReader, Expires: time.Now().Add(-time.Hour).Unix()},
	} {
		t.Run(name, func(t *testing.T) {
			srv, token := fullyWired(t)
			f := newFake(t, "credential-partial")
			f.register(t, srv, token)
			deny.Principal, deny.Resource, deny.Deny = srv.Passkeys.Credentials[0].Principal, "/", true
			if err := srv.Policy.Grant(deny); err != nil {
				t.Fatal(err)
			}
			f.count++
			if w := f.signIn(t, srv); w.Code != http.StatusOK || sessionOf(w) == nil {
				t.Fatalf("%s refused the passkey as a suspension: %d %s", name, w.Code, w.Body)
			}
		})
	}
}
