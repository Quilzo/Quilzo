// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/clientip"
	"github.com/quilzo/quilzo/internal/shield"
)

// shieldRoot is a store with an audit key, as a server has one.
func shieldRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	key, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(auditKeyPath(root)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditKeyPath(root), key, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func fromAddr(addr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pages", nil)
	r.RemoteAddr = addr + ":4000"
	return clientip.With(r, (*clientip.Resolver)(nil).From(r))
}

func TestADecoyPresentedShutsItsHolderOutAndSaysWhereItWasPlanted(t *testing.T) {
	root := shieldRoot(t)
	secret, d, err := shield.AddDecoy(root, "the deploy job's variables", "dana", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := newShieldHost(root)
	h.badToken(fromAddr("203.0.113.9"), secret, errors.New("no such token"))
	h.guard.Refresh()
	if _, blocked := h.guard.Blocked("203.0.113.9", shield.Admin, time.Now()); !blocked {
		t.Fatal("the decoy's holder still reaches the admin")
	}
	st, _ := shield.Load(root)
	if len(st.Responses) == 0 {
		t.Fatal("no response recorded")
	}
	sum := shieldSummary("A decoy was touched", st.Responses[0], shield.Signal{Name: "decoy", Subject: d.ID}, st)
	if !strings.HasPrefix(sum, "Shield: A decoy was touched (stage 1). Blocked") ||
		!strings.Contains(sum, "planted in the deploy job's variables") {
		t.Fatalf("%q", sum)
	}
}

func TestGuessesAreCountedAndLateCredentialsAreNot(t *testing.T) {
	root := shieldRoot(t)
	h := newShieldHost(root)
	expired := errors.New("token expired")
	for i := 0; i < 10; i++ {
		// Somebody's real token, used late: not an attack.
		h.badToken(fromAddr("198.51.100.7"), "qz_"+strings.Repeat("a", 52), expired)
		// Not shaped like a token at all: a misconfigured client.
		h.badToken(fromAddr("198.51.100.8"), "eyJhbGciOi.jwt", errUnknownForTest())
	}
	for i := 0; i < 5; i++ {
		h.badToken(fromAddr("198.51.100.9"), "qz_"+strings.Repeat("b", 52), errUnknownForTest())
	}
	h.guard.Refresh()
	now := time.Now()
	if _, b := h.guard.Blocked("198.51.100.7", shield.Admin, now); b {
		t.Fatal("a late credential was taken for guessing")
	}
	if _, b := h.guard.Blocked("198.51.100.8", shield.Admin, now); b {
		t.Fatal("a misconfigured client was taken for guessing")
	}
	if _, b := h.guard.Blocked("198.51.100.9", shield.Admin, now); !b {
		t.Fatal("five guesses were not stopped")
	}
}

// errUnknownForTest is what the token store answers for a secret it never
// issued.
func errUnknownForTest() error {
	_, err := (&auth.TokenStore{}).Authenticate("qz_"+strings.Repeat("z", 52), time.Now())
	return err
}

func TestTheLockdownGatesTheServersStoresAndNotTheMachines(t *testing.T) {
	root := shieldRoot(t)
	ts := &auth.TokenStore{}
	old, _, err := ts.Issue("laptop", "dana", auth.RoleAdmin, "", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // tokens and lockdowns are to the second
	p := shield.Protection{Kind: shield.Lockdown, Reason: "testing", By: "dana", Until: time.Now().Add(time.Hour)}
	if _, _, err := shield.Apply(root, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	h := newShieldHost(root)
	if _, err := h.gate(ts).Authenticate(old, time.Now()); !errors.Is(err, auth.ErrLockedDown) {
		t.Fatalf("a server's store let a pre-lockdown token in: %v", err)
	}
	ts.Admit = nil // the command line on the machine loads its own, ungated
	if _, err := ts.Authenticate(old, time.Now()); err != nil {
		t.Fatalf("the machine was locked out: %v", err)
	}
}
