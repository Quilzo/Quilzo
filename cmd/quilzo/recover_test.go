// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
)

// A break-glass recovery makes somebody an administrator of everything
// without anybody having signed in, which is also what an intruder with
// the store's files would do. It used to be written to the audit log and
// nowhere else, so nobody heard of it until they read the log. The
// security contact is told, the log says whether they were, and the
// credential it printed is in neither.
func TestABreakGlassRecoveryIsToldToTheSecurityContact(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := connectStore(t)
	box := securityMailbox(t, root)
	_, printed := captureStdout(t)
	err := cmdRecover(root, []string{"--principal", "dana", "--reason", "every admin token was lost",
		"--i-have-filesystem-access"})
	secret := strings.TrimSpace(printed())
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" {
		t.Fatal("the recovery printed no credential")
	}
	got := box.read()
	if len(got) != 1 || got[0].To != "security@crumb.example" || !strings.Contains(got[0].Body, "dana") ||
		!strings.Contains(got[0].Body, "every admin token was lost") {
		t.Fatalf("the security contact was told: %d messages", len(got))
	}
	if strings.Contains(got[0].Body, secret) || strings.Contains(got[0].Subject, secret) {
		t.Fatal("the mail carries the credential the recovery printed")
	}
	told := auditFor(t, root, "auth.told")
	if len(told) != 1 || told[0].Outcome != audit.Success || told[0].Detail["about"] != "break-glass" ||
		!strings.Contains(told[0].Detail["did"], "security@crumb.example") {
		t.Fatalf("the log does not say the security contact was told: %+v", told)
	}
}

// When the mail cannot go, the recovery still works, and the log says
// that nobody was told.
func TestABreakGlassRecoveryNobodyCouldBeToldIsAFailureOnTheRecord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := connectStore(t)
	box := securityMailbox(t, root)
	box.fail = errors.New("the relay refused the connection")
	_, printed := captureStdout(t)
	err := cmdRecover(root, []string{"--principal", "dana", "--reason", "every admin token was lost",
		"--i-have-filesystem-access"})
	printed()
	if err != nil {
		t.Fatalf("a mail that could not go undid the recovery: %v", err)
	}
	told := auditFor(t, root, "auth.told")
	if len(told) != 1 || told[0].Outcome != audit.Failure || told[0].Detail["error"] == "" {
		t.Fatalf("the log does not say nobody was told: %+v", told)
	}
}
