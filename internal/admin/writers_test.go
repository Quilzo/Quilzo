// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// Every writer of the register here names its caller by the pseudonym the
// register's subject map holds for them, as the command line's does: the
// record's own screens, the evidence screens and Sign-off's approvals. A
// record somebody imports, confirms or asks for is theirs on every surface,
// and a decision they raise is one they are the raiser of wherever they
// try to approve it.
//
// The evidence screens wrote as nobody the register could name, so what
// a person imported there was nobody's, and a key they asked to pin was
// one they could have approved themselves.
func TestEveryAdminWriterNamesItsCallerByPseudonym(t *testing.T) {
	srv, _ := setup(t)
	recording(t)
	p := principal{Name: "editor", Role: auth.RoleAdmin, Scope: "/", Session: true}
	_, onRecord, err := srv.registerWriter(p)
	if err != nil {
		t.Fatal(err)
	}
	_, onEvidence, err := srv.evidenceWriter(p)
	if err != nil {
		t.Fatal(err)
	}
	want, ok, err := register.Open(srv.Store).Side().Lookup("editor")
	if err != nil || !ok {
		t.Fatalf("the subject map does not name the person who wrote: %v %v", ok, err)
	}
	for name, by := range map[string]register.Actor{"the record's screens": onRecord, "the evidence screens": onEvidence} {
		if by.Subject != register.ID(want) {
			t.Errorf("%s write as %q, and the subject map names the person %s", name, by.Subject, want)
		}
	}
	if me, ok := srv.approvalsFor().Known("editor"); !ok || me != register.ID(want) {
		t.Errorf("Sign-off knows the person as %q, and the subject map as %s", me, want)
	}
}
