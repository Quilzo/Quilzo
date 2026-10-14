// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"
	"testing"
	"time"
)

func technician() AppRole {
	return AppRole{Name: "lab/technician", Title: "Lab technician", Bindings: []Binding{
		{Role: RoleAuthor, Resource: DataResource("samples")},
		{Permission: ActRunAgents, Resource: AgentResource("intake")},
	}}
}

// An app role is assigned whole, removed whole, and never half of it by
// revoking one of its bindings by hand.
func TestAnAppRoleIsAssignedAndRemovedWhole(t *testing.T) {
	var p Policy
	if err := p.Assign("tess", technician(), Binding{GrantedBy: "dana", Note: "cover"}); err != nil {
		t.Fatal(err)
	}
	if !p.Evaluate("tess", ActEditDraft, DataResource("samples")).Allowed ||
		!p.Evaluate("tess", ActRunAgents, AgentResource("intake")).Allowed {
		t.Fatal("the role does not grant what it declares")
	}
	if d := p.Evaluate("tess", ActRunAgents, AgentResource("intake")); !strings.Contains(d.Reason, "as lab/technician") {
		t.Errorf("the reason does not name the role: %s", d.Reason)
	}
	if err := p.Assign("tess", technician(), Binding{}); err == nil {
		t.Error("the role was assigned twice")
	}
	if err := p.Assign("tess", AppRole{Name: "lab/x", Bindings: technician().Bindings}, Binding{Deny: true}); err == nil {
		t.Error("an app role was denied")
	}
	// A grant made by hand that matches one of the role's stands apart.
	if err := p.Grant(Binding{Principal: "tess", Role: RoleAuthor, Resource: DataResource("samples")}); err != nil {
		t.Fatalf("a direct grant beside the role's was refused: %v", err)
	}
	if n := p.Revoke("tess", RoleAuthor, DataResource("samples")); n != 1 {
		t.Errorf("revoking by hand removed %d bindings; want only the one made by hand", n)
	}
	if n := p.RevokeAppRole("tess", "lab/technician"); n != 2 || len(p.Bindings) != 0 {
		t.Errorf("revoking the role removed %d; left %+v", n, p.Bindings)
	}
}

// Reassigning keeps who granted the role, why and until when, and gives
// its holders what it grants now.
func TestReassigningARoleKeepsItsHoldersAndTheirTerms(t *testing.T) {
	var p Policy
	until := time.Now().Add(48 * time.Hour).Unix()
	if err := p.Assign("tess", technician(), Binding{GrantedBy: "dana", Note: "cover", Expires: until}); err != nil {
		t.Fatal(err)
	}
	narrower := technician()
	narrower.Bindings = []Binding{{Role: RoleReader, Resource: DataResource("samples")}}
	if who := p.Reassign("lab/technician", &narrower); len(who) != 1 || who[0] != "tess" {
		t.Fatalf("reassigned %v", who)
	}
	if p.Evaluate("tess", ActEditDraft, DataResource("samples")).Allowed ||
		p.Evaluate("tess", ActRunAgents, AgentResource("intake")).Allowed {
		t.Error("the holder kept what the role no longer grants")
	}
	b := p.Bindings[0]
	if len(p.Bindings) != 1 || b.GrantedBy != "dana" || b.Note != "cover" || b.Expires != until || b.Via != ViaApp("lab/technician") {
		t.Errorf("the terms were not kept: %+v", p.Bindings)
	}
	if who := p.Reassign("lab/technician", nil); len(who) != 1 || len(p.Bindings) != 0 {
		t.Errorf("a role that is gone is still held: %+v", p.Bindings)
	}
}

func TestAnAppRoleNameIsAppSlashRole(t *testing.T) {
	for name, want := range map[string]bool{"lab/technician": true, "admin": false, "/x": false, "a/b/c": false, "lab/": false} {
		if got := IsAppRoleName(name); got != want {
			t.Errorf("%q: %v", name, got)
		}
	}
}
