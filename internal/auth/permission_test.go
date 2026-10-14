// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"
	"testing"
	"time"
)

// With no permission granted, each follows the rung it always followed.
func TestAPermissionFollowsItsRungByDefault(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "ana", Role: RoleAuthor, Resource: "/"})
	p.Grant(Binding{Principal: "ed", Role: RoleAdmin, Resource: "/"})
	for _, c := range []struct {
		who    string
		action Action
		want   bool
	}{
		{"ana", ActRunAgents, true}, {"ana", ActUseModels, true},
		{"ana", ActApprove, false}, {"ana", ActManageAgents, false}, {"ana", ActInstall, false},
		{"ed", ActApprove, true}, {"ed", ActManageAgents, true}, {"ed", ActInstall, true},
	} {
		if got := p.Evaluate(c.who, c.action, AgentResource("newsletter")).Allowed; got != c.want {
			t.Errorf("%s %s: %v", c.who, c.action, got)
		}
	}
}

// Granted alone, a permission reaches what it was granted on and nothing
// else: one agent, not every agent, and not the content.
func TestAPermissionGrantedAloneReachesOnlyItsResource(t *testing.T) {
	p := &Policy{}
	if err := p.Grant(Binding{Principal: "mo", Permission: ActApprove, Resource: AgentResource("newsletter")}); err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate("mo", ActApprove, AgentResource("newsletter"))
	if !d.Allowed || !strings.Contains(d.Reason, "the approve permission on /@agents/newsletter") {
		t.Fatalf("%+v", d)
	}
	for _, c := range []struct {
		action   Action
		resource string
	}{
		{ActApprove, AgentResource("billing")},
		{ActManageAgents, AgentResource("newsletter")},
		{ActView, "/"},
		{ActEditDraft, "/marketing"},
	} {
		if p.Evaluate("mo", c.action, c.resource).Allowed {
			t.Errorf("approve on one agent allowed %s on %s", c.action, c.resource)
		}
	}
	// On every agent.
	p.Grant(Binding{Principal: "lu", Permission: ActManageAgents, Resource: AreaAgents})
	if !p.Evaluate("lu", ActManageAgents, AgentResource("billing")).Allowed {
		t.Error("a permission on /@agents did not cover an agent")
	}
}

// A permission is a binding like any other: it ends, it can be denied, and
// it reaches a guarded area only when granted on the area.
func TestAPermissionEndsIsDeniedAndRespectsGuardedAreas(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "mo", Permission: ActApprove, Resource: AreaAgents,
		Expires: time.Now().Add(-time.Minute).Unix()})
	if p.Evaluate("mo", ActApprove, AgentResource("x")).Allowed {
		t.Error("an expired permission allowed")
	}
	p.Grant(Binding{Principal: "ed", Role: RoleAdmin, Resource: "/"})
	p.Grant(Binding{Principal: "ed", Permission: ActApprove, Resource: AgentResource("payroll"), Deny: true})
	if p.Evaluate("ed", ActApprove, AgentResource("payroll")).Allowed {
		t.Error("a denied permission did not stop an administrator")
	}
	if !p.Evaluate("ed", ActApprove, AgentResource("newsletter")).Allowed || !p.Evaluate("ed", ActManageAgents, AgentResource("payroll")).Allowed {
		t.Error("a denied permission stopped more than itself")
	}
	p.Grant(Binding{Principal: "sus", Role: RoleReader, Resource: "/", Deny: true})
	p.Grant(Binding{Principal: "sus", Permission: ActApprove, Resource: AreaAgents})
	if p.Evaluate("sus", ActApprove, AgentResource("x")).Allowed {
		t.Error("a suspended person kept a permission")
	}
	p.Grant(Binding{Principal: "gi", Permission: ActApprove, Resource: "/"})
	if p.Evaluate("gi", ActApprove, AreaSecurity+"/cases").Allowed {
		t.Error("a permission over the site reached a guarded area")
	}
}

func TestAPermissionIsGrantedAndRevokedByName(t *testing.T) {
	p := &Policy{}
	for _, b := range []Binding{
		{Principal: "mo", Permission: "fly"},
		{Principal: "mo", Permission: ActApprove, Role: RoleReader},
		{Principal: "mo", Permission: ActView},
	} {
		if err := p.Grant(b); err == nil {
			t.Errorf("%+v was granted", b)
		}
	}
	p.Grant(Binding{Principal: "mo", Permission: ActApprove, Resource: AreaAgents})
	if err := p.Grant(Binding{Principal: "mo", Permission: ActApprove, Resource: AreaAgents}); err == nil {
		t.Error("the same permission was granted twice")
	}
	if n := p.RevokeNamed("mo", "approve", AreaAgents); n != 1 || p.Evaluate("mo", ActApprove, AgentResource("x")).Allowed {
		t.Errorf("revoked %d", n)
	}
	if _, ok := PermissionNamed("install-features"); !ok {
		t.Error("a permission was not found by name")
	}
}

// A credential caps a permission granted on its own by its path and its
// limits; a permission that comes from a role is capped by the role, as
// everything else is.
func TestATokenCapsAPermissionByItsPathAndLimits(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "ria", Role: RoleReader, Resource: "/"})
	p.Grant(Binding{Principal: "ria", Permission: ActApprove, Resource: AgentResource("tidy")})
	p.Grant(Binding{Principal: "ed", Role: RoleAdmin, Resource: "/"})
	target := AgentResource("tidy")
	d := p.Evaluate("ria", ActApprove, target)
	if err := CheckGranted(d, RoleReader, "/", Scope{}, ActApprove, target); err != nil {
		t.Errorf("ria's own reader token could not use what she was granted: %v", err)
	}
	if err := CheckGranted(d, RoleReader, "/", Scope{ReadOnly: true}, ActApprove, target); err == nil {
		t.Error("a read-only token approved")
	}
	if err := CheckGranted(d, RoleReader, "/blog", Scope{}, ActApprove, target); err == nil {
		t.Error("a token scoped to /blog reached an agent")
	}
	d = p.Evaluate("ed", ActApprove, target)
	if err := CheckGranted(d, RoleReader, "/", Scope{}, ActApprove, target); err == nil {
		t.Error("an administrator's reader token approved")
	}
}

// A collection is its own resource: covered by a role on the site, not by a
// section of pages that shares its name.
func TestACollectionIsCheckedAsItsOwnResource(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "ed", Role: RoleAuthor, Resource: "/"})
	p.Grant(Binding{Principal: "sam", Role: RoleAuthor, Resource: "/samples"})
	p.Grant(Binding{Principal: "tech", Role: RoleAuthor, Resource: DataResource("samples")})
	if !p.Evaluate("ed", ActEditDraft, DataResource("samples")).Allowed {
		t.Error("an author over the site lost the data")
	}
	if p.Evaluate("sam", ActView, DataResource("samples")).Allowed {
		t.Error("a section of pages reached the collection of the same name")
	}
	if !p.Evaluate("tech", ActEditDraft, DataResource("samples")).Allowed || p.Evaluate("tech", ActView, DataResource("hr")).Allowed ||
		p.Evaluate("tech", ActView, "/").Allowed {
		t.Error("a grant on one collection reached more than it")
	}
	if !p.AnywhereUnder("tech", ActView, AreaData) || p.AnywhereUnder("sam", ActView, AreaData) {
		t.Error("AnywhereUnder")
	}
}
