// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package auth

import (
	"testing"
	"time"
)

func withJob(t *testing.T, p *Policy, who, job string) {
	t.Helper()
	j, ok := JobNamed(job)
	if !ok {
		t.Fatalf("no job %q", job)
	}
	for _, b := range j.Bindings {
		b.Principal = who
		if err := p.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
}

// A job is its area and nothing else.
func TestAJobCoversItsAreaAndNothingElse(t *testing.T) {
	p := &Policy{}
	withJob(t, p, "sam", "analyst")
	for _, ok := range []struct {
		act Action
		res string
	}{{ActGrant, AreaSecurity}, {ActView, AreaSecurity}, {ActGrant, AreaLog}} {
		if !p.Evaluate("sam", ok.act, ok.res).Allowed {
			t.Errorf("an analyst cannot %s on %s", ok.act, ok.res)
		}
	}
	for _, no := range []struct {
		act Action
		res string
	}{{ActView, "/"}, {ActView, "/index"}, {ActEditDraft, "/blog/post"},
		{ActGrant, "/"}, {ActToken, "/"}, {ActGrant, AreaCompliance}, {ActEditDraft, AreaInbox}} {
		if p.Evaluate("sam", no.act, no.res).Allowed {
			t.Errorf("an analyst may %s on %s", no.act, no.res)
		}
	}
	if p.Anywhere("sam", ActEditDraft) || p.Anywhere("sam", ActView) {
		t.Error("an analyst's area grant reads as somewhere in the site's content")
	}

	withJob(t, p, "lee", "support")
	if !p.Evaluate("lee", ActEditDraft, AreaInbox).Allowed || !p.Evaluate("lee", ActEditDraft, AreaBoards).Allowed {
		t.Error("support cannot answer the inbox or moderate boards")
	}
	if p.Evaluate("lee", ActGrant, AreaInbox).Allowed || p.Evaluate("lee", ActEditDraft, "/index").Allowed {
		t.Error("support holds more than it was given")
	}
}

// A whole-site administrator covers every area.
func TestAWholeSiteRoleCoversEveryArea(t *testing.T) {
	p := &Policy{}
	_ = p.Grant(Binding{Principal: "ada", Role: RoleAdmin, Resource: "/"})
	_ = p.Grant(Binding{Principal: "bo", Role: RoleAuthor, Resource: "/"})
	for _, area := range []string{AreaSecurity, AreaCompliance, AreaLog, AreaInbox, AreaBoards} {
		if !p.Evaluate("ada", ActGrant, area).Allowed {
			t.Errorf("a site administrator cannot reach %s", area)
		}
		if p.Evaluate("bo", ActGrant, area).Allowed {
			t.Errorf("an author reached %s as an administrator", area)
		}
	}
	// And a deny on the site denies the areas with it.
	_ = p.Grant(Binding{Principal: "ada", Role: RoleAdmin, Resource: "/", Deny: true})
	if p.Evaluate("ada", ActGrant, AreaSecurity).Allowed {
		t.Error("a deny on the whole site left an area open")
	}
}

func TestAGrantEndsWhenItExpires(t *testing.T) {
	p := &Policy{}
	_ = p.Grant(Binding{Principal: "cy", Role: RoleAdmin, Resource: AreaSecurity,
		Expires: time.Now().Add(-time.Minute).Unix()})
	_ = p.Grant(Binding{Principal: "di", Role: RoleAdmin, Resource: AreaSecurity,
		Expires: time.Now().Add(time.Hour).Unix()})
	if p.Evaluate("cy", ActView, AreaSecurity).Allowed {
		t.Error("an expired grant still works")
	}
	if !p.Evaluate("di", ActView, AreaSecurity).Allowed {
		t.Error("a grant that has not expired does not work")
	}
	// An expired deny no longer denies.
	_ = p.Grant(Binding{Principal: "di", Role: RoleReader, Resource: "/", Deny: true,
		Expires: time.Now().Add(-time.Minute).Unix()})
	if !p.Evaluate("di", ActView, AreaSecurity).Allowed {
		t.Error("an expired deny still denies")
	}
}

// Security operations, the posture and the audit log are reached from the
// whole site only as administrator. A reader over the site reads pages, not
// where the defences are thin; somebody who should read those is granted
// the area itself.
func TestAWholeSiteRoleBelowAdministratorDoesNotReachTheGuardedAreas(t *testing.T) {
	p := &Policy{}
	for _, r := range []Role{RoleReader, RoleAuthor, RolePublisher} {
		_ = p.Grant(Binding{Principal: string(r), Role: r, Resource: "/"})
		for _, area := range []string{AreaSecurity, AreaCompliance, AreaLog, AreaLog + "/2026"} {
			if d := p.Evaluate(string(r), ActView, area); d.Allowed {
				t.Errorf("a %s over the site reads %s: %s", r, area, d.Reason)
			}
		}
		for _, area := range []string{AreaInbox, AreaBoards} {
			if !p.Evaluate(string(r), ActView, area).Allowed {
				t.Errorf("a %s over the site lost %s, which is not guarded", r, area)
			}
		}
		if !p.Evaluate(string(r), ActView, "/index").Allowed {
			t.Errorf("a %s over the site cannot read a page", r)
		}
	}
	// Granted the area, a reader reads it and does nothing else there.
	withJob(t, p, "aud", "auditor")
	if !p.Evaluate("aud", ActView, AreaLog).Allowed || !p.Evaluate("aud", ActView, AreaCompliance).Allowed {
		t.Error("an auditor cannot read the log and the posture")
	}
	for _, c := range []struct {
		act Action
		on  string
	}{{ActGrant, AreaCompliance}, {ActEditDraft, AreaLog}, {ActView, AreaSecurity}, {ActView, "/index"}} {
		if p.Evaluate("aud", c.act, c.on).Allowed {
			t.Errorf("an auditor may %s on %s", c.act, c.on)
		}
	}
	// A deny over the site still covers the guarded areas: suspension
	// must outrank a grant on the area itself.
	_ = p.Grant(Binding{Principal: "aud", Role: RoleReader, Resource: "/", Deny: true})
	if p.Evaluate("aud", ActView, AreaLog).Allowed {
		t.Error("a deny over the site left a guarded area open")
	}
}
