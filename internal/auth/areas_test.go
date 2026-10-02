// SPDX-FileCopyrightText: 2026 rsh1k
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

// A whole-site role covers every area, exactly as before areas existed.
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
