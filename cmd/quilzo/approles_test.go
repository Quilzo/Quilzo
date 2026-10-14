// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/scim"
)

// labSite is a store with the lab sample tracker installed, roles and all.
func labSite(t *testing.T) string {
	t.Helper()
	root := featureSite(t)
	if err := installFeatureFile(root, writePackage(t, withoutAddress), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	return root
}

func allowed(t *testing.T, root, who string, act auth.Action, resource string) bool {
	t.Helper()
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	return pol.Evaluate(who, act, resource).Allowed
}

// A role a feature declares is granted by name and reaches what it says,
// on the feature's own blocks, and nothing else.
func TestAnAppRoleGrantsWhatItDeclaresAndNothingElse(t *testing.T) {
	root := labSite(t)
	if err := cmdAuth(root, []string{"grant", "tess", "lab-samples/technician"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "mia", "lab-samples/manager"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		who      string
		act      auth.Action
		resource string
		want     bool
	}{
		{"tess", auth.ActEditDraft, auth.DataResource("samples"), true},
		{"tess", auth.ActView, "/samples", true},
		{"tess", auth.ActEditDraft, "/samples", false},
		{"tess", auth.ActEditDraft, auth.DataResource("payroll"), false},
		{"tess", auth.ActView, "/", false},
		{"tess", auth.ActGrant, "/", false},
		{"mia", auth.ActPublish, "/samples", true},
		{"mia", auth.ActPublish, "/about", false},
	} {
		if got := allowed(t, root, c.who, c.act, c.resource); got != c.want {
			t.Errorf("%s %s on %s: %v, want %v", c.who, c.act, c.resource, got, c.want)
		}
	}
	pol, _ := loadPolicy(root)
	if d := pol.Evaluate("tess", auth.ActEditDraft, auth.DataResource("samples")); !strings.Contains(d.Reason, "as lab-samples/technician") {
		t.Errorf("explain does not say which role: %s", d.Reason)
	}
	if err := cmdAuth(root, []string{"grant", "tess", "lab-samples/technician"}); err == nil {
		t.Error("the same role was granted twice")
	}
	for _, bad := range [][]string{
		{"grant", "tess", "lab-samples/cleaner"},
		{"grant", "tess", "nothing/technician"},
		{"grant", "tess", "lab-samples/manager", "--on", "/blog"},
		{"deny", "tess", "lab-samples/manager"},
	} {
		if err := cmdAuth(root, bad); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}

	// Revoking one of its bindings by hand leaves the role whole; revoking
	// the role takes all of it.
	if err := cmdAuth(root, []string{"revoke", "tess", "author", "--on", auth.DataResource("samples")}); err == nil {
		t.Error("half of a role was revoked")
	}
	if err := cmdAuth(root, []string{"revoke", "tess", "lab-samples/technician"}); err != nil {
		t.Fatal(err)
	}
	if allowed(t, root, "tess", auth.ActView, "/samples") || allowed(t, root, "tess", auth.ActView, auth.DataResource("samples")) {
		t.Error("revoking the role left part of it")
	}
}

// An upgrade that changes a role changes what its holders may do, keeping
// who granted it and until when; and since that is granting access, it
// takes somebody who may grant. Removing the feature takes the role from
// everybody.
func TestAnUpgradeChangesWhatARolesHoldersMayDo(t *testing.T) {
	root := labSite(t)
	if err := cmdAuth(root, []string{"grant", "tess", "lab-samples/technician", "--for", "30d", "--note", "cover"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "ivo", "install-features"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "ivo", "reader"}); err != nil {
		t.Fatal(err)
	}
	readOnly := writePackage(t, func(p *feature.Package) {
		withoutAddress(p)
		p.Version = "1.1.0"
		p.Roles[0].Grants[0].May = "read"
	})
	ivo := human("ivo")
	ivo.Role = auth.RoleReader
	err := installFeatureFile(root, readOnly, "", "", ivo)
	if err == nil || !strings.Contains(err.Error(), "lab-samples/technician") {
		t.Fatalf("installing features changed what a role's holders may do: %v", err)
	}
	if err := installFeatureFile(root, readOnly, "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if allowed(t, root, "tess", auth.ActEditDraft, auth.DataResource("samples")) {
		t.Error("the technician still writes samples after the role became read-only")
	}
	if !allowed(t, root, "tess", auth.ActView, auth.DataResource("samples")) {
		t.Error("the technician no longer reads samples")
	}
	pol, _ := loadPolicy(root)
	for _, b := range pol.Snapshot() {
		if b.Principal == "tess" && (b.Expires == 0 || b.Note != "cover" || b.GrantedBy == "") {
			t.Errorf("the upgrade lost when the grant ends, why, or who made it: %+v", b)
		}
	}

	// A role a version no longer declares is held by nobody.
	noManager := writePackage(t, func(p *feature.Package) {
		withoutAddress(p)
		p.Version = "1.2.0"
		p.Roles[0].Grants[0].May = "read"
		p.Roles = p.Roles[:1]
	})
	if err := cmdAuth(root, []string{"grant", "mia", "lab-samples/manager"}); err != nil {
		t.Fatal(err)
	}
	if err := installFeatureFile(root, noManager, "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if allowed(t, root, "mia", auth.ActView, "/samples") {
		t.Error("a role the feature dropped is still held")
	}

	if err := removeFeature(root, "lab-samples", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	pol, _ = loadPolicy(root)
	for _, b := range pol.Snapshot() {
		if b.Via != "" {
			t.Errorf("removing the feature left %+v", b)
		}
	}
}

// A group in the identity provider can stand for a role in an app, and
// only for one an installed feature declares.
func TestAProvisionedGroupCanBeARoleInAnApp(t *testing.T) {
	root := labSite(t)
	if err := validMapping(root, "lab-samples/cleaner"); err == nil {
		t.Error("a group was mapped to a role nobody declares")
	}
	if err := validMapping(root, "lab-samples/technician"); err != nil {
		t.Fatal(err)
	}
	_ = scimStore(root).Update(func(st *scim.State) error { return nil })
	if err := scimSync(root, "lee", []string{"lab-samples/technician"}, false); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, root, "lee", auth.ActEditDraft, auth.DataResource("samples")) {
		t.Fatal("the group's role was not granted")
	}
	pol, _ := loadPolicy(root)
	if !pol.Holds("lee", "lab-samples/technician") {
		t.Error("the grant is not recorded as the role")
	}
	// Synced again with nothing: provisioning takes back what it gave.
	if err := scimSync(root, "lee", nil, false); err != nil {
		t.Fatal(err)
	}
	if allowed(t, root, "lee", auth.ActView, auth.DataResource("samples")) {
		t.Error("leaving the group left the role")
	}
}
