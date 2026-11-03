// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/out"
)

// Approving a group mapping that makes administrators lets the provisioning
// token already given out make them, so `quilzo pending show` lists every
// live token beside the request: who made it, when, and how it was approved.
//
// A token made while no group made administrators was made by one person,
// rightly, and stays valid once such a mapping is approved. The approver
// could not see it, and so could not know that agreeing to the mapping
// handed whoever held it the power to make administrators.
func TestAMappingThatMakesAdministratorsShowsTheLiveProvisioningTokens(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, lee := twoAdmins(t)
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf
	shown := func(id string) string {
		t.Helper()
		buf.Reset()
		if err := cmdPending(root, []string{"show", id}); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	today := time.Now().UTC().Format("2 Jan 2006")

	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdSCIM(root, []string{"token"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSCIM(root, []string{"map", "IT admins", "admin"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", lee)
	got := shown(waiting(t, root).ID)
	for _, want := range []string{"provisioning token", "made by dana", today, "nobody else was asked"} {
		if !strings.Contains(got, want) {
			t.Errorf("the mapping's request does not say %q:\n%s", want, got)
		}
	}

	// Approved; a new token now takes two, and replaces the first.
	if err := cmdPending(root, []string{"approve", waiting(t, root).ID}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdSCIM(root, []string{"token"}); err != nil {
		t.Fatal(err)
	}
	asked := waiting(t, root)
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", asked.ID}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdPending(root, []string{"redeem", asked.ID}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSCIM(root, []string{"map", "Ops", "admin"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", lee)
	got = shown(waiting(t, root).ID)
	if !strings.Contains(got, "made by dana") || !strings.Contains(got, "approved by lee") ||
		strings.Contains(got, "nobody else was asked") {
		t.Errorf("the live token, approved by two, is not the one shown:\n%s", got)
	}
}

// One approved alone says so.
func TestAProvisioningTokenApprovedAloneIsShownAsSo(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, lee := twoAdmins(t)
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf
	// Only dana, for now: lee is made an administrator after the token.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("lee", auth.RoleAdmin, "/")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	removalAt(t, root, 25*time.Hour)
	t.Setenv("QUILZO_TOKEN", dana)
	for _, args := range [][]string{{"map", "IT admins", "admin"}, {"token"}} {
		if err := cmdSCIM(root, args); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSCIM(root, []string{"map", "Ops", "admin"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", lee)
	buf.Reset()
	if err := cmdPending(root, []string{"show", waiting(t, root).ID}); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, "made by dana") || !strings.Contains(got, "approved alone") {
		t.Errorf("a token approved alone is not shown as one:\n%s", got)
	}
}

// The only administrator, mapping a group to make administrators, is
// approving it alone as they make it, and is shown the live tokens as an
// approver on `quilzo pending show` is.
//
// Nothing waits, so there was no request to show: the mapping took effect
// and said only that the group's members were administrators now, while a
// token another administrator made before any group made administrators
// went on working, now as a way to make them.
func TestAMappingApprovedAloneShowsTheLiveProvisioningTokens(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, lee := twoAdmins(t)
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf

	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdSCIM(root, []string{"token"}); err != nil {
		t.Fatal(err)
	}
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("lee", auth.RoleAdmin, "/")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	removalAt(t, root, 25*time.Hour)
	t.Setenv("QUILZO_TOKEN", dana)
	buf.Reset()
	if err := cmdSCIM(root, []string{"map", "IT admins", "admin"}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "now admin") {
		t.Fatalf("control: the mapping was not made alone:\n%s", got)
	}
	for _, want := range []string{"provisioning token", "made by lee", "nobody else was asked", "quilzo scim token --revoke"} {
		if !strings.Contains(got, want) {
			t.Errorf("the mapping made alone does not say %q:\n%s", want, got)
		}
	}

	// No token, and it says so; a mapping that makes nobody an
	// administrator says nothing about tokens.
	if err := cmdSCIM(root, []string{"token", "--revoke"}); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := cmdSCIM(root, []string{"map", "Ops", "admin"}); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, "no provisioning token works now") {
		t.Errorf("with no live token, the mapping made alone does not say so:\n%s", got)
	}
	buf.Reset()
	if err := cmdSCIM(root, []string{"map", "Writers", "author"}); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); strings.Contains(got, "provisioning token") {
		t.Errorf("a mapping that makes nobody an administrator talks about the token:\n%s", got)
	}
}

// A provisioning token made while a mapping that makes administrators
// waits takes two, as one made once it is approved does.
//
// The approver reads the live tokens with the request, then approves. A
// token made in between, while no group made administrators yet, was made
// on one administrator's word and was not among those read: dana asked
// for the mapping, lee saw that no token worked and approved it, and the
// token dana had made a moment before then made administrators.
func TestAProvisioningTokenMadeWhileAMappingWaitsTakesTwo(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, lee := twoAdmins(t)
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf

	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdSCIM(root, []string{"map", "IT admins", "admin"}); err != nil {
		t.Fatal(err)
	}
	mapping := waiting(t, root)
	t.Setenv("QUILZO_TOKEN", lee)
	buf.Reset()
	if err := cmdPending(root, []string{"show", mapping.ID}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no provisioning token works now") {
		t.Fatalf("control: a token works before any was made:\n%s", buf.String())
	}

	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdSCIM(root, []string{"token"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", mapping.ID}); err != nil {
		t.Fatal(err)
	}
	if live, err := liveSCIMTokens(root, time.Now()); err != nil || len(live) != 0 {
		t.Errorf("a token made on one administrator's word while the mapping waited now makes administrators: %+v %v",
			live, err)
	}
	pend, _ := dualStore(root).Pending(time.Now())
	if len(pend) != 1 || pend[0].Kind != dual.SCIMToken || pend[0].By != "dana" {
		t.Errorf("the token does not wait for a second administrator: %+v", pend)
	}
}
