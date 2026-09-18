// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"path/filepath"
	"testing"

	"time"

	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/out"
)

// configured writes settings into a store and returns its root.
func configured(t *testing.T, pairs ...string) string {
	t.Helper()
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		if err := cfg.Set(pairs[i], pairs[i+1],
			"because the test says so", "test"); err != nil {
			t.Fatalf("%s=%s: %v", pairs[i], pairs[i+1], err)
		}
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	return root
}

// The setting whose own text ends "Set to two, nothing publishes without two
// people" — and which nothing read, so setting it to two did nothing.
func TestTheApprovalSettingsReachThePolicy(t *testing.T) {
	root := configured(t,
		"review.required_approvals", "2",
		"approval.required_humans", "2")

	p, err := loadApprovalPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	if p.Required != 2 {
		t.Errorf("required approvals is %d", p.Required)
	}
	if p.RequiredHumans != 2 {
		t.Errorf("required humans is %d — the setting says \"set to two, "+
			"nothing publishes without two people\"", p.RequiredHumans)
	}
}

// And the policy actually refuses. A number that reaches a struct and changes
// no decision is the same bug one layer along.
func TestTwoHumansAreActuallyRequired(t *testing.T) {
	root := configured(t, "approval.required_humans", "2",
		"review.required_approvals", "2")
	p, err := loadApprovalPolicy(root)
	if err != nil {
		t.Fatal(err)
	}

	const content = "abc123"
	prop := collab.Proposal{
		Content: content,
		Approvals: []collab.Approval{
			{Content: content, By: "importer", At: time.Now().Unix()},
			{Content: content, By: "deployer", At: time.Now().Unix()},
		},
	}
	// Two approvals, both from machines, which is the case the setting exists
	// for: "a nightly import approved by the importer and the deploy account
	// meets 'two approvals' and has been seen by nobody."
	machines := func(string) string { return "service" }
	if d := p.Evaluate(prop, machines, time.Now()); d.Allowed {
		t.Error("two machine approvals satisfied a two-human requirement")
	}

	people := func(string) string { return "human" }
	if d := p.Evaluate(prop, people, time.Now()); !d.Allowed {
		t.Errorf("two people did not satisfy it: %s", d.Reason)
	}
}

// An install that set nothing behaves exactly as before. This is what keeps
// wiring the settings from turning a single-person install into one that
// cannot publish at all.
func TestAnUnconfiguredStoreHasNoApprovalRequirement(t *testing.T) {
	root := configured(t)
	p, err := loadApprovalPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	if p.Required != 0 || p.RequiredHumans != 0 {
		t.Errorf("an unconfigured store requires %d approvals and %d humans",
			p.Required, p.RequiredHumans)
	}
}

// approval.json is the operator's more specific answer and wins where it says
// anything — but a file written before these settings existed carries no
// opinion about them, and reading it as zero would silently undo a configured
// requirement.
func TestTheFileWinsWhereItSpeaksAndNotWhereItIsSilent(t *testing.T) {
	root := configured(t, "approval.required_humans", "2",
		"review.required_approvals", "2")

	// A file that raises the count and says nothing about humans.
	if err := saveJSON(filepath.Join(root, "approval.json"),
		collab.Policy{Required: 3}); err != nil {
		t.Fatal(err)
	}
	p, err := loadApprovalPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	if p.Required != 3 {
		t.Errorf("the file's count did not win: %d", p.Required)
	}
	if p.RequiredHumans != 2 {
		t.Errorf("a silent file undid the configured human requirement: %d",
			p.RequiredHumans)
	}
}

// A value that has somehow become unparseable must not make publishing
// impossible. It falls back to the number that changes nothing.
func TestAnUnparseableHumanCountIsTheHarmlessNumber(t *testing.T) {
	for _, raw := range []string{"", "   ", "two", "-1", "1.5"} {
		if got := atoiOr(raw, 0); got != 0 {
			t.Errorf("%q became %d", raw, got)
		}
	}
	if got := atoiOr(" 3 ", 0); got != 3 {
		t.Errorf("a padded number became %d", got)
	}
}
