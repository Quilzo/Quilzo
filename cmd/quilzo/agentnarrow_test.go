// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/site"
)

// wideAgent is a manifest that asks for everything, so a narrowing has
// something to take away.
func wideAgent() agent.Manifest {
	return agent.Manifest{
		Name: "editor", Kind: agent.KindTask,
		Purpose:      "write and publish",
		Capabilities: []string{"list_pages", "read_page", "write_page", "publish"},
		Autonomy:     agent.AutonomyPublish,
		Retrieval:    agent.Retrieval{Ref: site.RefDraft},
		Budget: agent.Budget{
			Steps: 50, Tools: 10, Duration: agent.Duration(time.Hour)},
		HumanApproval: true,
	}
}

func asToken(role auth.Role, sc auth.Scope) *Caller {
	return &Caller{Name: "somebody", Role: role, Limits: sc}
}

// The hole. A token deliberately narrowed afterwards stopped mattering the
// moment its holder ran an agent.
func TestAReadOnlyTokenCannotRunAWritingAgent(t *testing.T) {
	got := narrowedBy(wideAgent(),
		asToken(auth.RolePublisher, auth.Scope{ReadOnly: true}))

	if got.Autonomy != agent.AutonomyPropose {
		t.Errorf("a read-only token produced autonomy %q", got.Autonomy)
	}
	for _, c := range got.Capabilities {
		if agent.IsWrite(c) {
			t.Errorf("a read-only token kept the writing capability %q", c)
		}
	}
	if got.Retrieval.Ref != site.RefLive {
		t.Errorf("a read-only token reads %q", got.Retrieval.Ref)
	}
}

// A reader's token cannot produce a draft, however the manifest is written.
func TestARoleCapsWhatAnAgentMayDo(t *testing.T) {
	for _, tc := range []struct {
		role auth.Role
		want agent.Autonomy
	}{
		{auth.RoleReader, agent.AutonomyPropose},
		{auth.RoleAuthor, agent.AutonomyDraft},
		{auth.RolePublisher, agent.AutonomyPublish},
		{auth.RoleAdmin, agent.AutonomyPublish},
	} {
		got := narrowedBy(wideAgent(), asToken(tc.role, auth.Scope{}))
		if got.Autonomy != tc.want {
			t.Errorf("%s gave autonomy %q, wanted %q",
				tc.role, got.Autonomy, tc.want)
		}
	}
	// And the capability list follows: a reader's agent holds no write.
	got := narrowedBy(wideAgent(), asToken(auth.RoleReader, auth.Scope{}))
	for _, c := range got.Capabilities {
		if agent.IsWrite(c) {
			t.Errorf("a reader's token kept %q", c)
		}
	}
}

// A token scoped to content types narrows what the agent may retrieve, in the
// same vocabulary — auth.Scope and agent.Retrieval both name content types.
func TestATypeScopedTokenNarrowsRetrieval(t *testing.T) {
	m := wideAgent()
	m.Retrieval.Types = []string{"article", "product", "policy"}

	got := narrowedBy(m, asToken(auth.RolePublisher,
		auth.Scope{Types: []string{"article", "product"}}))

	if strings.Join(got.Retrieval.Types, ",") != "article,product" {
		t.Errorf("types are %v", got.Retrieval.Types)
	}
}

// A token restricting nothing must not narrow a list to nothing. Empty means
// all on both sides, which is what makes this not a set intersection.
func TestAnUnscopedTokenLeavesTheManifestAlone(t *testing.T) {
	m := wideAgent()
	m.Retrieval.Types = []string{"article"}
	m.Retrieval.Locales = []string{"en"}

	got := narrowedBy(m, asToken(auth.RoleAdmin, auth.Scope{}))

	if len(got.Capabilities) != len(m.Capabilities) {
		t.Errorf("capabilities went from %v to %v", m.Capabilities, got.Capabilities)
	}
	if strings.Join(got.Retrieval.Types, ",") != "article" {
		t.Errorf("types are %v", got.Retrieval.Types)
	}
	if strings.Join(got.Retrieval.Locales, ",") != "en" {
		t.Errorf("locales are %v", got.Retrieval.Locales)
	}
	if got.Autonomy != agent.AutonomyPublish {
		t.Errorf("autonomy is %q", got.Autonomy)
	}
}

// Two restrictions that do not overlap permit nothing, and must say so with an
// empty list rather than a nil one — nil means "all" everywhere else in this
// struct, so returning it here would widen the thing being narrowed.
func TestDisjointScopesPermitNothing(t *testing.T) {
	m := wideAgent()
	m.Retrieval.Types = []string{"article"}

	got := narrowedBy(m, asToken(auth.RolePublisher,
		auth.Scope{Types: []string{"product"}}))

	if got.Retrieval.Types == nil {
		t.Fatal("disjoint type scopes produced nil, which reads as unrestricted")
	}
	if len(got.Retrieval.Types) != 0 {
		t.Errorf("disjoint type scopes produced %v", got.Retrieval.Types)
	}
}

// An unresolved caller refuses rather than permits. This is the case where the
// safe default matters most.
func TestNoCallerMeansNoAuthority(t *testing.T) {
	got := narrowedBy(wideAgent(), nil)
	if got.Autonomy != agent.AutonomyPropose {
		t.Errorf("a nil caller gave autonomy %q", got.Autonomy)
	}
	if got.Retrieval.Ref != site.RefLive {
		t.Errorf("a nil caller reads %q", got.Retrieval.Ref)
	}
}

// Narrowing must never add. Whatever the token says, the result is a subset of
// what the manifest declared.
func TestNarrowingOnlyEverRemoves(t *testing.T) {
	m := wideAgent()
	declared := map[string]bool{}
	for _, c := range m.Capabilities {
		declared[c] = true
	}

	for _, role := range []auth.Role{
		auth.RoleReader, auth.RoleAuthor, auth.RolePublisher, auth.RoleAdmin} {
		for _, sc := range []auth.Scope{
			{}, {ReadOnly: true}, {Types: []string{"article"}},
			{Locales: []string{"en"}}, {Types: []string{"nope"}, ReadOnly: true},
		} {
			got := narrowedBy(m, asToken(role, sc))
			for _, c := range got.Capabilities {
				if !declared[c] {
					t.Errorf("%s/%v gained the capability %q", role, sc, c)
				}
			}
			if !got.Autonomy.AtMost(m.Autonomy) {
				t.Errorf("%s/%v raised autonomy to %q", role, sc, got.Autonomy)
			}
			if got.Budget.Steps > m.Budget.Steps {
				t.Errorf("%s/%v raised the step budget to %d",
					role, sc, got.Budget.Steps)
			}
			if m.HumanApproval && !got.HumanApproval {
				t.Errorf("%s/%v dropped the approval requirement", role, sc)
			}
		}
	}
}

// The budget belongs to the agent. A token carries none, so capping by the
// caller would mean inventing a number.
func TestTheCallerDoesNotChangeTheBudget(t *testing.T) {
	m := wideAgent()
	got := narrowedBy(m, asToken(auth.RoleAdmin, auth.Scope{}))
	if got.Budget != m.Budget {
		t.Errorf("the budget became %+v from %+v", got.Budget, m.Budget)
	}
}

// A role that cannot write must not leave a writing capability in the list.
//
// Stripped rather than left for Session.check to refuse: both would be
// correct, and an agent that holds write_page and is refused every time it
// tries looks broken in a trace, while one that never held it reads as what
// it is.
func TestAWritingCapabilityIsRemovedAndNotJustRefused(t *testing.T) {
	got := narrowedBy(wideAgent(), asToken(auth.RoleReader, auth.Scope{}))
	for _, c := range got.Capabilities {
		if agent.IsWrite(c) {
			t.Errorf("a reader's agent still holds %q", c)
		}
	}
	// And the reads survive, or this narrowed to nothing and proved little.
	if len(got.Capabilities) == 0 {
		t.Fatal("a reader's agent holds nothing at all")
	}
}

// internal/agent spells "live" as its own constant because it deliberately
// does not import the store or the site. This is where the two are both
// visible, so this is where the drift is caught — and behaviourally rather
// than by comparing one constant against another, which would prove nothing.
func TestNarrowingToLiveMeansTheRealLiveRef(t *testing.T) {
	parent := agent.Manifest{Retrieval: agent.Retrieval{Ref: site.RefLive}}
	child := agent.Manifest{Retrieval: agent.Retrieval{Ref: site.RefDraft}}

	if got := parent.Narrow(child).Retrieval.Ref; got != site.RefLive {
		t.Fatalf("narrowing a draft agent by a live one gave %q, and "+
			"site.RefLive is %q — internal/agent's own spelling has drifted",
			got, site.RefLive)
	}
}
