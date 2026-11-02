// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// What waits on a person is one list wherever they look: a newsletter issue
// an agent proposed is on it for whoever may send it.
func TestWhatWaitsIsOneList(t *testing.T) {
	root, _ := newsletterStore(t) // dana and sam administer
	list, err := openNewsletter(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := list.NewIssue("index", "Autumn at the bakery", newsletter.Proposed, "writer",
		"the new loaves, for this month's issue", time.Now()); err != nil {
		t.Fatal(err)
	}
	items, err := waitingFor(root, asAdmin("dana"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var found *waitingItem
	for i := range items {
		if items[i].Source == "newsletter" {
			found = &items[i]
		}
	}
	if found == nil || found.Agent != "writer" || found.Commits != "sends" ||
		!strings.Contains(found.What, "Autumn at the bakery") || !strings.Contains(found.Decide, "quilzo newsletter send index") {
		t.Fatalf("%+v in %+v", found, items)
	}
	// Somebody who may not send it does not see it as theirs to decide.
	items, _ = waitingFor(root, human("rhea"), time.Now())
	for _, it := range items {
		if it.Source == "newsletter" {
			t.Fatalf("a reader was asked to send a newsletter: %+v", it)
		}
	}
	// And not over the machine interface: a model reading what it and
	// others wait to have approved is the one reader it is kept from.
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, asAdmin("dana"), t.TempDir())
	if _, mcpErr := callTool(t, srv, "quilzo_read", "list_waiting", nil); mcpErr == nil {
		t.Fatal("the queue of approvals is readable over MCP")
	}
}

// The change to the site waiting for a second approval is on the list of
// the administrator who may give it, and not on its author's.
func TestTheChangeWaitingForApprovalIsOnTheList(t *testing.T) {
	root, _ := newsletterStore(t) // dana and sam administer
	setStaffConfig(t, root, "review.required_approvals", "2")
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{"index": map[string]any{"title": "Crumb, open late"}},
		"open late on Fridays", "sam"); err != nil {
		t.Fatal(err)
	}
	find := func(name string) *waitingItem {
		items, err := waitingFor(root, asAdmin(name), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		for i := range items {
			if items[i].Source == "review" {
				return &items[i]
			}
		}
		return nil
	}
	got := find("dana")
	if got == nil || got.Commits != "publishes" || !strings.Contains(got.Why, "0 of 2 approvals") ||
		!strings.Contains(got.Why, "open late on Fridays") {
		t.Fatalf("%+v", got)
	}
	if find("sam") != nil {
		t.Fatal("the author was asked to approve their own change")
	}
}

func setStaffConfig(t *testing.T, root, key, value string) {
	t.Helper()
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set(key, value, "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
}
