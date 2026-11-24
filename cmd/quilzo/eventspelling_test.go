// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/event"
	"github.com/quilzo/quilzo/internal/webhook"
)

// The audit's commands, each with the other vocabulary's name for one
// event: a page going live.
//
//	quilzo webhook add … --types page.published    "not an event this sends"
//	quilzo config set notify.events published      "not an event"
//	quilzo agent trigger add tidy --on published   "neither an event nor schedule"
//
// One event, two names, and each surface took one of them. Now each takes
// both, keeps what was typed, and hears the same events.
func TestEverySurfaceTakesAnEventByEitherOfItsNames(t *testing.T) {
	root := triggeredStore(t)
	asOnly(t, root, "dana")
	if err := cmdWebhook(root, []string{"add", "https://hooks.example.org/e1", "--types", "page.published,booked"}); err != nil {
		t.Errorf("a webhook for page.published: %v", err)
	}
	var f hookFile
	b, _ := os.ReadFile(hooksPath(root))
	_ = json.Unmarshal(b, &f)
	if len(f.Endpoints) != 1 || !slices.Equal(f.Endpoints[0].Types, []string{"page.published", "booked"}) {
		t.Fatalf("the endpoint was kept as %+v, not as typed", f.Endpoints)
	}
	if !f.Endpoints[0].Wants("published") || f.Endpoints[0].Wants("submitted") {
		t.Error("an endpoint for page.published is not told what it asked for and only that")
	}
	if err := cmdWebhook(root, []string{"add", "https://hooks.example.org/e2", "--types", "publish"}); err == nil {
		t.Error("a webhook for an event that never happens was accepted")
	}

	if err := cmdConfig(root, []string{"set", "notify.events", "published,handoff.requested"}); err != nil {
		t.Errorf("notify.events by its webhook name: %v", err)
	}
	if got := mustConfig(root).Raw("notify.events"); got != "published,handoff.requested" {
		t.Errorf("notify.events was kept as %q", got)
	}
	if err := cmdAgent(root, []string{"trigger", "tidy", "add", "--on", "published", "--where", "/blog", "--goal", "tidy the post"}); err != nil {
		t.Errorf("a trigger on published: %v", err)
	}
	set, err := loadAgents(root)
	if err != nil {
		t.Fatal(err)
	}
	tr := set.Agents["tidy"].Triggers
	if len(tr) != 1 || !tr[0].Matches(event.Event{Type: event.PagePublished, Pages: []string{"blog/x"}}) {
		t.Errorf("the trigger on published does not start from a page going live: %+v", tr)
	}
}

// Every name a webhook is told is the name of one event, and the acts that
// tell webhooks write that event: a scheduled publish too, which was told
// as "scheduled" and was no event at all.
func TestEveryWebhookNameIsTheWireNameOfOneEvent(t *testing.T) {
	for _, name := range webhook.EventTypes {
		e, ok := eventOfWebhook(webhook.Event{Type: name})
		if !ok {
			t.Errorf("%q is told to webhooks and is no event", name)
			continue
		}
		if wire, _ := event.WebhookName(e.Type); wire != name {
			t.Errorf("%q is the event %s, whose webhook name is %q", name, e.Type, wire)
		}
	}
	if _, ok := eventOfWebhook(webhook.Event{Type: "test"}); ok {
		t.Error("a test delivery is an event")
	}
	root := triggeredStore(t, agent.Trigger{On: "page.published", Goal: "g"})
	before, _, _ := adminEvents(root).Read(0, 1000)
	fireWebhooks(root, "scheduled", "abc", nil)
	after, _, _ := adminEvents(root).Read(0, 1000)
	if len(after) != len(before)+1 || after[len(after)-1].Type != event.PublishScheduled {
		t.Errorf("scheduling a publish wrote %d events, not one publish.scheduled: %+v", len(after)-len(before), after[len(before):])
	}
}
