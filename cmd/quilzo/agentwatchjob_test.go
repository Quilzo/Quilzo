// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/shield"
)

// An agent that keeps reaching for what it was refused is told to the
// shield once, which tells the security contact and the agent's sponsor
// and opens a case; the next sweep, with nothing new, tells nobody.
func TestAFlaggedAgentReachesTheShieldAndItsSponsorOnce(t *testing.T) {
	root, _ := identityStore(t)
	set, _ := loadAgents(root)
	id := set.Identities["tidy"]
	id.Sponsor = "sam@example.com"
	set.Identities["tidy"] = id
	if err := saveJSON(agentsPath(root), set); err != nil {
		t.Fatal(err)
	}
	refuse := func(step int) {
		record(root, audit.Record{Action: "agent.action", Resource: "/legal", Outcome: audit.Denied,
			Principal: "agent/tidy", Kind: audit.KindAI, Model: "local", Verified: true,
			Detail: map[string]string{"agent": "tidy", "run": "r1", "step": fmt.Sprint(step), "reason": "authorisation"}})
	}
	for i := 1; i <= 6; i++ {
		refuse(i)
	}
	if n, err := tellTheShieldOfFlags(root, time.Now()); err != nil || n != 1 {
		t.Fatalf("told %d: %v", n, err)
	}
	if n, _ := tellTheShieldOfFlags(root, time.Now()); n != 0 {
		t.Fatalf("the same flag was told again, %d times", n)
	}
	if lost, how := trustLost(root, "tidy"); lost.IsZero() || !strings.Contains(how, "agentwatch flagged it") {
		t.Fatalf("the flag did not cost it its earned autonomy: %v %q", lost, how)
	}
	evs, _ := audit.Read(auditPath(root))
	var flagged, security, sponsor, cases int
	for _, e := range evs {
		switch {
		case e.Action == "agentwatch.flagged" && e.Detail["agent"] == "tidy":
			flagged++
		case e.Action == "shield.notify" && e.Detail["playbook"] == "agent-misbehaving" && e.Detail["did"] == "told the agent's sponsor":
			sponsor++
		case e.Action == "shield.notify" && e.Detail["playbook"] == "agent-misbehaving":
			security++
		case e.Action == "shield.open-case" && e.Detail["playbook"] == "agent-misbehaving":
			cases++
		}
	}
	if flagged != 1 || security != 1 || sponsor != 1 || cases != 1 {
		t.Fatalf("flagged %d, security told %d, sponsor told %d, cases %d", flagged, security, sponsor, cases)
	}

	// A new strike is new news.
	refuse(7)
	if n, _ := tellTheShieldOfFlags(root, time.Now()); n != 1 {
		t.Fatalf("a new strike told %d times", n)
	}
}

func TestOnlyAnAgentsSignalHasASponsorToTell(t *testing.T) {
	for _, c := range []struct {
		s    shield.Signal
		want string
	}{
		{shield.Signal{Name: "agent-hijacked", Subject: "tidy"}, "tidy"},
		{shield.Signal{Name: "model-spend", Subject: "agent:tidy"}, "tidy"},
		{shield.Signal{Name: "agent-misbehaving", Subject: "agent:tidy"}, "tidy"},
		{shield.Signal{Name: "agent-misbehaving", Subject: "app:https://app.example.com/meta"}, ""},
		{shield.Signal{Name: "model-spend", Subject: "chatbot:help"}, ""},
	} {
		if got := agentOf(c.s); got != c.want {
			t.Errorf("%+v: %q", c.s, got)
		}
	}
}

// A sponsor hears two weeks before their agent stops, once for each end
// date: renewing it moves the date, and the next reminder is for the new
// one.
func TestASponsorIsRemindedOnceBeforeTheirAgentStops(t *testing.T) {
	root, _ := identityStore(t)
	set, _ := loadAgents(root)
	id := set.Identities["tidy"]
	id.Sponsor = "sam@example.com"
	set.Identities["tidy"] = id
	if err := saveJSON(agentsPath(root), set); err != nil {
		t.Fatal(err)
	}
	early := id.Expires.Add(-30 * 24 * time.Hour)
	if n, _ := remindSponsors(root, early); n != 0 {
		t.Fatalf("reminded a month ahead: %d", n)
	}
	near := id.Expires.Add(-3 * 24 * time.Hour)
	if n, err := remindSponsors(root, near); n != 1 || err != nil {
		t.Fatalf("three days ahead: %d %v", n, err)
	}
	if n, _ := remindSponsors(root, near.Add(time.Hour)); n != 0 {
		t.Fatalf("reminded again for the same end: %d", n)
	}
	id.Expires = id.Expires.Add(24 * time.Hour)
	set.Identities["tidy"] = id
	if err := saveJSON(agentsPath(root), set); err != nil {
		t.Fatal(err)
	}
	if n, _ := remindSponsors(root, near.Add(2*time.Hour)); n != 1 {
		t.Fatalf("a new end date was not reminded: %d", n)
	}
	evs, _ := audit.Read(auditPath(root))
	got := 0
	for _, e := range evs {
		if e.Action == "agent.renewal-reminded" && e.Detail["agent"] == "tidy" {
			got++
		}
	}
	if got != 2 {
		t.Fatalf("%d reminders recorded", got)
	}
}
