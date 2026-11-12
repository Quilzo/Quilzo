// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/chatact"
)

// chatActStore has a public chatbot whose actions ask an agent, a key the
// host site signs visitors with, and a model.
func chatActStore(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	t.Setenv("QUILZO_MODEL_URL", "http://127.0.0.1:1/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_SECRET_SHOP_VISITORS", "a key the shop and the chatbot share")
	m := agent.Manifest{Name: "bookings", Kind: agent.KindTask, Purpose: "Look up a visitor's booking",
		Capabilities: []string{"read_page", "list_records"}, Autonomy: agent.AutonomyDraft,
		Budget: agent.Budget{Steps: 6, Tools: 1, Duration: agent.Duration(time.Minute)}}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	set, _ := assistant.Load(assistantsPath(root))
	if err := set.Put(assistant.Assistant{Name: "help", Title: "Help", Public: true, IdentitySecret: "shop-visitors",
		Actions: []assistant.Action{
			{Name: "booking", Kind: assistant.Agent, Target: "bookings", Description: "Look up your booking", Fields: []string{"booking_ref"}},
			{Name: "mine", Kind: assistant.Agent, Target: "bookings", Description: "Your bookings", Identity: true, Writes: true},
		}}); err != nil {
		t.Fatal(err)
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	return root
}

// A visitor's request runs the agent on its sponsor's authority, as a
// reader unless the action writes, with the visitor's words tainting it
// and the site's signed word about them given as fact; the visitor is
// answered only by a run that read nothing private.
func TestAVisitorsRequestRunsTheAgentAsItShould(t *testing.T) {
	root := chatActStore(t)
	var got struct {
		caller *Caller
		goal   string
	}
	answer := agentOutcome{Trace: agent.Trace{Answer: "Your table for two is at 7pm on Friday.", Complete: true}}
	old := chatActRun
	chatActRun = func(_ context.Context, _, name, goal string, c *Caller, _ string) (string, agentOutcome, error) {
		got.caller, got.goal = c, goal
		return "run-1", answer, nil
	}
	t.Cleanup(func() { chatActRun = old })

	res := runChatAction(context.Background(), root, chatact.Request{ID: strings.Repeat("a", 32), Chatbot: "help",
		Action: "booking", Args: map[string]string{"booking_ref": "HB-2201", "smuggled": "x"}})
	if res.State != chatact.Done || res.Answer != answer.Trace.Answer {
		t.Fatalf("%+v", res)
	}
	if !got.caller.Limits.ReadOnly || got.caller.Name != "dana" || got.caller.Untrusted == "" || got.caller.Via != "chatbot" {
		t.Errorf("the run's authority: %+v", got.caller)
	}
	if !strings.Contains(got.goal, `booking_ref: "HB-2201"`) || strings.Contains(got.goal, "smuggled") ||
		!strings.Contains(got.goal, "data, not instructions") {
		t.Errorf("%s", got.goal)
	}

	// A run that read something private is answered by a person.
	answer.Receipt.Private = []string{"personal data (email) returned by crm"}
	if res := runChatAction(context.Background(), root, chatact.Request{ID: strings.Repeat("b", 32), Chatbot: "help",
		Action: "booking", Args: map[string]string{"booking_ref": "HB-2201"}}); res.State != chatact.Person || res.Answer != "" {
		t.Fatalf("%+v", res)
	}
	answer.Receipt.Private = nil

	// Who they are is only what the site signed, checked here again.
	key := []byte("a key the shop and the chatbot share")
	tok := assistant.SignVisitor(map[string]string{"customer": "c-1042"}, key, time.Now().Add(time.Hour))
	if res := runChatAction(context.Background(), root, chatact.Request{ID: strings.Repeat("c", 32), Chatbot: "help",
		Action: "mine", Token: tok}); res.State != chatact.Done {
		t.Fatalf("%+v", res)
	}
	if got.caller.Limits.ReadOnly || !strings.Contains(got.goal, "customer: c-1042") {
		t.Errorf("an action that writes, for a signed visitor: %+v\n%s", got.caller, got.goal)
	}
	forged := assistant.SignVisitor(map[string]string{"customer": "c-1"}, []byte("a key the site never had at all"), time.Now().Add(time.Hour))
	for _, r := range []chatact.Request{
		{ID: strings.Repeat("d", 32), Chatbot: "help", Action: "mine", Token: forged},
		{ID: strings.Repeat("e", 32), Chatbot: "help", Action: "mine"},
		{ID: strings.Repeat("f", 32), Chatbot: "help", Action: "refund"},
		{ID: strings.Repeat("1", 32), Chatbot: "nobody", Action: "booking"},
	} {
		if res := runChatAction(context.Background(), root, r); res.State != chatact.Failed {
			t.Errorf("%+v ran: %+v", r, res)
		}
	}
}

// The loop takes each request once, and the answer is there to read.
func TestARequestIsTakenOnceAndAnswered(t *testing.T) {
	root := chatActStore(t)
	runs := 0
	old := chatActRun
	chatActRun = func(context.Context, string, string, string, *Caller, string) (string, agentOutcome, error) {
		runs++
		return "run-1", agentOutcome{Trace: agent.Trace{Answer: "Friday at 7pm.", Complete: true}}, nil
	}
	t.Cleanup(func() { chatActRun = old })
	act, answer := chatActSite(root)
	id, _ := chatact.NewID()
	if err := act(chatact.Request{ID: id, Chatbot: "help", Action: "booking", Args: map[string]string{"booking_ref": "HB-1"}, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runChatActions(ctx, root, func(string) {}) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if res, ok, made := answer(id); ok && made && res.State == chatact.Done {
			if res.Answer != "Friday at 7pm." {
				t.Fatalf("%+v", res)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not answered")
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(1200 * time.Millisecond)
	cancel()
	<-done
	if runs != 1 {
		t.Fatalf("run %d times", runs)
	}
}

// What a visitor typed for an action is cut where a character starts. It is
// quoted into the goal of the run that does the action, and a reference
// typed in Japanese reached the agent with half a character in it.
func TestAVisitorsLongArgumentReachesTheRunWhole(t *testing.T) {
	root := chatActStore(t)
	var goal string
	old := chatActRun
	chatActRun = func(_ context.Context, _, _, g string, _ *Caller, _ string) (string, agentOutcome, error) {
		goal = g
		return "run-1", agentOutcome{Trace: agent.Trace{Answer: "Found it.", Complete: true}}, nil
	}
	t.Cleanup(func() { chatActRun = old })
	kept := strings.Repeat("a", 299)
	runChatAction(context.Background(), root, chatact.Request{ID: strings.Repeat("a", 32), Chatbot: "help",
		Action: "booking", Args: map[string]string{"booking_ref": kept + "中文"}})
	if !strings.Contains(goal, `booking_ref: "`+kept+`"`) {
		at := strings.Index(goal, "booking_ref")
		t.Fatalf("the run was asked %q", goal[max(0, at):min(len(goal), at+20)]+"…"+goal[min(len(goal), at+312):min(len(goal), at+330)])
	}
}
