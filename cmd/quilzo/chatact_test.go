// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/chatact"
	"github.com/quilzo/quilzo/internal/event"
	"github.com/quilzo/quilzo/internal/handoff"
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

// A visitor whose request waits for a person is told the outcome on the
// page they asked on, once the person has answered and the run has ended,
// and nobody else's request is.
//
// The visitor's page used to stop at "A person needs to look at this, and
// will." for good: the request was answered "person" the moment the run
// stopped to ask, and nothing looked at it again, so the run's final words
// after the person let it go ahead reached the run's record and never the
// visitor.
func TestAVisitorIsToldTheOutcomeOnceAPersonHasAnswered(t *testing.T) {
	root := chatActStore(t)
	waiting := func(id string) agent.Record {
		return agent.Record{ID: id, Agent: "bookings", Goal: "a visitor's request", By: "dana",
			Started: time.Now().UTC(), Trace: agent.Trace{Waiting: &agent.Pending{N: 1,
				Action: agent.Action{Op: "list_records"}, Since: time.Now().UTC()}}}
	}
	runs := map[string]string{"HB-1": "run-20261104-0000000a", "HB-2": "run-20261104-0000000b"}
	old := chatActRun
	chatActRun = func(_ context.Context, root, _, goal string, _ *Caller, _ string) (string, agentOutcome, error) {
		id := runs["HB-1"]
		if strings.Contains(goal, "HB-2") {
			id = runs["HB-2"]
		}
		rec := waiting(id)
		if err := writeAgentRun(root, rec); err != nil {
			t.Error(err)
		}
		return id, agentOutcome{Trace: rec.Trace}, nil
	}
	t.Cleanup(func() { chatActRun = old })

	act, answer := chatActSite(root)
	mine, _ := chatact.NewID()
	theirs, _ := chatact.NewID()
	for id, ref := range map[string]string{mine: "HB-1", theirs: "HB-2"} {
		if err := act(chatact.Request{ID: id, Chatbot: "help", Action: "booking",
			Args: map[string]string{"booking_ref": ref}, At: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runChatActions(ctx, root, func(string) {}) }()
	t.Cleanup(func() { cancel(); <-done })
	until := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(15 * time.Second); !ok(); time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s did not happen", what)
			}
		}
	}
	until("both requests stopping for a person", func() bool {
		a, okA, _ := answer(mine)
		b, okB, _ := answer(theirs)
		return okA && okB && a.State != chatact.Working && b.State != chatact.Working
	})
	for _, id := range []string{mine, theirs} {
		if a, _, _ := answer(id); a.State != chatact.Waiting || a.Answer != "" {
			t.Fatalf("a request waiting for a person: %+v", a)
		}
	}

	// The person lets mine go ahead, and the run ends with its words.
	rec := waiting(runs["HB-1"])
	rec.Trace.Waiting = nil
	rec.Trace.Complete = true
	rec.Trace.Answer = "Your booking HB-1 is moved to Friday at 7pm."
	if err := writeAgentRun(root, rec); err != nil {
		t.Fatal(err)
	}
	until("the visitor being told the outcome", func() bool {
		a, _, _ := answer(mine)
		return a.State == chatact.Done
	})
	if a, _, _ := answer(mine); a.Answer != rec.Trace.Answer {
		t.Errorf("the visitor was told %q", a.Answer)
	}
	// The other request still waits for its own person, and carries
	// nothing of this one.
	time.Sleep(1200 * time.Millisecond)
	if b, _, _ := answer(theirs); b.State != chatact.Waiting || b.Answer != "" {
		t.Errorf("another visitor's request: %+v", b)
	}

	// A run that read something private on the way is answered by a
	// person, as it would have been had it never stopped to ask.
	rec = waiting(runs["HB-2"])
	rec.Trace.Waiting = nil
	rec.Trace.Complete = true
	rec.Trace.Answer = "HB-2 belongs to somebody at 12 Hill Street."
	rec.Receipt.Private = []string{"personal data (address) returned by crm"}
	if err := writeAgentRun(root, rec); err != nil {
		t.Fatal(err)
	}
	until("the private run being handed to a person", func() bool {
		b, _, _ := answer(theirs)
		return b.State == chatact.Person
	})
	if b, _, _ := answer(theirs); b.Answer != "" {
		t.Errorf("a run that read something private answered the visitor: %q", b.Answer)
	}
	// And it reaches that person, in the Inbox, with what was asked.
	b, _, _ := answer(theirs)
	if c, err := handoffStore(root).Get("help", handoff.IDFor(b.Conversation)); err != nil ||
		!strings.Contains(c.Messages[0].Text, "HB-2") {
		t.Errorf("the request held after a person answered is not in the Inbox: %v", err)
	}
}

// lookingUpModel answers as a model that reads the delivery page and then
// tells the visitor what it says.
func lookingUpModel(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"done","say":"UK delivery costs £4.50."}`
		if strings.Contains(string(b), "Nothing has been done yet") {
			choice = `{"op":"read_page","input":{"page":"delivery"}}`
		}
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": choice}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("QUILZO_MODEL_URL", srv.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")
}

// An action that only looks things up runs in a store where access is
// granted by a policy, which is every store with a second person in it.
//
// It failed for every visitor there, and the visitor who confirmed was told
// "This could not be done just now": the run was made read-only first and
// then the policy was asked whether it may start an agent's run, which a
// read-only credential may not. So the safe kind of action, the one an owner
// adds first, never ran, and only the ones declared to change something did.
// The test above did not see it, because its store grants nothing and so
// enforces nothing. Whether the sponsor may run the agent is a question
// about the sponsor; that the run then only reads is a limit on the run.
func TestALookUpRunsWhereAccessIsGranted(t *testing.T) {
	root := chatActStore(t)
	lookingUpModel(t)
	grant := func(role auth.Role) {
		t.Helper()
		pol := &auth.Policy{}
		if err := pol.Grant(auth.Binding{Principal: "dana", Role: role, Resource: "/"}); err != nil {
			t.Fatal(err)
		}
		if err := saveJSON(policyPath(root), pol); err != nil {
			t.Fatal(err)
		}
	}
	grant(auth.RoleAdmin)
	res := runChatAction(context.Background(), root, chatact.Request{ID: strings.Repeat("a", 32), Chatbot: "help",
		Action: "booking", Args: map[string]string{"booking_ref": "HB-2201"}})
	if res.State != chatact.Done || res.Answer != "UK delivery costs £4.50." {
		t.Fatalf("a look-up, confirmed by the visitor: %+v", res)
	}
	// And the run it started is kept as one that only reads.
	runs, err := listAgentRuns(root, "bookings", 10)
	if err != nil || len(runs) != 1 || !runs[0].ReadOnly {
		t.Fatalf("the look-up's run: %+v, %v", runs, err)
	}

	// A sponsor who may not start the agent's run is still refused: the
	// question is asked, of the sponsor.
	grant(auth.RoleReader)
	if res := runChatAction(context.Background(), root, chatact.Request{ID: strings.Repeat("b", 32), Chatbot: "help",
		Action: "booking", Args: map[string]string{"booking_ref": "HB-2201"}}); res.State != chatact.Failed {
		t.Fatalf("a sponsor who may only read ran the agent: %+v", res)
	}
}

// bookingOfferModel answers as a chatbot's model that writes no answer and
// offers to look a booking up, and counts how often it was asked.
func bookingOfferModel(t *testing.T) *int {
	t.Helper()
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant",
				"content": `{"answer": "", "action": {"name": "booking", "args": {"booking_ref": "HB-2201"}}}`}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("QUILZO_MODEL_URL", srv.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")
	return &asked
}

// A chatbot that offers a visitor something to do, for a request no page
// is about, offers it to its owner trying it out; and where an offer has no
// place, nothing is asked for one: a reply drafted for a person to send
// still says the site does not answer that, and a question the site does
// not answer is still one no page answers.
func TestAnOfferIsShownWhereThereIsAPlaceForOne(t *testing.T) {
	root := chatActStore(t)
	set, _ := assistant.Load(assistantsPath(root))
	a, _ := set.Get("help")
	a.UseModel = true
	if err := set.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	asked := bookingOfferModel(t)
	const q = "Please look up HB-2201"

	idx, err := assistantIndex(root, a)
	if err != nil {
		t.Fatal(err)
	}
	m, why := assistantModelAt(root, a)
	if m == nil {
		t.Fatal(why)
	}
	ans, err := assistant.Respond(context.Background(), a, idx, m, q)
	if err != nil || ans.Refused || ans.Proposed == nil || ans.Proposed.Action.Name != "booking" || *asked != 1 {
		t.Fatalf("the owner's own question: %+v, %v, the model asked %d times", ans, err, *asked)
	}

	*asked = 0
	if draft, _, err := suggestReply(root, "help", q); err == nil {
		t.Errorf("a draft for a message no page answers: %q", draft)
	}
	keepGaps(t, root)
	gapKeeper(root)("help", q)
	r, err := checkGaps(context.Background(), root, "help", "dana", time.Now())
	if err != nil || r.Asked != 1 || r.Closed != 0 {
		t.Errorf("a question no page answers, checked again: %+v, %v", r, err)
	}
	if *asked != 0 {
		t.Errorf("the model was asked %d times for an offer nobody could be shown", *asked)
	}
}

// A request held for a person reaches one: it is a conversation in the
// Inbox, staff are told as for any visitor asking for a person, and the
// visitor is given the conversation's address to be answered at.
//
// The visitor was told "A person needs to look at this, and will. You do
// not need to ask again." and nothing put the request in front of anybody:
// no Inbox conversation, no approval, no notice, only an audit record, and
// the visitor had no way back to an answer.
func TestARequestHeldForAPersonReachesOne(t *testing.T) {
	root := chatActStore(t)
	answer := agentOutcome{Trace: agent.Trace{Answer: "HB-2201 is booked by somebody at 12 Hill Street.", Complete: true},
		Receipt: agent.Receipt{Private: []string{"personal data (address) returned by crm"}}}
	old := chatActRun
	chatActRun = func(context.Context, string, string, string, *Caller, string) (string, agentOutcome, error) {
		return "run-1", answer, nil
	}
	t.Cleanup(func() { chatActRun = old })

	res := runChatAction(context.Background(), root, chatact.Request{ID: strings.Repeat("b", 32), Chatbot: "help",
		Action: "booking", Args: map[string]string{"booking_ref": "HB-2201"}})
	if res.State != chatact.Person || res.Answer != "" {
		t.Fatalf("%+v", res)
	}
	if res.Conversation == "" {
		t.Fatal("the visitor was told a person will look, and given nowhere to be answered")
	}
	c, err := handoffStore(root).Get("help", handoff.IDFor(res.Conversation))
	if err != nil {
		t.Fatalf("the held request is not in the Inbox: %v", err)
	}
	if !c.Waiting() || !strings.Contains(c.Question, "Look up your booking") ||
		!strings.Contains(c.Messages[0].Text, "HB-2201") {
		t.Errorf("the Inbox does not say what was asked: %+v", c)
	}
	// What the run read stays out of it: a person looks that up.
	if strings.Contains(c.Question+c.Messages[0].Text, "Hill Street") {
		t.Error("what the run read reached the conversation")
	}
	evs, _, _ := adminEvents(root).Read(0, 100)
	told := false
	for _, e := range evs {
		told = told || (e.Type == event.HandoffRequested && e.Subject == "help")
	}
	if !told {
		t.Error("staff are not told a visitor is waiting")
	}
}
