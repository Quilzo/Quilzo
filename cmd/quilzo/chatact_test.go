// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/chatact"
	"github.com/quilzo/quilzo/internal/event"
	"github.com/quilzo/quilzo/internal/handoff"
	"github.com/quilzo/quilzo/internal/public"
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

// That a conversation was opened for a held request is in the audit log,
// and the log is not left refusing what agents do next.
//
// The record was written as a service's with nothing to say a credential
// had proved it, which the log refuses: no handoff.open was kept for a
// conversation the server opened itself, and the refusal was remembered as
// the log's last write having failed. From then until some other record
// went in, every agent's action was refused for want of a log that could
// take its record, in the server that had just held a request for a person.
func TestAHeldRequestsConversationIsRecorded(t *testing.T) {
	root := chatActStore(t)
	old := chatActRun
	chatActRun = func(context.Context, string, string, string, *Caller, string) (string, agentOutcome, error) {
		return "run-1", agentOutcome{Trace: agent.Trace{Answer: "It belongs to somebody at 12 Hill Street.", Complete: true},
			Receipt: agent.Receipt{Private: []string{"personal data (address) returned by crm"}}}, nil
	}
	t.Cleanup(func() { chatActRun = old })
	id := strings.Repeat("d", 32)
	res := runChatAction(context.Background(), root, chatact.Request{ID: id, Chatbot: "help",
		Action: "booking", Args: map[string]string{"booking_ref": "HB-2201"}})
	if res.State != chatact.Person || res.Conversation == "" {
		t.Fatalf("%+v", res)
	}
	if err := auditReady(root); err != nil {
		t.Errorf("after a request was held for a person: %v", err)
	}
	found := false
	for _, r := range auditFor(t, root, "handoff.open") {
		found = found || (r.Detail["conversation"] == handoff.IDFor(res.Conversation) && r.Detail["request"] == id)
	}
	if !found {
		t.Error("nothing records that a conversation was opened for the request")
	}
}

// The dispatcher says it is taking requests, and a request made long
// before it started is answered as not done, rather than run then.
//
// With the admin server stopped, a visitor's confirmed request waited, and
// ran with their words whenever an admin next started, up to a day later,
// long after the visitor had left.
func TestARequestLongBeforeAnythingTookItIsNotRun(t *testing.T) {
	root := chatActStore(t)
	runs := 0
	old := chatActRun
	chatActRun = func(context.Context, string, string, string, *Caller, string) (string, agentOutcome, error) {
		runs++
		return "run-1", agentOutcome{Trace: agent.Trace{Answer: "Friday at 7pm.", Complete: true}}, nil
	}
	t.Cleanup(func() { chatActRun = old })
	q := chatActQueue(root)
	if q.Taking(time.Now()) {
		t.Fatal("taking requests with no dispatcher")
	}
	act, answer := chatActSite(root)
	stale, _ := chatact.NewID()
	fresh, _ := chatact.NewID()
	if err := act(chatact.Request{ID: stale, Chatbot: "help", Action: "booking",
		Args: map[string]string{"booking_ref": "HB-1"}, At: time.Now().Add(-2 * chatact.MaxWait)}); err != nil {
		t.Fatal(err)
	}
	if err := act(chatact.Request{ID: fresh, Chatbot: "help", Action: "booking",
		Args: map[string]string{"booking_ref": "HB-2"}, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runChatActions(ctx, root, func(string) {}) }()
	t.Cleanup(func() { cancel(); <-done })
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		a, okA, _ := answer(stale)
		b, okB, _ := answer(fresh)
		if okA && okB && a.State != chatact.Working && b.State != chatact.Working {
			if a.State != chatact.Failed || b.State != chatact.Done || runs != 1 {
				t.Fatalf("stale %+v, fresh %+v, %d runs", a, b, runs)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not answered")
		}
	}
	if !q.Taking(time.Now()) {
		t.Error("the dispatcher does not say it is taking requests")
	}
}

// A request held for a person reaches one however much the visitor wrote.
//
// What goes into the conversation was cut to the most a message may be and
// then marked as cut, which made it three bytes more than a message may be:
// the conversation was refused, and a visitor who had filled in six or more
// of an action's fields at length was told nobody had been asked, with
// nothing in the Inbox and no notice to staff. The request with the most to
// read was the one that reached nobody.
func TestARequestWithMuchInItStillReachesAPerson(t *testing.T) {
	root := chatActStore(t)
	set, _ := assistant.Load(assistantsPath(root))
	a, _ := set.Get("help")
	fields := []string{"what", "when", "where", "who", "why", "how", "then", "more"}
	a.Actions = append(a.Actions, assistant.Action{Name: "claim", Kind: assistant.Agent, Target: "bookings",
		Description: "Make a claim about your booking", Fields: fields})
	if err := set.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	old := chatActRun
	chatActRun = func(context.Context, string, string, string, *Caller, string) (string, agentOutcome, error) {
		return "run-1", agentOutcome{Trace: agent.Trace{Answer: "It belongs to somebody at 12 Hill Street.", Complete: true},
			Receipt: agent.Receipt{Private: []string{"personal data (address) returned by crm"}}}, nil
	}
	t.Cleanup(func() { chatActRun = old })

	args := map[string]string{}
	for _, f := range fields {
		// As long as a field may be, and ending in a character of several
		// bytes, so that a cut inside one would show.
		args[f] = "HB-2201 " + strings.Repeat("é", (public.MaxActArg-8)/2)
	}
	res := runChatAction(context.Background(), root, chatact.Request{ID: strings.Repeat("c", 32), Chatbot: "help",
		Action: "claim", Args: args})
	if res.State != chatact.Person {
		t.Fatalf("%+v", res)
	}
	if res.Conversation == "" {
		t.Fatal("a long request held for a person reached nobody")
	}
	c, err := handoffStore(root).Get("help", handoff.IDFor(res.Conversation))
	if err != nil {
		t.Fatalf("the held request is not in the Inbox: %v", err)
	}
	if !c.Waiting() || !strings.Contains(c.Messages[0].Text, "what: HB-2201") {
		t.Errorf("the Inbox does not say what was asked: %+v", c)
	}
	if !utf8.ValidString(c.Messages[0].Text) || !utf8.ValidString(c.Question) {
		t.Error("what was asked was cut inside a character")
	}
}

// A request held for a person reaches one when a field was cut inside a
// character, and neither the agent nor the person is given half of one.
//
// A field was cut at its 300th byte wherever that fell, on the site and
// again here. One written in a script of several bytes to the character
// came through with part of a character at its end: the request's file
// keeps that as U+FFFD, three bytes, and the cut here left one byte of it.
// A conversation's text is made valid when it is kept, each such byte
// becoming three again, so a request just under what a message may be went
// over it: the conversation was refused and the visitor told nobody had
// been asked. The agent was given the stray byte too, as "\xef" at the end
// of what the visitor gave.
func TestARequestCutInsideACharacterStillReachesAPerson(t *testing.T) {
	root := chatActStore(t)
	set, _ := assistant.Load(assistantsPath(root))
	a, _ := set.Get("help")
	fields := []string{"what", "when", "where", "who", "why", "how", "more"}
	a.Actions = append(a.Actions, assistant.Action{Name: "claim", Kind: assistant.Agent, Target: "bookings",
		Description: "Make a claim about your booking", Fields: fields})
	if err := set.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	goal := ""
	old := chatActRun
	chatActRun = func(_ context.Context, _, _, g string, _ *Caller, _ string) (string, agentOutcome, error) {
		goal = g
		return "run-1", agentOutcome{Trace: agent.Trace{Answer: "It belongs to somebody at 12 Hill Street.", Complete: true},
			Receipt: agent.Receipt{Private: []string{"personal data (address) returned by crm"}}}, nil
	}
	t.Cleanup(func() { chatActRun = old })

	// As a site that cut at the byte wrote it: 299 letters and the first
	// byte of an é.
	cut := (strings.Repeat("a", public.MaxActArg-1) + "é")[:public.MaxActArg]
	q := chatActQueue(root)
	// The last field at every length around the one that takes the whole
	// request to what a message may be.
	for n := 80; n <= 120; n++ {
		id := fmt.Sprintf("%032x", n)
		args := map[string]string{}
		for _, f := range fields[:len(fields)-1] {
			args[f] = cut
		}
		args["more"] = strings.Repeat("b", n)
		if err := q.Put(chatact.Request{ID: id, Chatbot: "help", Action: "claim", Args: args, At: time.Now()}); err != nil {
			t.Fatal(err)
		}
		r, ok := q.Request(id)
		if !ok {
			t.Fatal("the request was not kept")
		}
		res := runChatAction(context.Background(), root, r)
		if res.State != chatact.Person {
			t.Fatalf("%+v", res)
		}
		if res.Conversation == "" {
			t.Fatalf("with %d bytes in the last field, the request held for a person reached nobody", n)
		}
		c, err := handoffStore(root).Get("help", handoff.IDFor(res.Conversation))
		if err != nil {
			t.Fatalf("the held request is not in the Inbox: %v", err)
		}
		if said := c.Messages[0].Text; !strings.Contains(said, "what: "+strings.Repeat("a", public.MaxActArg-1)+"\n") ||
			strings.ContainsRune(said, utf8.RuneError) {
			t.Fatalf("the person is given part of a character: %q", said)
		}
		if strings.Contains(goal, `\x`) || strings.ContainsRune(goal, utf8.RuneError) {
			t.Fatalf("the agent is given part of a character:\n%s", goal)
		}
	}
}

// A request that was being done when the admin server stopped is answered
// when one starts again.
//
// The dispatcher that took it wrote that it was working on it, and stopped
// before it wrote anything else: a restart for an upgrade, a crash, or a
// shutdown with the request still queued behind others. Nothing takes a
// request twice, and the site saw a dispatcher beating again, so the
// visitor's page said "Working on it" and reloaded every three seconds
// until the request was deleted a day later.
func TestARequestCutOffByARestartIsAnswered(t *testing.T) {
	root := chatActStore(t)
	runs := 0
	old := chatActRun
	chatActRun = func(context.Context, string, string, string, *Caller, string) (string, agentOutcome, error) {
		runs++
		return "run-1", agentOutcome{Trace: agent.Trace{Answer: "Friday at 7pm.", Complete: true}}, nil
	}
	t.Cleanup(func() { chatActRun = old })
	q := chatActQueue(root)
	act, answer := chatActSite(root)
	id, _ := chatact.NewID()
	if err := act(chatact.Request{ID: id, Chatbot: "help", Action: "booking",
		Args: map[string]string{"booking_ref": "HB-1"}, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// The dispatcher that took it stopped there.
	if mine, err := q.Claim(id, time.Now()); err != nil || !mine {
		t.Fatal(mine, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runChatActions(ctx, root, func(string) {}) }()
	t.Cleanup(func() { cancel(); <-done })
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if res, ok, _ := answer(id); ok && res.State != chatact.Working {
			// Not run again: it may have changed something the first time.
			if res.State != chatact.Failed || runs != 0 {
				t.Fatalf("%+v, %d runs", res, runs)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the visitor is still told it is being worked on")
		}
	}
	found := false
	for _, r := range auditFor(t, root, "assistant.act.failed") {
		found = found || r.Detail["request"] == id
	}
	if !found {
		t.Error("nothing records that the request was not finished")
	}
}

// What a chatbot offers is told to whoever asks it over the agent
// interface, as it is on the command line and the Chatbots screen.
//
// ask_assistant gave the answer's words and left out what it offered. An
// answer that is only an offer came back as "This is something I can help
// with." and nothing to say what, and an offer beside a page's words was
// not told at all, so an owner or an agent testing a chatbot there could
// not see that it offers an action, which is what they were asking to see.
func TestAnOfferIsToldOverTheAgentInterface(t *testing.T) {
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
	bookingOfferModel(t)
	srv := assistantMCP(t, root)
	text, merr := callTool(t, srv, "quilzo_read", "ask_assistant", map[string]any{
		"name": "help", "question": "Please look up HB-2201"})
	if merr != nil {
		t.Fatal(merr.Message)
	}
	var ans struct {
		Answer  string
		Refused bool
		Offers  *struct {
			Name, Description string
			Args              map[string]string
		}
	}
	if err := json.Unmarshal([]byte(text), &ans); err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	if ans.Refused || ans.Offers == nil || ans.Offers.Name != "booking" ||
		ans.Offers.Description != "Look up your booking" || ans.Offers.Args["booking_ref"] != "HB-2201" {
		t.Fatalf("what it offers is not told: %s", text)
	}
}
