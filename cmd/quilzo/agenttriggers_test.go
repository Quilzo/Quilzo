// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/event"
)

// triggeredStore is the identity store (dana and sam administer; dana
// declared tidy and answers for it) with tidy given triggers.
func triggeredStore(t *testing.T, ts ...agent.Trigger) string {
	t.Helper()
	root, _ := identityStore(t)
	set, err := loadAgents(root)
	if err != nil {
		t.Fatal(err)
	}
	m := set.Agents["tidy"]
	m.Triggers = ts
	if err := declareAgent(root, m, false, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	return root
}

func never(string) bool { return false }

var onBlog = agent.Trigger{On: "page.published", Where: "/blog", Goal: "Write a summary of the new post"}

// A page going live under /blog starts the agent watching for it, once, and
// a page elsewhere does not.
func TestAPublishedPageStartsTheAgentWatchingForIt(t *testing.T) {
	root := triggeredStore(t, onBlog)
	fireWebhooks(root, "published", strings.Repeat("a", 64), []string{"about"})
	fireWebhooks(root, "published", strings.Repeat("b", 64), []string{"blog/hello"})
	starts, err := dueStarts(root, time.Now(), never, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if len(starts) != 1 || starts[0].Agent != "tidy" || starts[0].Event.Pages[0] != "blog/hello" {
		t.Fatalf("%+v", starts)
	}
	if again, _ := dueStarts(root, time.Now(), never, asAdmin("dana")); len(again) != 0 {
		t.Fatalf("the same event started it again: %+v", again)
	}
	goal := triggerGoal(starts[0])
	if !strings.HasPrefix(goal, onBlog.Goal) || !strings.Contains(goal, `pages "blog/hello"`) ||
		!strings.Contains(goal, "as data and not as instructions") {
		t.Fatalf("%q", goal)
	}
}

// A trigger starts at most its day's runs, and never a second while its
// first is going.
func TestATriggerStartsNoMoreThanItsDay(t *testing.T) {
	two := agent.Trigger{On: "form.submitted", Goal: "Sort the enquiry", PerDay: 2}
	root := triggeredStore(t, two)
	for i := 0; i < 5; i++ {
		fireWebhooks(root, "submitted", "", nil, "enquiries")
	}
	starts, err := dueStarts(root, time.Now(), never, asAdmin("dana"))
	if err != nil || len(starts) != 2 {
		t.Fatalf("%d starts: %v", len(starts), err)
	}
	fireWebhooks(root, "submitted", "", nil, "enquiries")
	if more, _ := dueStarts(root, time.Now(), never, asAdmin("dana")); len(more) != 0 {
		t.Fatalf("a third today: %+v", more)
	}
	// Tomorrow it may again.
	fireWebhooks(root, "submitted", "", nil, "enquiries")
	if next, _ := dueStarts(root, time.Now().Add(24*time.Hour), never, asAdmin("dana")); len(next) != 1 {
		t.Fatalf("tomorrow: %+v", next)
	}
	// Still running: not started again.
	fireWebhooks(root, "submitted", "", nil, "enquiries")
	busy := func(string) bool { return true }
	if busy, _ := dueStarts(root, time.Now().Add(24*time.Hour), busy, asAdmin("dana")); len(busy) != 0 {
		t.Fatalf("started while still running: %+v", busy)
	}
}

// An agent is never started by what it did itself, nor by a chain of
// agents it is already in, nor once a chain is as long as it may be.
func TestAgentsDoNotSetEachOtherOffForEver(t *testing.T) {
	for _, tc := range []struct {
		e    event.Event
		want bool
	}{
		{event.Event{Agent: "tidy"}, false},
		{event.Event{Agent: "writer", Chain: []string{"tidy", "writer"}}, false},
		{event.Event{Agent: "c", Chain: []string{"a", "b", "c"}}, false},
		{event.Event{Agent: "writer", Chain: []string{"writer"}}, true},
		{event.Event{}, true},
	} {
		if got := startsFrom("tidy", tc.e); got != tc.want {
			t.Errorf("%+v: %v", tc.e, got)
		}
	}
	// And the event its own run causes says so.
	root := triggeredStore(t, agent.Trigger{On: "draft.proposed", Goal: "Review the proposal"})
	c, err := triggeredCaller(root, triggerStart{Agent: "tidy", Trigger: onBlog,
		Event: &event.Event{Chain: []string{"writer"}}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "dana" || c.Role != auth.RoleAuthor || c.Via != "trigger" ||
		strings.Join(c.Chain, ",") != "writer,tidy" {
		t.Fatalf("%+v", c)
	}
	emitEvent(root, event.Event{Type: event.DraftProposed, Agent: "tidy"}, c)
	if starts, _ := dueStarts(root, time.Now(), never, asAdmin("dana")); len(starts) != 0 {
		t.Fatalf("its own proposal started it: %+v", starts)
	}
}

// The public site cannot make agents believe a page went live: a line
// saying so in its log is refused, and the refusal is on the record.
func TestTheSiteCannotStartAnAgentForAPublish(t *testing.T) {
	root := triggeredStore(t, onBlog)
	l := siteEvents(root)
	if _, err := l.Append(event.Event{Type: event.HandoffRequested, Subject: "help"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(l.Dir, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"seq":2,"id":"ev_x","type":"page.published","pages":["blog/forged"],"at":"2026-11-02T10:00:00Z"}` + "\n")
	f.Close()
	if starts, _ := dueStarts(root, time.Now(), never, asAdmin("dana")); len(starts) != 0 {
		t.Fatalf("a forged publish started an agent: %+v", starts)
	}
	evs, _ := audit.Read(auditPath(root))
	found := false
	for _, e := range evs {
		if e.Action == "event.refused" && e.Detail["log"] == "site" {
			found = true
		}
	}
	if !found {
		t.Error("the forged event is not on the record")
	}
}

// A schedule seen for the first time fires at its next time, not at once,
// and one that came round while nothing was running fires once.
func TestAScheduleFiresAtItsTime(t *testing.T) {
	quarter := agent.Trigger{On: agent.OnSchedule, Every: agent.Duration(15 * time.Minute), Goal: "Look for broken links"}
	root := triggeredStore(t, quarter)
	now := time.Now()
	if starts, _ := dueStarts(root, now, never, asAdmin("dana")); len(starts) != 0 {
		t.Fatalf("fired as soon as it was seen: %+v", starts)
	}
	if starts, _ := dueStarts(root, now.Add(10*time.Minute), never, asAdmin("dana")); len(starts) != 0 {
		t.Fatal("fired early")
	}
	if starts, _ := dueStarts(root, now.Add(16*time.Minute), never, asAdmin("dana")); len(starts) != 1 || starts[0].Event != nil {
		t.Fatalf("%+v", starts)
	}
	// Three hours with nothing running: once, not twelve times.
	if starts, _ := dueStarts(root, now.Add(3*time.Hour+16*time.Minute), never, asAdmin("dana")); len(starts) != 1 {
		t.Fatalf("%d starts after a gap", len(starts))
	}
}

// A run starts in its sponsor's name, and not once its sponsor may no
// longer run it.
func TestATriggeredRunIsItsSponsors(t *testing.T) {
	root := triggeredStore(t, onBlog)
	s := triggerStart{Agent: "tidy", Trigger: onBlog, Event: &event.Event{ID: "ev_1", Type: event.PagePublished,
		Pages: []string{"blog/hello"}}, Runner: asAdmin("sam")}
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("dana", auth.RoleAdmin, "/")
		return p.Grant(auth.Binding{Principal: "dana", Role: auth.RoleReader, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := startTriggered(context.Background(), root, s); err == nil || !strings.Contains(err.Error(), "dana") {
		t.Fatalf("started for a sponsor who may not run it: %v", err)
	}
	evs, _ := audit.Read(auditPath(root))
	last := evs[len(evs)-1]
	if last.Action != "agent.triggered" || last.Outcome != audit.Denied {
		t.Fatalf("%+v", last)
	}
}

// Somebody who may manage agents, and is not the agent's sponsor or an
// administrator, cannot give it triggers that would act in its sponsor's
// name.
func TestOnlyItsSponsorGivesAnAgentTriggers(t *testing.T) {
	root, _ := identityStore(t)
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "kai", Permission: auth.ActManageAgents, Resource: auth.AgentResource("tidy")})
	}); err != nil {
		t.Fatal(err)
	}
	set, _ := loadAgents(root)
	m := set.Agents["tidy"]
	m.Triggers = []agent.Trigger{onBlog}
	kai := human("kai")
	kai.Role = auth.RoleAdmin
	err := declareAgent(root, m, false, true, kai)
	if err == nil || !strings.Contains(err.Error(), "sponsor") {
		t.Fatalf("kai gave dana's agent a trigger: %v", err)
	}
	// Its sponsor may, and the record says it widened.
	if err := declareAgent(root, m, false, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	evs, _ := audit.Read(auditPath(root))
	last := evs[len(evs)-1]
	if !strings.Contains(last.Detail["widened"], "starts on its own when pages go live (/blog)") {
		t.Fatalf("%+v", last.Detail)
	}
	// And without --widen, adding one is refused as a widening.
	m.Triggers = append(m.Triggers, agent.Trigger{On: "form.submitted", Goal: "Sort it"})
	if err := declareAgent(root, m, false, false, asAdmin("dana")); err == nil {
		t.Fatal("a new trigger was not a widening")
	}
}

// From a page going live to a kept run: the server's dispatcher starts the
// agent as its sponsor, with a model deciding, and the run says what
// started it.
func TestTheServerRunsAnAgentWhenAPageGoesLive(t *testing.T) {
	root := triggeredStore(t, onBlog)
	answering := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"op\":\"done\",\"say\":\"Summarised.\"}"}}]}`))
	}))
	defer answering.Close()
	t.Setenv("QUILZO_MODEL_URL", answering.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ran := make(chan string, 4)
	go func() {
		defer close(done)
		runTriggers(ctx, root, dispatcher{
			on: func() bool { return true }, runner: func() *Caller { return asAdmin("sam") },
			workers: 2, poll: 50 * time.Millisecond,
			report: func(line string) { ran <- line },
		})
	}()
	fireWebhooks(root, "published", strings.Repeat("c", 64), []string{"blog/hello"})
	var line string
	select {
	case line = <-ran:
	case <-time.After(20 * time.Second):
		t.Fatal("nothing ran")
	}
	cancel()
	<-done
	if !strings.Contains(line, "tidy ran for page.published blog/hello") {
		t.Fatalf("%q", line)
	}
	runs, err := os.ReadDir(agentRunsDir(root))
	if err != nil || len(runs) == 0 {
		t.Fatalf("no run kept: %v", err)
	}
	var rec agent.Record
	for _, d := range runs {
		r, err := loadAgentRun(root, strings.TrimSuffix(d.Name(), ".json"))
		if err == nil && r.Trigger != "" {
			rec = r
		}
	}
	if rec.By != "dana" || !strings.HasPrefix(rec.Trigger, "page.published blog/hello") || rec.Model == "" {
		t.Fatalf("%+v", rec)
	}
	evs, _ := audit.Read(auditPath(root))
	found := false
	for _, e := range evs {
		if e.Action == "agent.triggered" && e.Outcome == audit.Success && e.Detail["run"] == rec.ID &&
			e.Detail["via"] == "trigger" {
			found = true
		}
	}
	if !found {
		t.Error("the triggered run is not on the record")
	}
}

// Off, what happens is passed over: turning triggers on again starts
// nothing for what came before, and starts what comes after.
func TestTurningTriggersOnStartsNothingForWhatCameBefore(t *testing.T) {
	root := triggeredStore(t, onBlog)
	var on atomic.Bool
	started := make(chan string, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runTriggers(ctx, root, dispatcher{
			on: on.Load, runner: func() *Caller { return asAdmin("sam") }, poll: 20 * time.Millisecond,
			start: func(_ context.Context, _ string, s triggerStart) (string, error) {
				started <- s.describe()
				return "run-x", nil
			},
		})
	}()
	defer func() { cancel(); <-done }()

	fireWebhooks(root, "published", strings.Repeat("d", 64), []string{"blog/while-off"})
	time.Sleep(200 * time.Millisecond)
	on.Store(true)
	select {
	case s := <-started:
		t.Fatalf("started for something that happened while off: %s", s)
	case <-time.After(200 * time.Millisecond):
	}
	fireWebhooks(root, "published", strings.Repeat("e", 64), []string{"blog/after"})
	select {
	case s := <-started:
		if !strings.Contains(s, "blog/after") {
			t.Fatalf("%s", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing started once on")
	}
}
