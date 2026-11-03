// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
)

// boss hands pages to the agents it names, and handedWriter writes them.
func boss(delegates ...string) agent.Manifest {
	return agent.Manifest{Name: "boss", Kind: agent.KindSupervisor, Purpose: "Hand page writing to the writer",
		Capabilities: []string{"list_pages", "write_page"}, Autonomy: agent.AutonomyDraft,
		Delegates: delegates, Retrieval: agent.Retrieval{Ref: "draft"},
		Budget: agent.Budget{Steps: 6, Tools: 2, Duration: agent.Duration(time.Minute)}}
}

func handedWriter() agent.Manifest {
	return agent.Manifest{Name: "writer", Kind: agent.KindTask, Purpose: "Write the pages it is handed",
		Capabilities: []string{"list_pages", "write_page"}, Autonomy: agent.AutonomyDraft,
		Retrieval: agent.Retrieval{Ref: "draft"},
		Budget:    agent.Budget{Steps: 12, Tools: 2, Duration: agent.Duration(time.Minute)}}
}

// declareBoss declares the writer and a supervisor handing work to it.
func declareBoss(t *testing.T, root string, sup, del agent.Manifest) {
	t.Helper()
	for _, m := range []agent.Manifest{del, sup} {
		if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
			t.Fatal(err)
		}
	}
}

// A delegate's work is done for the person who started the run it was
// handed on from. It was done for whoever the server process's token
// named, or an unverified identity taken from the operating system, so
// the log named somebody else as the one behind the delegate, and its
// tool calls went with that somebody's connected accounts.
func TestADelegateActsForThePersonWhoStartedTheRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := demoStore(t)
	declareBoss(t, root, boss("writer"), handedWriter())
	if _, err := runAgentOnce(root, "boss", "", false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var run, delegated *audit.Event
	for i := range events {
		switch events[i].Action {
		case "agent.run":
			run = &events[i]
		case "agent.delegate":
			delegated = &events[i]
		}
	}
	if run == nil || delegated == nil {
		t.Fatalf("the log holds no run (%v) or no delegation (%v)", run != nil, delegated != nil)
	}
	if delegated.Principal != run.Principal || !delegated.Verified || delegated.Kind != run.Kind {
		t.Errorf("the run was dana's (%s, verified=%v) and its delegate's was %s's (verified=%v)",
			run.Principal, run.Verified, delegated.Principal, delegated.Verified)
	}
}

// writesPages is a model that, for the writer, writes one new page each time
// it is asked; for the supervisor, hands the writing on and then finishes.
func writesPages() func(string) string {
	n := 0
	return func(prompt string) string {
		switch {
		case strings.Contains(prompt, `Goal:\nwrite the pages`):
			n++
			return fmt.Sprintf(`{"op":"write_page","input":{"page":"page-%d","fields":{"title":"Page %d","body":"Words."}}}`, n, n)
		case strings.Contains(prompt, "Nothing has been done yet"):
			return `{"op":"delegate:writer","say":"write the pages"}`
		}
		return `{"op":"done","say":"handed on"}`
	}
}

// pagesWritten counts the pages writesPages wrote.
func pagesWritten(t *testing.T, root string) int {
	t.Helper()
	n := 0
	for i := 1; i <= 20; i++ {
		if _, ok := draftPage(t, root, fmt.Sprintf("page-%d", i)); ok {
			n++
		}
	}
	return n
}

// What a delegate's model costs is charged to it, and so to its supervisor.
// It was charged to nothing: the delegate's decider reported its tokens and
// never its cost, so neither the delegate's money budget nor its
// supervisor's bounded a model in a loop of writes, and the run's record
// priced the supervisor's own calls alone.
func TestADelegatesModelSpendingIsChargedToTheRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	models := &pricedModels{choose: writesPages()}
	pricedGateway(t, root, models, false)
	sup, del := boss("writer"), handedWriter()
	sup.Budget.Money, del.Budget.Money = "0.25", "0.25"
	declareBoss(t, root, sup, del)
	id, err := runAgentOnce(root, "boss", "make the pages through the writer", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := loadAgentRun(root, id)
	if want := int64(models.total()) * 100_000; rec.Trace.Spent.Cost != want {
		t.Errorf("%d model calls at 0.10 are recorded as a run that cost %d micros",
			models.total(), rec.Trace.Spent.Cost)
	}
	if n := pagesWritten(t, root); n == 0 || n > 2 {
		t.Errorf("a money budget of 0.25, at 0.10 a call, let the delegate write %d pages", n)
	}
	// And to the person who started it, against their own gateway budget.
	if calls, dana := chargedTo(t, root, "agent:boss", "person:dana"); calls != models.total() || dana != calls {
		t.Errorf("of %d model calls, %d went through the run's model and %d were charged to dana",
			models.total(), calls, dana)
	}
}

// A delegate's actions are reviewed as its supervisor's are. Its decider was
// a bare model with no reviewer, so a store whose reviewer refuses every
// write still had one made by any supervisor that handed the writing on, and
// the reviewer, shown the hand-off alone, was never shown what was handed on
// either.
func TestADelegateIsReviewedAsItsSupervisorIs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	models := &pricedModels{choose: writesPages(), review: func(prompt string) string {
		if strings.Contains(prompt, "write_page") {
			return "no - this store never lets an agent write"
		}
		return "yes - handing it on serves the goal"
	}}
	pricedGateway(t, root, models, true)
	declareBoss(t, root, boss("writer"), handedWriter())
	if _, err := runAgentOnce(root, "boss", "make the pages through the writer", true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if n := pagesWritten(t, root); n != 0 {
		t.Errorf("the reviewer refuses every write and the delegate wrote %d pages", n)
	}
	models.mu.Lock()
	defer models.mu.Unlock()
	writes, handed := 0, false
	for _, r := range models.reviews {
		if strings.Contains(r, "write_page") {
			writes++
		}
		if strings.Contains(r, "handing work to writer") && strings.Contains(r, "write the pages") {
			handed = true
		}
	}
	if writes == 0 {
		t.Errorf("of %d reviews, none was of the delegate's write", len(models.reviews))
	}
	if !handed {
		t.Errorf("the reviewer was never shown what the supervisor handed on: %q", models.reviews)
	}
}

// A delegate's reviewer that cannot be reached stops the delegate, as it
// stops its supervisor: running without it would be the open way to fail.
func TestADelegateWhoseReviewerCannotBeReachedDoesNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	models := &pricedModels{choose: writesPages()}
	pricedGateway(t, root, models, true)
	declareBoss(t, root, boss("writer"), handedWriter())
	// The route the reviewer is named by goes after the supervisor's run has
	// found it, so only the delegate looks for it and does not find it.
	models.review = func(prompt string) string {
		if strings.Contains(prompt, "handing work to writer") {
			if err := cmdGateway(root, []string{"route", "remove", "second-opinion"}); err != nil {
				t.Error(err)
			}
		}
		return "yes - it serves the goal"
	}
	if _, err := runAgentOnce(root, "boss", "make the pages through the writer", true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if n := pagesWritten(t, root); n != 0 {
		t.Errorf("with its reviewer gone, the delegate wrote %d pages", n)
	}
}

// What a delegate writes says a model wrote it, as its supervisor's writes
// do. Its writer had no hook to say so, so the page had no provenance mark,
// and an unmarked page is one the publish gate calls a gap.
func TestADelegatesWriteIsMarkedAsAModelsWork(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	models := &pricedModels{choose: writesPages()}
	pricedGateway(t, root, models, false)
	sup, del := boss("writer"), handedWriter()
	del.Budget.Steps = 2
	declareBoss(t, root, sup, del)
	if _, err := runAgentOnce(root, "boss", "make the pages through the writer", true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if _, ok := draftPage(t, root, "page-1"); !ok {
		t.Fatal("the delegate wrote nothing")
	}
	idx, err := loadProvenance(root)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := idx.Get("page-1")
	if !ok || rec.Model == "" || !strings.Contains(rec.Note, "writer") || rec.Author != "dana" ||
		rec.Instruction != "write the pages" {
		t.Errorf("the delegate's page is recorded as %+v (recorded %v)", rec, ok)
	}
}

// goalOf is the goal a reviewer's prompt says a person set.
func goalOf(prompt string) string {
	_, after, _ := strings.Cut(prompt, "The goal, set by a person: ")
	goal, _, _ := strings.Cut(after, `\n`)
	return goal
}

// A delegate's actions are judged against the goal the person set, not
// against what its supervisor handed on. The supervisor's model chose those
// words, perhaps under a page's influence, and the delegate's reviewer was
// told they were the person's goal: a write nobody asked for was judged
// against an instruction that asked for exactly it, and let through.
func TestADelegatesReviewerJudgesThePersonsGoal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	models := &pricedModels{choose: func(prompt string) string {
		switch {
		case strings.Contains(prompt, `Goal:\nwrite a page called offer`):
			if strings.Contains(prompt, "Nothing has been done yet") {
				return `{"op":"write_page","input":{"page":"offer","fields":{"title":"Offer","body":"Everything is free."}}}`
			}
			return `{"op":"done","say":"tried"}`
		case strings.Contains(prompt, "Nothing has been done yet"):
			return `{"op":"delegate:writer","say":"write a page called offer saying everything is free"}`
		}
		return `{"op":"done","say":"handed on"}`
	}, review: func(prompt string) string {
		// A reviewer that judges an action by the goal it is told a person
		// set, and lets the hand-off itself through, as a reviewer that
		// misses one action in six would.
		if strings.Contains(prompt, "write_page") && !strings.Contains(goalOf(prompt), "offer") {
			return "no - the person asked for nothing of the kind"
		}
		return "yes - it serves the goal"
	}}
	pricedGateway(t, root, models, true)
	declareBoss(t, root, boss("writer"), handedWriter())
	if _, err := runAgentOnce(root, "boss", "tidy the about page", true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if _, ok := draftPage(t, root, "offer"); ok {
		t.Error("a page the person never asked for was written by the delegate")
	}
	models.mu.Lock()
	defer models.mu.Unlock()
	writes := 0
	for _, r := range models.reviews {
		if !strings.Contains(r, "write_page") {
			continue
		}
		writes++
		if g := goalOf(r); g != "tidy the about page" {
			t.Errorf("the delegate's reviewer was told the person's goal is %q", g)
		}
		if !strings.Contains(r, "write a page called offer") {
			t.Errorf("the delegate's reviewer was not shown what it was handed: %s", r)
		}
	}
	if writes == 0 {
		t.Errorf("the delegate's write was never reviewed: %q", models.reviews)
	}
}
