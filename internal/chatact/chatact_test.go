// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package chatact

import (
	"testing"
	"time"
)

// Whether anything takes requests is known from the dispatcher's last
// beat, so the site can stop offering what nothing will run.
//
// Only the admin server runs a chatbot's agents, and the site had no way to
// know it was not running: it offered the action, took the visitor's
// confirmation and said "Working on it" for good.
func TestTheSiteKnowsWhetherAnythingTakesRequests(t *testing.T) {
	q := Queue{Dir: t.TempDir()}
	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	if q.Taking(now) {
		t.Fatal("taking requests before anything ever beat")
	}
	if err := q.Beat(now); err != nil {
		t.Fatal(err)
	}
	if !q.Taking(now.Add(Stale - time.Second)) {
		t.Fatal("not taking requests just after a beat")
	}
	if q.Taking(now.Add(Stale + time.Second)) {
		t.Fatal("taking requests long after the last beat")
	}
	// The beat is not a request, and pruning leaves it.
	if p, _ := q.Pending(); len(p) != 0 {
		t.Fatalf("the beat is pending: %+v", p)
	}
	if q.Prune(now.Add(2*Keep)) != 0 {
		t.Fatal("the beat was pruned")
	}
}

// A request somebody took and never answered can be found again.
//
// Nothing could find one: it is not pending, because it is run once, and
// it has no answer. So when the dispatcher that took it stopped, its
// visitor's page said "Working on it" until the request was deleted.
func TestARequestTakenAndNeverAnsweredIsFound(t *testing.T) {
	q := Queue{Dir: t.TempDir()}
	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	ids := map[string]string{}
	for _, what := range []string{"untaken", "taken", "answered", "waiting"} {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		ids[what] = id
		if err := q.Put(Request{ID: id, Chatbot: "help", Action: "booking", At: now}); err != nil {
			t.Fatal(err)
		}
		if what == "untaken" {
			continue
		}
		if mine, err := q.Claim(id, now); err != nil || !mine {
			t.Fatal(mine, err)
		}
	}
	if err := q.Answer(Result{ID: ids["answered"], State: Done, Answer: "Friday.", At: now}); err != nil {
		t.Fatal(err)
	}
	if err := q.Answer(Result{ID: ids["waiting"], State: Waiting, At: now}); err != nil {
		t.Fatal(err)
	}
	got := q.Unfinished()
	if len(got) != 1 || got[0].ID != ids["taken"] || got[0].Chatbot != "help" {
		t.Fatalf("taken and never answered: %+v", got)
	}
	// Answered, it is unfinished no more.
	if err := q.Answer(Result{ID: ids["taken"], State: Failed, At: now}); err != nil {
		t.Fatal(err)
	}
	if got := q.Unfinished(); len(got) != 0 {
		t.Fatalf("still unfinished: %+v", got)
	}
}
