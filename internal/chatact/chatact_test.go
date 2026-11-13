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
