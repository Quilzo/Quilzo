// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
)

// What the admin reports is kept: a person signed in as the verified human
// they are, and a refusal at the door, with nobody signed in, as an
// anonymous caller — written, not refused by the log for having no
// principal, and as the refusal it was.
func TestTheAdminsRecordsAreKeptAndSayWhatHappened(t *testing.T) {
	root := connectStore(t)
	record(root, adminRecord("enrol.refused", "/", map[string]string{"source": "p_1"}))
	record(root, adminRecord("publish", "/", map[string]string{"by": "dana", "commit": "abc"}))
	record(root, adminRecord("publish", "/", map[string]string{"by": "dana", "outcome": "failed"}))
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]audit.Event{}
	for _, e := range evs {
		got[e.Action+"/"+string(e.Outcome)] = e
	}
	door, ok := got["enrol.refused/denied"]
	if !ok || door.Verified || door.Kind != audit.KindUnknown {
		t.Fatalf("a refusal at the door was not kept as an unverified, denied attempt: %+v", evs)
	}
	if e, ok := got["publish/success"]; !ok || !e.Verified || e.Kind != audit.KindHuman {
		t.Errorf("a person's publish was not kept as theirs: %+v", evs)
	}
	if _, ok := got["publish/failure"]; !ok {
		t.Errorf("a failed publish was kept as something else: %+v", evs)
	}
}
