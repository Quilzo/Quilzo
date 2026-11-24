// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// registerOn is the register of a store a test made, with an audit log that
// keeps nothing and a fixed clock, for putting records in to be read back.
func registerOn(t *testing.T, root string) *register.Register {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	r := register.Open(s)
	r.Audit = func(audit.Record) error { return nil }
	at := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	r.Now = func() time.Time { return at }
	return r
}

var (
	testOwner  = register.ID("0123456789abcdef0123456789abcdef")
	testPerson = register.Actor{Name: "owner", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman,
		Verified: true, May: func(auth.Action, string) error { return nil }}
	testCrew = register.Actor{Name: "control-tester", Kind: audit.KindAI, Verified: true,
		May: func(auth.Action, string) error { return nil }}
)

// `quilzo register kinds` names every kind the register defines, with its
// collection and how many records it holds, and answers --json.
func TestRegisterKindsNamesEveryKind(t *testing.T) {
	root, token := accessStore(t)
	o, e, code := cliRun(t, root, token, "register", "kinds", "--json")
	if code != 0 {
		t.Fatalf("register kinds: %s", e)
	}
	var got struct {
		Kinds []struct {
			Kind, Collection string
			Records          int
			Fields           []register.Field
		}
	}
	if err := json.Unmarshal([]byte(o), &got); err != nil {
		t.Fatalf("%v\n%s", err, firstLines(o, 4))
	}
	if len(got.Kinds) != len(register.Kinds()) || len(got.Kinds) < 26 {
		t.Fatalf("named %d kinds of %d", len(got.Kinds), len(register.Kinds()))
	}
	for _, k := range got.Kinds {
		if !strings.HasPrefix(k.Collection, register.Prefix) || len(k.Fields) == 0 || k.Records != 0 {
			t.Errorf("%s is described as %+v", k.Kind, k)
		}
	}
	h, _, code := cliRun(t, root, token, "register")
	if code != 0 || !strings.Contains(h, "Control") || !strings.Contains(h, "sec_control") {
		t.Errorf("bare `quilzo register` does not list the kinds: %s", firstLines(h, 4))
	}
}

// What Put wrote is what list and show read back, by its identifier, with
// the hash it is stored under; and a record waiting on the proposals ref is
// not in the register.
func TestRegisterListAndShowReadWhatPutWrote(t *testing.T) {
	root, token := accessStore(t)
	r := registerOn(t, root)
	controls := []register.Record{
		register.Control{Ref: "AC-01", Title: "Second factor for every account", Domain: "identity", Owner: testOwner},
		register.Control{Ref: "AC-02", Title: "Encrypted disks", Domain: "endpoints", Owner: testOwner},
	}
	if _, err := r.Put(testPerson, "two controls", controls...); err != nil {
		t.Fatal(err)
	}
	proposed := register.Control{Ref: "AC-03", Title: "Quarterly access review", Domain: "identity", Owner: testOwner}
	if _, err := r.Propose(testCrew, "drafted from the review", proposed); err != nil {
		t.Fatal(err)
	}
	o, e, code := cliRun(t, root, token, "register", "list", "control", "--json")
	if code != 0 {
		t.Fatalf("register list: %s", e)
	}
	var list struct {
		Kind    string
		Total   int
		Records []struct {
			ID     register.ID
			Record map[string]any
		}
		Head string
	}
	if err := json.Unmarshal([]byte(o), &list); err != nil {
		t.Fatalf("%v\n%s", err, firstLines(o, 4))
	}
	if list.Kind != "Control" || list.Total != 2 || len(list.Records) != 2 || list.Head != r.Head() {
		t.Fatalf("listed %+v", list)
	}
	id := list.Records[0].ID
	o, e, code = cliRun(t, root, token, "register", "show", string(id), "--json")
	if code != 0 {
		t.Fatalf("register show: %s", e)
	}
	var one struct {
		ID     register.ID
		Kind   string
		Object string
		Record map[string]any
	}
	if err := json.Unmarshal([]byte(o), &one); err != nil {
		t.Fatal(err)
	}
	if one.ID != id || one.Kind != "Control" || len(one.Object) != 64 || one.Record["ref"] == nil {
		t.Errorf("show answered %+v", one)
	}
	human, _, _ := cliRun(t, root, token, "register", "list", "Control")
	if !strings.Contains(human, "AC-01") || strings.Contains(human, "AC-03") {
		t.Errorf("the list is not the register's two controls:\n%s", human)
	}
	waitingID, _ := register.IDOf(proposed)
	if _, e, code := cliRun(t, root, token, "register", "show", string(waitingID)); code != 4 {
		t.Errorf("a proposal was shown as a record of the register: %d %s", code, firstLines(e, 2))
	}
	if _, e, code := cliRun(t, root, token, "register", "list", "Nonsense"); code != 4 {
		t.Errorf("a kind that does not exist exited %d: %s", code, firstLines(e, 2))
	}
	if _, e, code := cliRun(t, root, token, "register", "list", "Control", "--limit", "x"); code != 2 {
		t.Errorf("a limit that is not a number exited %d: %s", code, firstLines(e, 2))
	}
}

// A record a crew proposes is waiting for a person: in `quilzo approvals`,
// with the command that lists it, and in `quilzo register proposals`; and it
// is in no list of the register itself (PLAN theme 8).
func TestProposalShowsInWaiting(t *testing.T) {
	root, token := accessStore(t)
	r := registerOn(t, root)
	proposed := register.Control{Ref: "AC-09", Title: "Quarterly access review", Domain: "identity", Owner: testOwner}
	rc, err := r.Propose(testCrew, "drafted from the access review", proposed)
	if err != nil || len(rc.Written) != 1 {
		t.Fatalf("propose: %v %+v", err, rc)
	}
	id := rc.Written[0].ID
	o, e, code := cliRun(t, root, token, "approvals", "--json")
	if code != 0 {
		t.Fatalf("approvals: %s", e)
	}
	var w struct{ Waiting []waitingItem }
	if err := json.Unmarshal([]byte(o), &w); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range w.Waiting {
		if it.Source == "register" && it.ID == string(id) {
			found = true
			if it.Agent != "control-tester" || it.Decide != "quilzo register proposals" || strings.Contains(it.What, "Quarterly") {
				t.Errorf("the proposal waits as %+v", it)
			}
		}
	}
	if !found {
		t.Fatalf("the proposal is not in what waits: %s", firstLines(o, 10))
	}
	o, e, code = cliRun(t, root, token, "register", "proposals", "--json")
	if code != 0 || !strings.Contains(o, string(id)) {
		t.Errorf("register proposals: %d %s %s", code, firstLines(o, 4), e)
	}
	o, _, _ = cliRun(t, root, token, "register", "list", "Control", "--json")
	if strings.Contains(o, string(id)) {
		t.Errorf("the proposal is listed in the register: %s", firstLines(o, 4))
	}
}
