// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func inForce(t *testing.T, root, name string) (Playbook, bool) {
	t.Helper()
	bk, err := LoadBook(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, pb := range bk.InForce() {
		if pb.Name == name {
			return pb, true
		}
	}
	return Playbook{}, false
}

func TestNothingKeptIsWhatShips(t *testing.T) {
	bk, _ := LoadBook(t.TempDir())
	if !reflect.DeepEqual(bk.InForce(), Builtins()) {
		t.Fatal("an empty book is not the shipped playbooks")
	}
}

func TestAChangeTakesASecondPerson(t *testing.T) {
	root := t.TempDir()
	pb, _ := inForce(t, root, "chatbot-flood")
	pb.Mode = "act"
	p, err := Propose(root, pb, false, "it has watched a month without a false block", "dana", t0)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := inForce(t, root, "chatbot-flood"); got.Mode != "watch" {
		t.Fatal("a proposal took effect")
	}
	if _, err := Decide(root, p.ID, "dana", true, false, t0); err == nil {
		t.Fatal("the proposer approved their own change")
	}
	if _, err := Withdraw(root, p.ID, "sam", t0); err == nil {
		t.Fatal("somebody else withdrew it")
	}
	d, err := Decide(root, p.ID, "sam", true, false, t0.Add(time.Minute))
	if err != nil || d.Outcome != "approved" || d.DecidedBy != "sam" || d.Alone {
		t.Fatalf("%+v %v", d, err)
	}
	if got, _ := inForce(t, root, "chatbot-flood"); got.Mode != "act" || !got.Builtin {
		t.Fatalf("not in force: %+v", got)
	}
	if _, err := Decide(root, p.ID, "sam", true, false, t0); err == nil {
		t.Fatal("approved twice")
	}
	bk, _ := LoadBook(root)
	if len(bk.Pending) != 0 || len(bk.Decided) != 1 {
		t.Fatalf("pending %d decided %d", len(bk.Pending), len(bk.Decided))
	}
}

func TestTheOnlyAdministratorMayApproveAlone(t *testing.T) {
	root := t.TempDir()
	pb, _ := inForce(t, root, "form-flood")
	pb.Mode = "act"
	p, _ := Propose(root, pb, false, "spam every night", "dana", t0)
	d, err := Decide(root, p.ID, "dana", true, true, t0)
	if err != nil || !d.Alone {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestDeclineAndWithdrawChangeNothing(t *testing.T) {
	root := t.TempDir()
	pb, _ := inForce(t, root, "signin-attack")
	pb.Mode = "off"
	p, _ := Propose(root, pb, false, "noisy", "dana", t0)
	if _, err := Propose(root, pb, false, "again", "sam", t0); err == nil || !strings.Contains(err.Error(), "already waiting") {
		t.Fatalf("a second change to the same playbook: %v", err)
	}
	if d, err := Decide(root, p.ID, "sam", false, false, t0); err != nil || d.Outcome != "declined" {
		t.Fatalf("%+v %v", d, err)
	}
	q, _ := Propose(root, pb, false, "noisy", "dana", t0)
	if d, err := Withdraw(root, q.ID, "dana", t0); err != nil || d.Outcome != "withdrawn" {
		t.Fatalf("%+v %v", d, err)
	}
	if got, _ := inForce(t, root, "signin-attack"); got.Mode != "act" {
		t.Fatal("a declined change took effect")
	}
}

func TestProposalsAreChecked(t *testing.T) {
	root := t.TempDir()
	cur, _ := inForce(t, root, "signin-attack")
	if _, err := Propose(root, cur, false, "same", "dana", t0); err == nil {
		t.Fatal("proposed the playbook as it is")
	}
	bad := cur
	bad.Mode = "ask"
	if _, err := Propose(root, bad, false, "x", "dana", t0); err == nil {
		t.Fatal("an invalid playbook was proposed")
	}
	if _, err := Propose(root, cur, true, "x", "dana", t0); err == nil {
		t.Fatal("a shipped playbook was removed")
	}
	if _, err := Propose(root, valid(), true, "x", "dana", t0); err == nil {
		t.Fatal("removed one that does not exist")
	}
	if _, err := Propose(root, valid(), false, "", "dana", t0); err == nil {
		t.Fatal("no reason given")
	}
	// A new one, then its removal.
	p, _ := Propose(root, valid(), false, "ours", "dana", t0)
	Decide(root, p.ID, "sam", true, false, t0)
	if got, ok := inForce(t, root, "mine"); !ok || got.Builtin {
		t.Fatalf("added: %+v %v", got, ok)
	}
	p, err := Propose(root, valid(), true, "done with it", "dana", t0)
	if err != nil {
		t.Fatal(err)
	}
	Decide(root, p.ID, "sam", true, false, t0)
	if _, ok := inForce(t, root, "mine"); ok {
		t.Fatal("not removed")
	}
	// Claiming to be shipped does not make it so.
	fake := valid()
	fake.Builtin = true
	p, _ = Propose(root, fake, false, "x", "dana", t0)
	if p.Playbook.Builtin {
		t.Fatal("a playbook claimed to ship")
	}
}

func TestSettingAShippedPlaybookBackKeepsNothing(t *testing.T) {
	root := t.TempDir()
	pb, _ := inForce(t, root, "admin-hunting")
	pb.Mode = "watch"
	SetOnMachine(root, pb, false, "testing", "operator", t0)
	pb.Mode = "act"
	SetOnMachine(root, pb, false, "back", "operator", t0)
	bk, _ := LoadBook(root)
	if len(bk.Playbooks) != 0 {
		t.Fatalf("kept %+v", bk.Playbooks)
	}
}

func TestAChangeOnTheMachineReplacesOneWaiting(t *testing.T) {
	root := t.TempDir()
	pb, _ := inForce(t, root, "admin-hunting")
	pb.Mode = "watch"
	p, _ := Propose(root, pb, false, "x", "dana", t0)
	pb.Mode = "off"
	m, err := SetOnMachine(root, pb, false, "incident", "operator", t0)
	if err != nil || m.Outcome != "applied on the machine" {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := Decide(root, p.ID, "sam", true, false, t0); err == nil {
		t.Fatal("the replaced proposal was approved over the machine's change")
	}
	if got, _ := inForce(t, root, "admin-hunting"); got.Mode != "off" {
		t.Fatal("the machine's change is not in force")
	}
	if _, err := SetOnMachine(root, pb, true, "x", "operator", t0); err == nil {
		t.Fatal("a shipped playbook was removed on the machine")
	}
}

func TestAKeptPlaybookThatNoLongerValidatesIsNotRun(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(BookPath(root), []byte(`{"playbooks":[{"name":"signin-attack","title":"x","mode":"act",
		"on":{"signal":"signin-failures","per":"source","count":1,"within":"1h"},
		"stages":[{"do":[{"action":"block-source","where":"all","for":"72h"}]}]}]}`), 0o600)
	bk, err := LoadBook(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := inForce(t, root, "signin-attack"); !reflect.DeepEqual(got, Builtins()[0]) {
		t.Fatalf("ran the invalid one: %+v", got)
	}
	if p := bk.Problems(); len(p) != 1 || !strings.Contains(p[0], "signin-attack") {
		t.Fatalf("problems %v", p)
	}
}

func TestTheLibraryFollowsTheFile(t *testing.T) {
	root := t.TempDir()
	l := &Library{Root: root}
	if !reflect.DeepEqual(l.Get(), Builtins()) {
		t.Fatal("not the shipped playbooks")
	}
	pb := Builtins()[0]
	pb.Mode = "off"
	SetOnMachine(root, pb, false, "x", "operator", t0)
	l.Refresh()
	if l.Get()[0].Mode != "off" {
		t.Fatal("the change was not read")
	}
	os.WriteFile(BookPath(root), []byte("{"), 0o600)
	os.Chtimes(BookPath(root), time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	l.Refresh()
	if l.Get()[0].Mode != "off" {
		t.Fatal("a broken file replaced what was in force")
	}
	fresh := &Library{Root: root}
	// Quilzo's own, watching only: the file may hold two administrators'
	// decision to turn one off.
	got := fresh.Get()
	if !reflect.DeepEqual(got, Watching(Builtins())) {
		t.Fatal("a broken file with nothing read before is not the shipped playbooks, watching")
	}
	for _, pb := range got {
		if pb.Mode == "act" {
			t.Fatalf("%s acts from a broken file", pb.Name)
		}
	}
}
