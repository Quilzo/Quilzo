// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package incident

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var day0 = time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC)

func kept(t *testing.T) *Incident {
	t.Helper()
	i, err := Declare("inc-20260928-0a1b2c", "Payroll export reachable",
		Sev2, "dana", day0, "eu", "nis2")
	if err != nil {
		t.Fatal(err)
	}
	return i
}

// Stored and read back, the record keeps its order and keeps working.
func TestAStoredIncidentComesBackInTheOrderItWasWritten(t *testing.T) {
	i := kept(t)
	for n, a := range []Action{
		{Do: "assign", Role: Commander, Who: "sam"},
		{Do: "note", Text: "export bucket was public since Friday"},
		{Do: "decide", Trigger: Aware, Text: "access logs show two downloads"},
		{Do: "link", Finding: "f-123"},
	} {
		// Written from machines whose clocks disagree: later entries carry
		// earlier times.
		if err := i.Apply(a, "dana", day0.Add(-time.Duration(n)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(i)
	if err != nil {
		t.Fatal(err)
	}
	var back Incident
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	back.Restore()
	before, after := i.Timeline(), back.Timeline()
	if len(after) != len(before) {
		t.Fatalf("%d entries came back of %d", len(after), len(before))
	}
	for n := range before {
		if before[n].What != after[n].What {
			t.Fatalf("entry %d is %q, was %q", n, after[n].What, before[n].What)
		}
	}
	// And the next entry goes after the last, not among them.
	if err := back.Apply(Action{Do: "note", Text: "bucket closed"}, "sam",
		day0.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if tl := back.Timeline(); tl[len(tl)-1].What != "bucket closed" {
		t.Errorf("a note after a restore landed at %q", tl[len(tl)-1].What)
	}
	if len(back.Findings) != 1 || len(back.Duties(day0)) != 5 {
		t.Errorf("findings %v, %d duties", back.Findings, len(back.Duties(day0)))
	}
	// An incident with nothing decided comes back able to be decided.
	var bare Incident
	_ = json.Unmarshal([]byte(`{"id":"inc-20260928-000000","title":"x",`+
		`"grade":"sev3","state":"open","regimes":["eu"]}`), &bare)
	bare.Restore()
	if err := bare.Apply(Action{Do: "decide", Trigger: Aware, Text: "y"},
		"dana", day0); err != nil {
		t.Errorf("a restored incident could not be decided: %v", err)
	}
}

func TestOneListOfWhatCanBeDoneAndEachHasItsEdges(t *testing.T) {
	i := kept(t)
	for name, a := range map[string]Action{
		"an unknown action":       {Do: "delete"},
		"a note saying nothing":   {Do: "note", Text: "  "},
		"a clock with no reason":  {Do: "decide", Trigger: Aware},
		"a decision not in table": {Do: "decide", Trigger: "vibes", Text: "x"},
		"a regime not in table":   {Do: "discharge", Regime: "GDPR", Text: "x"},
		"watching for no reason":  {Do: "watch"},
		"reopening what is open":  {Do: "reopen", Text: "x"},
		"unlinking a stranger":    {Do: "unlink", Finding: "f-9"},
		"closing with no cause":   {Do: "close", Actions: []string{"x"}},
		"closing with no action":  {Do: "close", Text: "x", Actions: []string{" "}},
		"a note of ten thousand":  {Do: "note", Text: strings.Repeat("a", 10_000)},
	} {
		if err := i.Apply(a, "dana", day0); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := i.Apply(Action{Do: "note", Text: "x"}, " ", day0); err == nil {
		t.Error("an entry by nobody")
	}
	// A clock is started once.
	ok := Action{Do: "decide", Trigger: Aware, Text: "two downloads"}
	if err := i.Apply(ok, "dana", day0); err != nil {
		t.Fatal(err)
	}
	if err := i.Apply(ok, "sam", day0.Add(time.Hour)); err == nil {
		t.Error("the start of a clock was moved")
	}
	if err := i.Apply(Action{Do: "link", Finding: "f-1"}, "dana", day0); err != nil {
		t.Fatal(err)
	}
	if err := i.Apply(Action{Do: "link", Finding: "f-1"}, "dana", day0); err == nil {
		t.Error("the same finding was linked twice")
	}

	// Closing is refused while a duty is neither met nor ruled out, and
	// afterwards the record takes notes and nothing else.
	closing := Action{Do: "close", Text: "bucket policy copied from a " +
		"public template", Actions: []string{"deny public ACLs at the account"}}
	if err := i.Apply(closing, "dana", day0); err == nil ||
		!strings.Contains(err.Error(), "GDPR Article 33") {
		t.Fatalf("closed over an open obligation: %v", err)
	}
	for _, d := range i.Duties(day0) {
		a := Action{Do: "discharge", Regime: d.Regime, Text: "sent, ref 881"}
		if d.Regime == "GDPR Article 34" {
			a = Action{Do: "waive", Regime: d.Regime, Text: "no high risk: " +
				"the file held no identifiers"}
		}
		if err := i.Apply(a, "dana", day0.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err := i.Apply(closing, "dana", day0.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := i.Apply(Action{Do: "assign", Role: Scribe, Who: "li"}, "dana", day0); err == nil {
		t.Error("a closed incident was changed")
	}
	if err := i.Apply(Action{Do: "note", Text: "regulator acknowledged"},
		"dana", day0.Add(24*time.Hour)); err != nil {
		t.Errorf("a closed incident could not be annotated: %v", err)
	}
}

func TestTheNextDeadlineIsTheNearestOneStillOwed(t *testing.T) {
	i := kept(t)
	if _, any := i.Next(day0); any {
		t.Error("a deadline with no clock running")
	}
	_ = i.Apply(Action{Do: "decide", Trigger: Aware, Text: "x"}, "dana", day0)
	d, _ := i.Next(day0.Add(time.Hour))
	if d.Regime != "NIS2 early warning" || d.Left != 23*time.Hour {
		t.Errorf("next is %s with %s left", d.Regime, d.Left)
	}
	_ = i.Apply(Action{Do: "discharge", Regime: d.Regime, Text: "sent"}, "dana", day0)
	if d, _ = i.Next(day0.Add(80 * time.Hour)); !d.Late() ||
		!strings.HasPrefix(d.Regime, "GDPR Article 33") && !strings.HasPrefix(d.Regime, "NIS2 notification") {
		t.Errorf("after 80 hours the next is %s, late %v", d.Regime, d.Late())
	}
}

func TestAnIdentifierIsAShapeAndNotAPath(t *testing.T) {
	id, err := NewID(day0, "0A1B2C")
	if err != nil || id != "inc-20260928-0a1b2c" {
		t.Fatalf("%q %v", id, err)
	}
	for _, bad := range []string{"", "../audit", "inc-20260928-0a1b2c/x",
		"inc-20260928-0a1b2", "inc-2026-0a1b2c", "INC-20260928-0a1b2c",
		"inc-20260928-0a1b2c\n"} {
		if ValidID(bad) {
			t.Errorf("%q passes as an identifier", bad)
		}
	}
	if _, err := NewID(day0, "../../x"); err == nil {
		t.Error("an identifier was made from a path")
	}
	if got := strings.Join(Scopes(), " "); got != "circia dora eu hipaa nis2 sec" {
		t.Errorf("scopes: %s", got)
	}
}

// Every playbook that ships is one the engine will accept, names a reason
// for every step, and says how each reversible step is reversed.
func TestTheShippedPlaybooksAreWorkable(t *testing.T) {
	all, err := Shipped()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 5 {
		t.Fatalf("%d playbooks ship", len(all))
	}
	for _, p := range all {
		reversible := 0
		for _, s := range p.Steps {
			if s.Undo != "" {
				reversible++
			}
			// The words of an action this program cannot take. A step
			// that reads as if it will be done for you is one nobody does.
			for _, claim := range []string{"automatically", "quilzo will"} {
				if strings.Contains(strings.ToLower(s.Title+s.Why), claim) {
					t.Errorf("%s/%s reads as if it does itself", p.ID, s.ID)
				}
			}
		}
		if reversible == 0 {
			t.Errorf("%s has no step that says how it is reversed", p.ID)
		}
	}
}

func TestAPlaybookThatCannotBeWorkedIsRefused(t *testing.T) {
	ok := Playbook{ID: "x-1", Title: "t", For: "f", Steps: []Step{
		{ID: "a", Title: "t", Why: "w"},
		{ID: "b", Title: "t", Why: "w", Needs: []string{"a"}}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Playbook){
		"no steps":              func(p *Playbook) { p.Steps = nil },
		"a path as an id":       func(p *Playbook) { p.ID = "../x" },
		"a step with no why":    func(p *Playbook) { p.Steps[0].Why = " " },
		"two steps one name":    func(p *Playbook) { p.Steps[1].ID = "a" },
		"a need that is not":    func(p *Playbook) { p.Steps[1].Needs = []string{"z"} },
		"a need that is later":  func(p *Playbook) { p.Steps[0].Needs = []string{"b"} },
		"a step needing itself": func(p *Playbook) { p.Steps[1].Needs = []string{"b"} },
		"nothing it is for":     func(p *Playbook) { p.For = "" },
	} {
		p := Playbook{ID: ok.ID, Title: ok.Title, For: ok.For,
			Steps: append([]Step(nil), ok.Steps...)}
		change(&p)
		if p.Validate() == nil {
			t.Errorf("a playbook with %s was accepted", name)
		}
	}
	if _, err := ReadPlaybook([]byte(`{"id":"x-1"}`)); err == nil {
		t.Error("a playbook with nothing in it was read")
	}
}

func TestARunIsProposedApprovedWorkedInOrderAndRecorded(t *testing.T) {
	i := kept(t)
	p := Playbook{ID: "exposed", Title: "Exposed data", For: "f", Steps: []Step{
		{ID: "close", Title: "Close it", Why: "w", Evidence: true,
			Undo: "restore the old policy"},
		{ID: "logs", Title: "Export logs", Why: "w"},
		{ID: "read", Title: "Read them", Why: "w", Needs: []string{"close", "logs"}},
	}}
	do := func(by string, a Action) error { return i.Apply(a, by, day0) }
	step := func(by, id, outcome, note string) error {
		return do(by, Action{Do: "step", Run: "exposed", Step: id,
			Outcome: outcome, Text: note})
	}
	if do("dana", Action{Do: "propose", Playbook: &p}) == nil {
		t.Error("proposed with no reason it fits")
	}
	if err := do("dana", Action{Do: "propose", Playbook: &p,
		Text: "the bucket was public"}); err != nil {
		t.Fatal(err)
	}
	if do("dana", Action{Do: "propose", Playbook: &p, Text: "again"}) == nil {
		t.Error("the same playbook was started twice")
	}
	// Proposed is not agreed.
	if step("dana", "logs", "done", "") == nil {
		t.Error("a step was worked before anybody approved the run")
	}
	// Whoever proposed it does not also approve it.
	_ = do("dana", Action{Do: "assign", Role: Commander, Who: "sam"})
	if do("dana", Action{Do: "approve", Run: "exposed"}) == nil {
		t.Error("the proposer approved their own proposal")
	}
	if err := do("sam", Action{Do: "approve", Run: "exposed"}); err != nil {
		t.Fatal(err)
	}
	if do("sam", Action{Do: "approve", Run: "exposed"}) == nil {
		t.Error("approved twice")
	}
	for name, err := range map[string]error{
		"out of order":           step("li", "read", "done", "nothing odd"),
		"done with no note":      step("li", "close", "done", " "),
		"skipped for no reason":  step("li", "logs", "skip", ""),
		"undone before done":     step("li", "close", "undo", "x"),
		"a step that is not":     step("li", "zzz", "done", "x"),
		"an outcome that is not": step("li", "logs", "forget", "x"),
	} {
		if err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := step("li", "close", "done", "policy now denies public read"); err != nil {
		t.Fatal(err)
	}
	if step("li", "close", "done", "again") == nil {
		t.Error("done twice")
	}
	if err := step("li", "logs", "skip", "the provider keeps them a year"); err != nil {
		t.Fatal(err)
	}
	if step("li", "logs", "undo", "x") == nil {
		t.Error("a skipped step, or one with no way back, was undone")
	}
	if err := step("omar", "read", "done", ""); err != nil {
		t.Fatalf("a step whose needs were done or skipped: %v", err)
	}
	if step("omar", "read", "undo", "changed my mind") == nil {
		t.Error("a step that does not say how it is reversed was recorded " +
			"as reversed")
	}
	// Reversed, it is owed again, and an incident cannot close over it.
	if err := step("li", "close", "undo", "a build depended on it"); err != nil {
		t.Fatal(err)
	}
	r := i.run("exposed")
	if r.Left() != 1 || r.Steps[0].State != Undone || r.Steps[0].By != "li" {
		t.Errorf("%+v", r.Steps[0])
	}
	for _, d := range i.Duties(day0) {
		_ = i.Apply(Action{Do: "waive", Regime: d.Regime, Text: "test"}, "sam", day0)
	}
	closing := Action{Do: "close", Text: "a template", Actions: []string{"x"}}
	if err := do("sam", closing); err == nil ||
		!strings.Contains(err.Error(), "exposed/close") {
		t.Fatalf("closed over a step nobody finished: %v", err)
	}
	if err := step("li", "close", "done", "closed again, build fixed"); err != nil {
		t.Fatal(err)
	}
	if err := do("sam", closing); err != nil {
		t.Fatal(err)
	}
	// All of it is in the record, by name.
	var said []string
	for _, e := range i.Timeline() {
		said = append(said, e.By+" "+e.What)
	}
	record := strings.Join(said, "\n")
	for _, want := range []string{"dana proposed playbook exposed",
		"sam approved playbook exposed", "li did exposed/close",
		"li skipped exposed/logs: the provider keeps them a year",
		"li undid exposed/close: a build depended on it"} {
		if !strings.Contains(record, want) {
			t.Errorf("the record lacks %q", want)
		}
	}
	// A run nobody approved is also something an incident cannot close over.
	j := kept(t)
	_ = j.Apply(Action{Do: "propose", Playbook: &p, Text: "fits"}, "dana", day0)
	for _, d := range j.Duties(day0) {
		_ = j.Apply(Action{Do: "waive", Regime: d.Regime, Text: "test"}, "dana", day0)
	}
	if err := j.Apply(closing, "dana", day0); err == nil ||
		!strings.Contains(err.Error(), "never approved") {
		t.Errorf("closed over a proposal nobody answered: %v", err)
	}
	// It is withdrawn with a reason, and an approved one is not.
	if j.Apply(Action{Do: "withdraw", Run: "exposed"}, "dana", day0) == nil {
		t.Error("withdrawn for no reason")
	}
	if err := j.Apply(Action{Do: "withdraw", Run: "exposed",
		Text: "it was a share, not a bucket"}, "dana", day0); err != nil {
		t.Fatal(err)
	}
	if err := j.Apply(closing, "dana", day0); err != nil {
		t.Errorf("after withdrawing: %v", err)
	}
	// Unless they are the one commanding it; and a third person may.
	k := kept(t)
	_ = k.Apply(Action{Do: "assign", Role: Commander, Who: "Dana"}, "dana", day0)
	_ = k.Apply(Action{Do: "propose", Playbook: &p, Text: "fits"}, "dana", day0)
	if err := k.Apply(Action{Do: "approve", Run: "exposed"}, "dana", day0); err != nil {
		t.Errorf("the commander could not approve their own proposal: %v", err)
	}
	l := kept(t)
	_ = l.Apply(Action{Do: "propose", Playbook: &p, Text: "fits"}, "dana", day0)
	if err := l.Apply(Action{Do: "approve", Run: "exposed"}, "omar", day0); err != nil {
		t.Errorf("a second person could not approve: %v", err)
	}
	if k.Apply(Action{Do: "withdraw", Run: "exposed", Text: "x"}, "dana", day0) == nil {
		t.Error("an approved run was withdrawn")
	}
}
