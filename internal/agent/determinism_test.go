// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"fmt"
	"testing"
	"time"
)

// The assumption the security figure rests on.
//
// scripts/agentdojo/README.md describes the number this program reports as a
// lower bound:
//
//	An attack the gate refuses cannot succeed for ANY model, however
//	persuadable, which makes the security figure a lower bound rather than
//	an estimate.
//
// That is true only if the gate answers the same way every time. A gate that
// refused an attack on one run and permitted it on the next would have a
// per-attempt refusal rate, and a rate is exactly what a lower bound is not.
//
// Nothing was checking, and there are three ordinary ways it could stop being
// true without anybody meaning it: Go randomises map iteration deliberately,
// budgets are spent in order, and the duration budget is measured against a
// clock. scripts/agentdojo/passk.py measures this over the whole AgentDojo
// corpus through the built binary; this is the same property at the unit, so
// that a change which breaks it fails in the package that broke it rather than
// in a script nobody runs before pushing.

// asked is one session's answer to a sequence, as a comparable value.
func asked(m Manifest, ops []string) []string {
	s := NewSession(m, fixedClock())
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		if err := s.Authorize(op); err != nil {
			out = append(out, "no: "+err.Error())
			continue
		}
		out = append(out, "yes")
	}
	ok, why := s.Publishable()
	out = append(out, fmt.Sprintf("publishable=%v %s", ok, why))
	return out
}

// fixedClock removes the one input that is genuinely allowed to vary.
//
// The duration budget is measured against a clock, so two runs separated by
// enough time legitimately differ. That is not the nondeterminism in question
// — it is the budget working — so it is held still here and the other sources
// are what the comparison is left with.
func fixedClock() Clock {
	at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return at }
}

func TestTheGateAnswersTheSameWayEveryTime(t *testing.T) {
	m := Manifest{
		Name: "support", Kind: KindRetrieval, Purpose: "answer",
		Capabilities: []string{"read_page", "list_pages", "search_pages"},
		Autonomy:     AutonomyPropose,
		Retrieval:    Retrieval{Ref: "live", Types: []string{"article", "faq"}},
		Tools: []Tool{
			{Name: "crm", Host: "api.example.com", Purpose: "lookup"},
		},
		Budget: Budget{Steps: 8, Tools: 3, Duration: Duration(time.Hour)},
	}
	ops := []string{
		"read_page", "publish", "list_pages", "write_page",
		"search_pages", "delete_page", "read_page",
	}

	want := asked(m, ops)
	for i := range 200 {
		if got := asked(m, ops); !equal(got, want) {
			t.Fatalf("pass %d answered differently:\n  first %v\n  then  %v\n"+
				"The gate has a per-attempt rate, so the figure in "+
				"scripts/agentdojo is an estimate and not a lower bound",
				i, want, got)
		}
	}
}

// And the refusals, which are what an operator acts on.
//
// A gate that refuses the same operations and explains them differently is
// still telling somebody a different story each time they look, and the
// explanation is the part a person uses.
func TestARefusalReadsTheSameWayEveryTime(t *testing.T) {
	m := Manifest{
		Name: "support", Kind: KindRetrieval, Purpose: "answer",
		Capabilities: []string{"read_page", "list_pages", "search_pages"},
		Autonomy:     AutonomyPropose,
		Retrieval:    Retrieval{Ref: "live"},
		Budget:       Budget{Steps: 20, Tools: 3, Duration: Duration(time.Hour)},
	}
	var want []string
	for i := range 200 {
		s := NewSession(m, fixedClock())
		_ = s.Authorize("publish")
		_ = s.MayCallTool("crm", "evil.example.com")
		_ = s.Retrieve("draft", "secret", "", "")

		got := make([]string, 0, 3)
		for _, r := range s.Refusals() {
			got = append(got, r.Op+": "+r.Reason)
		}
		if want == nil {
			want = got
			if len(want) != 3 {
				t.Fatalf("expected three refusals, got %d: %v", len(want), want)
			}
			continue
		}
		if !equal(got, want) {
			t.Fatalf("pass %d refused differently:\n  first %v\n  then  %v",
				i, want, got)
		}
	}
}

// The capability list is a map inside the session, and Go randomises map
// iteration on purpose. Anything built from it has to sort.
func TestAnythingBuiltFromAMapComesBackInOneOrder(t *testing.T) {
	m := Manifest{
		Name: "errands", Kind: KindOperator, Purpose: "errands",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyPropose,
		Tools: []Tool{
			{Name: "a", Host: "one.example.com", Purpose: "x"},
			{Name: "b", Host: "two.example.com", Purpose: "y"},
			{Name: "c", Host: "three.example.com", Purpose: "z"},
		},
		Budget: Budget{Steps: 5, Tools: 5, Duration: Duration(time.Hour)},
	}
	var want string
	for range 200 {
		s := NewSession(m, fixedClock())
		err := s.MayReach("nowhere.example.com")
		if err == nil {
			t.Fatal("an undeclared host was permitted")
		}
		if want == "" {
			want = err.Error()
			continue
		}
		if err.Error() != want {
			t.Fatalf("the refusal names the hosts in a different order:\n"+
				"  first %s\n  then  %s", want, err.Error())
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
