// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package gate

import (
	"errors"
	"strings"
	"testing"
)

func pass(name string) Check {
	return Check{
		Name:    name,
		Refusal: func(int) string { return name + " refused" },
		Run: func() (blocking, advisory []Finding, err error) {
			return nil, nil, nil
		},
	}
}

func refuse(name string, findings ...string) Check {
	c := pass(name)
	c.Run = func() (blocking, advisory []Finding, err error) {
		for _, f := range findings {
			blocking = append(blocking, Finding{Detail: f})
		}
		return blocking, nil, nil
	}
	return c
}

func broken(name string) Check {
	c := pass(name)
	c.Run = func() (blocking, advisory []Finding, err error) {
		return nil, nil, errors.New("the file could not be read")
	}
	return c
}

// A check that cannot run is a refusal, not an absence.
//
// This is the failure mode of every gate that returns nil on error: "the claim
// check could not run" reaching somebody as "there are no claims to answer
// for". Corrupting the rules file is then the way to publish anything.
func TestACheckThatCannotRunIsARefusal(t *testing.T) {
	_, _, err := Set{pass("first"), broken("claims"), refuse("later", "x")}.Run()
	if err == nil {
		t.Fatal("a check that errored was treated as a check that passed")
	}
	if !strings.Contains(err.Error(), "could not run") ||
		!strings.Contains(err.Error(), "claims") {
		t.Errorf("the error names neither the problem nor the check: %v", err)
	}
}

// The first refusal, and the checks after it are not run.
//
// A screen listing eight unrelated refusals at once is one nobody reads to the
// end of, and the first is the one to fix.
func TestRunStopsAtTheFirstRefusal(t *testing.T) {
	ran := false
	later := pass("later")
	later.Run = func() (blocking, advisory []Finding, err error) {
		ran = true
		return nil, nil, nil
	}

	refused, _, err := Set{pass("first"), refuse("claims", "a", "b"), later}.Run()
	if err != nil {
		t.Fatal(err)
	}
	if refused == nil {
		t.Fatal("nothing refused")
	}
	if refused.Check.Name != "claims" || len(refused.Findings) != 2 {
		t.Errorf("refused by %q with %d finding(s)",
			refused.Check.Name, len(refused.Findings))
	}
	if ran {
		t.Error("a check after the refusal ran anyway")
	}
}

// Advice from the checks that passed comes back either way.
//
// It is the half worth having: a licence expiring in six weeks can be renewed
// and one that expired last month cannot.
func TestAdviceSurvivesARefusal(t *testing.T) {
	advisory := pass("rights")
	advisory.Run = func() (blocking, adv []Finding, err error) {
		return nil, []Finding{{Page: "pen.png", Detail: "running out"}}, nil
	}

	refused, advice, err := Set{advisory, refuse("claims", "x")}.Run()
	if err != nil || refused == nil {
		t.Fatalf("refused=%v err=%v", refused, err)
	}
	if len(advice) != 1 || advice[0].Page != "pen.png" {
		t.Errorf("the advice was dropped when a later gate refused: %v", advice)
	}
}

// A clean set says so.
func TestNothingWrongIsNoRefusal(t *testing.T) {
	refused, advice, err := Set{pass("a"), pass("b")}.Run()
	if err != nil || refused != nil || len(advice) != 0 {
		t.Errorf("refused=%v advice=%v err=%v", refused, advice, err)
	}
}

// The refusal reads as one message, naming what to do and what was found.
func TestAReportReadsAsOneMessage(t *testing.T) {
	refused, _, _ := Set{refuse("claims", "pen: Guaranteed")}.Run()
	msg := refused.Error()
	if !strings.Contains(msg, "claims refused") ||
		!strings.Contains(msg, "pen: Guaranteed") {
		t.Errorf("the message loses either the refusal or the finding: %q", msg)
	}
}

// A finding about the set rather than about a page does not invent one.
func TestAFindingWithNoPageIsJustTheDetail(t *testing.T) {
	if got := (Finding{Detail: "the menu points at nothing"}).String(); got !=
		"the menu points at nothing" {
		t.Errorf("got %q", got)
	}
	if got := (Finding{Page: "index", Detail: "wrong"}).String(); got !=
		"index: wrong" {
		t.Errorf("got %q", got)
	}
}
