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
