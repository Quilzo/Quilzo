// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"strings"
	"testing"
	"time"
)

// A kept run is for seeing what happened, not a second copy of the content.
func TestAKeptRunBoundsWhatEachStepReturned(t *testing.T) {
	long := strings.Repeat("x", MaxStored*3)
	tr := Trace{Agent: "answers", Goal: "g", Answer: long, Steps: []Step{
		{N: 1, Allowed: true, Result: long}, {N: 2, Allowed: true, Result: "short"}}}
	rec := Keep("run-20260930-0000beef", "dana", "", time.Now(), tr,
		Receipt{Kind: KindRetrieval})

	if n := len(rec.Trace.Steps[0].Result); n > MaxStored+4 {
		t.Errorf("a step kept %d bytes", n)
	}
	if n := len(rec.Trace.Answer); n > MaxStored+4 {
		t.Errorf("the answer kept %d bytes", n)
	}
	if rec.Trace.Steps[1].Result != "short" {
		t.Error("a short result was changed")
	}
	// The run that was just made is not altered by keeping it.
	if len(tr.Steps[0].Result) != len(long) {
		t.Error("keeping a run cut the trace it was made from")
	}
}

func TestARunIsNamedInAWordByHowItEnded(t *testing.T) {
	for want, r := range map[string]Record{
		"complete": {Trace: Trace{Complete: true}, Receipt: Receipt{Did: 2}},
		"refused":  {Trace: Trace{Complete: true}, Receipt: Receipt{Refused: 2}},
		"failed":   {Trace: Trace{Complete: true}, Receipt: Receipt{Did: 1, Failed: 1}},
		"stopped":  {Receipt: Receipt{Did: 1}},
	} {
		if got := r.Outcome(); got != want {
			t.Errorf("%+v is called %q, wanted %q", r.Receipt, got, want)
		}
	}
	for _, bad := range []string{"", "run-2026093-0000beef", "run-20260930-0000BEEF",
		"run-20260930-0000beef.json", "../run-20260930-0000beef"} {
		if ValidRecordID(bad) {
			t.Errorf("%q names a run", bad)
		}
	}
	if !ValidRecordID("run-20260930-0000beef") {
		t.Error("a well-formed identifier was refused")
	}
}
