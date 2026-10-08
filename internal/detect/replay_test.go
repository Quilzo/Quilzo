// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package detect

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// adminFails fires on a failed sign-in by an account whose name starts
// with prefix.
func adminFails(id, prefix string) Rule {
	return Rule{ID: id, Title: id, Sources: []string{"okta/system"},
		When: Predicate{All: []Predicate{
			{Match: &Match{Field: "disposition", Op: Equals, Values: []string{"failed"}}},
			{Match: &Match{Field: "actor.value", Op: Prefix, Values: []string{prefix}}},
		}}}
}

func replayEvent(who string, d telemetry.Disposition) telemetry.Event {
	return telemetry.Event{Source: "okta/system", Disposition: d,
		Actor: telemetry.ID{Issuer: "okta", Value: who}}
}

func TestAReplayCountsWhatARuleCaughtMissedAndWronglyRaised(t *testing.T) {
	rule := adminFails("auth.privileged-failed", "admin-")
	corpus := []Labelled{
		{Name: "a sprayed admin", Expect: []string{rule.ID},
			Event: replayEvent("admin-dana", telemetry.DispositionFailed)},
		{Name: "an admin succeeding",
			Event: replayEvent("admin-dana", telemetry.DispositionAllowed)},
		{Name: "the admin-tools service account, closed false",
			Event: replayEvent("admin-tools-svc", telemetry.DispositionFailed)},
		{Name: "a root account the rule should catch", Expect: []string{rule.ID},
			Event: replayEvent("root", telemetry.DispositionFailed)},
	}
	out, err := Replay([]Rule{rule}, corpus)
	if err != nil {
		t.Fatal(err)
	}
	o := out[0]
	if o.Caught != 1 || o.OK() {
		t.Fatalf("%+v", o)
	}
	if strings.Join(o.Wrong, "|") != "the admin-tools service account, closed false" {
		t.Errorf("wrongly raised: %v", o.Wrong)
	}
	if strings.Join(o.Missed, "|") != "a root account the rule should catch" {
		t.Errorf("missed: %v", o.Missed)
	}
}

// A false positive learned today is reported and does not fail; once the
// rule stops firing on it, it says so.
func TestAPendingFalsePositiveIsKnownUntilTheRuleIsMended(t *testing.T) {
	entry := Labelled{Name: "svc account", Pending: true,
		From:  "finding closed false-positive, rule auth.privileged-failed",
		Event: replayEvent("admin-tools-svc", telemetry.DispositionFailed)}
	wide := adminFails("auth.privileged-failed", "admin-")
	out, _ := Replay([]Rule{wide}, []Labelled{entry})
	if !out[0].OK() || len(out[0].Known) != 1 {
		t.Errorf("a pending false positive: %+v", out[0])
	}
	// The rule is narrowed to people, whose accounts are admin-<name>.
	narrow := wide
	narrow.When.All = append(narrow.When.All, Predicate{Not: &Predicate{
		Match: &Match{Field: "actor.value", Op: Suffix, Values: []string{"-svc"}}}})
	out, _ = Replay([]Rule{narrow}, []Labelled{entry})
	if len(out[0].Mended) != 1 || len(out[0].Known) != 0 {
		t.Errorf("after the fix: %+v", out[0])
	}
	// With the mark off it is a guard: widening the rule again fails.
	entry.Pending = false
	out, _ = Replay([]Rule{wide}, []Labelled{entry})
	if out[0].OK() {
		t.Error("a settled false positive came back and the replay passed")
	}
}

func TestACorpusThatNamesARuleNobodyHasIsAnError(t *testing.T) {
	_, err := Replay([]Rule{adminFails("auth.a", "admin-")}, []Labelled{{
		Name: "x", Expect: []string{"auth.renamed"},
		Event: replayEvent("admin-dana", telemetry.DispositionFailed)}})
	if err == nil {
		t.Error("an entry expecting a rule that does not exist was counted " +
			"as nothing")
	}
	for name, l := range map[string]Labelled{
		"no name":   {Event: replayEvent("a", telemetry.DispositionFailed)},
		"no source": {Name: "x"},
		"pending and expecting": {Name: "x", Pending: true, Expect: []string{"auth.a"},
			Event: replayEvent("a", telemetry.DispositionFailed)},
	} {
		if l.Validate() == nil {
			t.Errorf("an entry with %s was accepted", name)
		}
	}
}
