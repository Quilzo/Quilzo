// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

var tnow = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// verdicts makes n findings from one rule in one state, each about a
// different entity unless entity is given.
func verdicts(rule string, state finding.State, n int, entity string) []finding.Finding {
	var out []finding.Finding
	for i := 0; i < n; i++ {
		who := entity
		if who == "" {
			who = fmt.Sprintf("%s-%s-%d", rule, state, i)
		}
		out = append(out, finding.Finding{Kind: finding.FromDetection,
			Source: rule, State: state, Seen: 1, Last: tnow,
			Entity: telemetry.ID{Issuer: "okta", Value: who}})
	}
	return out
}

func statsFor(t *testing.T, ring Ring, fs ...[]finding.Finding) Stats {
	t.Helper()
	var all []finding.Finding
	for _, f := range fs {
		all = append(all, f...)
	}
	rings := map[string]Placement{}
	if ring != "" {
		rings["r"] = Placement{Ring: ring}
	}
	return Measure([]Rule{{ID: "r"}}, all, rings, nil, nil)[0]
}

func TestPrecisionIsNotQuotedFromAHandfulOfVerdicts(t *testing.T) {
	s := statsFor(t, "", verdicts("r", finding.Triaged, 2, ""))
	if _, _, _, enough := s.Useful(); enough {
		t.Error("two verdicts were enough to quote a precision — 100% of two " +
			"is how a noisy rule gets kept")
	}
	s = statsFor(t, "", verdicts("r", finding.Triaged, 7, ""),
		verdicts("r", finding.FalsePositive, 2, ""),
		verdicts("r", finding.Benign, 1, ""),
		verdicts("r", finding.Open, 4, ""))
	rate, low, high, enough := s.Useful()
	if !enough || s.Decided() != 10 || s.Undecided != 4 {
		t.Fatalf("%+v", s)
	}
	if rate != 0.7 || low >= rate || high <= rate || low < 0.35 || high > 0.95 {
		t.Errorf("7 of 10: %.2f in [%.2f, %.2f]", rate, low, high)
	}
	// Benign counts against the useful rate and not against precision.
	if p, _ := s.Precision(); p < 0.77 || p > 0.78 {
		t.Errorf("precision %.3f, want 7/9", p)
	}
}

func TestTheIntervalHasWidthAtTheExtremes(t *testing.T) {
	low, high := wilson(10, 10)
	if low > 0.75 || high < 0.999 {
		t.Errorf("10 of 10 is [%.2f, %.2f]; ten verdicts do not prove a "+
			"rule is always right", low, high)
	}
	low, high = wilson(0, 10)
	if low != 0 || high < 0.25 {
		t.Errorf("0 of 10 is [%.2f, %.2f]", low, high)
	}
}

func proposalsFor(s Stats, sups []Suppression, hits map[string]int) string {
	var out []string
	for _, p := range Propose([]Stats{s}, sups, hits, tnow) {
		out = append(out, p.Do)
	}
	return strings.Join(out, ",")
}

func TestANoisyRuleIsProposedForDemotionAndABorderlineOneIsNot(t *testing.T) {
	noisy := statsFor(t, "", verdicts("r", finding.Triaged, 1, ""),
		verdicts("r", finding.FalsePositive, 11, ""))
	if got := proposalsFor(noisy, nil, nil); got != "demote" {
		t.Errorf("1 real of 12: proposed %q", got)
	}
	// 5 of 12 is 42%, and the likely range reaches well past half.
	borderline := statsFor(t, "", verdicts("r", finding.Triaged, 5, ""),
		verdicts("r", finding.FalsePositive, 7, ""))
	if got := proposalsFor(borderline, nil, nil); got != "" {
		t.Errorf("5 real of 12: proposed %q on evidence that does not "+
			"support it", got)
	}
	few := statsFor(t, "", verdicts("r", finding.FalsePositive, 6, ""))
	if got := proposalsFor(few, nil, nil); got != "" {
		t.Errorf("six verdicts: proposed %q", got)
	}
}

func TestNoiseFromOneThingIsASuppressionNotADemotion(t *testing.T) {
	s := statsFor(t, "", verdicts("r", finding.Triaged, 1, ""),
		verdicts("r", finding.Benign, 1, ""),
		verdicts("r", finding.FalsePositive, 1, ""))
	// One finding about the backup account, closed benign — but findings
	// fold by entity, so the noise is counted per finding. Ten different
	// findings about ten things is a rule problem; here nine are one thing.
	var fs []finding.Finding
	fs = append(fs, verdicts("r", finding.Triaged, 3, "")...)
	for i := 0; i < 9; i++ {
		f := verdicts("r", finding.Benign, 1, "svc-backup")[0]
		f.Entity.Issuer = fmt.Sprintf("okta%d", 0) // the same entity each time
		fs = append(fs, f)
	}
	fs = append(fs, verdicts("r", finding.FalsePositive, 1, "")...)
	s = Measure([]Rule{{ID: "r"}}, fs, nil, nil, nil)[0]
	if s.NoisyEntity != "okta0:svc-backup" || s.NoisyCount != 9 {
		t.Fatalf("noisy entity: %+v", s)
	}
	if got := proposalsFor(s, nil, nil); got != "suppress" {
		t.Errorf("nine of ten noisy verdicts about one account: proposed %q",
			got)
	}
	// Already suppressed: not proposed again.
	sup := Suppression{ID: "s1", Rule: "r", Field: "actor",
		Value: "okta0:svc-backup", At: tnow, Until: tnow.Add(24 * time.Hour)}
	if got := proposalsFor(s, []Suppression{sup}, nil); strings.Contains(got, "suppress") {
		t.Errorf("proposed a suppression that exists: %q", got)
	}
}

func TestATrialRuleIsPromotedOnlyOnEvidence(t *testing.T) {
	good := statsFor(t, Trial, verdicts("r", finding.Triaged, 11, ""),
		verdicts("r", finding.FalsePositive, 1, ""))
	if got := proposalsFor(good, nil, nil); got != "promote" {
		t.Errorf("11 real of 12 in trial: proposed %q", got)
	}
	middling := statsFor(t, Trial, verdicts("r", finding.Triaged, 7, ""),
		verdicts("r", finding.FalsePositive, 5, ""))
	if got := proposalsFor(middling, nil, nil); got != "" {
		t.Errorf("7 real of 12 in trial: proposed %q", got)
	}
}

func goodSuppression() Suppression {
	return Suppression{ID: "s1", Rule: "auth.privileged-failed", Field: "actor",
		Value: "okta:svc-backup", Owner: "dana", Because: "nightly backup",
		By: "dana", Kind: audit.KindHuman, At: tnow,
		Until: tnow.Add(30 * 24 * time.Hour)}
}

func TestASuppressionHasEdges(t *testing.T) {
	if err := goodSuppression().Validate(tnow); err != nil {
		t.Fatalf("a narrow, owned, dated suppression was refused: %v", err)
	}
	for name, spoil := range map[string]func(*Suppression){
		"every rule":         func(s *Suppression) { s.Rule = "*" },
		"a whole source":     func(s *Suppression) { s.Field = "source" },
		"an issuer":          func(s *Suppression) { s.Field = "actor.issuer" },
		"the message":        func(s *Suppression) { s.Field = "message" },
		"a wildcard":         func(s *Suppression) { s.Value = "okta:svc-*" },
		"nobody's":           func(s *Suppression) { s.Owner = "" },
		"for no reason":      func(s *Suppression) { s.Because = " " },
		"for ever":           func(s *Suppression) { s.Until = time.Time{} },
		"for a year":         func(s *Suppression) { s.Until = tnow.Add(365 * 24 * time.Hour) },
		"already over":       func(s *Suppression) { s.Until = tnow.Add(-time.Hour) },
		"written by a model": func(s *Suppression) { s.Kind = audit.KindAI },
		"with no value":      func(s *Suppression) { s.Value = "" },
	} {
		s := goodSuppression()
		spoil(&s)
		if s.Validate(tnow) == nil {
			t.Errorf("a suppression of %s was accepted", name)
		}
	}
}

func TestASuppressionHidesOneThingFromOneRuleUntilItExpires(t *testing.T) {
	s := goodSuppression()
	backup := telemetry.Event{Source: "okta/system",
		Actor: telemetry.ID{Issuer: "okta", Value: "svc-backup"}}
	other := telemetry.Event{Source: "okta/system",
		Actor: telemetry.ID{Issuer: "okta", Value: "admin-dana"}}
	if !s.Hides("auth.privileged-failed", backup, tnow) {
		t.Error("the suppressed account was not hidden")
	}
	if s.Hides("auth.privileged-failed", other, tnow) {
		t.Error("another account was hidden")
	}
	if s.Hides("auth.impossible-travel", backup, tnow) {
		t.Error("another rule was silenced for the same account")
	}
	if s.Hides("auth.privileged-failed", backup, s.Until.Add(time.Minute)) {
		t.Error("an expired suppression still hides")
	}
}

func TestMovingARuleNeedsAPersonAndAReason(t *testing.T) {
	p := Placement{Ring: Trial, By: "dana", At: tnow, Because: "noisy"}
	if err := p.Validate(audit.KindHuman); err != nil {
		t.Fatal(err)
	}
	if p.Validate(audit.KindAI) == nil {
		t.Error("a model moved a rule out of the queue")
	}
	p.Because = ""
	if p.Validate(audit.KindHuman) == nil {
		t.Error("a rule was quietened with no reason")
	}
	p.Ring = "asleep"
	if p.Validate(audit.KindHuman) == nil {
		t.Error("a made-up ring was accepted")
	}
	// Putting a rule back needs no justification.
	if err := (Placement{Ring: Live, By: "dana", At: tnow}).Validate(audit.KindHuman); err != nil {
		t.Errorf("restoring a rule: %v", err)
	}
}

func TestSuppressionsThatHaveRunTheirCourseAreBroughtUp(t *testing.T) {
	expired := goodSuppression()
	expired.ID, expired.Until = "old", tnow.Add(-time.Hour)
	idle := goodSuppression()
	idle.ID, idle.At = "idle", tnow.Add(-45*24*time.Hour)
	idle.Until = tnow.Add(40 * 24 * time.Hour)
	ending := goodSuppression()
	ending.ID, ending.Until = "ending", tnow.Add(5*24*time.Hour)
	busy := goodSuppression()
	busy.ID, busy.At = "busy", tnow.Add(-45*24*time.Hour)
	busy.Until = tnow.Add(40 * 24 * time.Hour)
	got := map[string]string{}
	for _, p := range Propose(nil, []Suppression{expired, idle, ending, busy},
		map[string]int{"ending": 12, "busy": 40}, tnow) {
		got[p.Suppression] = p.Do
	}
	if got["old"] != "retire" || got["idle"] != "retire" ||
		got["ending"] != "renew" || got["busy"] != "" {
		t.Errorf("%v", got)
	}
}
