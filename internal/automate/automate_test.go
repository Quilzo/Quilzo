// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package automate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type recorder struct{ did []string }

func actions(rec *recorder) map[string]Action {
	run := func(id string) func(Event, map[string]string) (string, error) {
		return func(ev Event, with map[string]string) (string, error) {
			rec.did = append(rec.did, id+":"+ev.Subject+":"+with["to"])
			if id == "broken" {
				return "", errors.New("the other system said no")
			}
			return "done", nil
		}
	}
	return map[string]Action{
		"step-up":             {ID: "step-up", Name: "Step up", Does: "make them prove it", Kinds: []string{"signin"}, Inline: true},
		"notify":              {ID: "notify", Name: "Tell somebody", Does: "send a message", Kinds: []string{"signin", "finding", "device", "person"}, Params: []Param{{Name: "to", Choices: []string{"security", "person"}}}, Run: run("notify")},
		"end-sessions":        {ID: "end-sessions", Name: "End sessions", Does: "sign them out", Kinds: []string{"signin", "finding", "person"}, Run: run("end-sessions")},
		"broken":              {ID: "broken", Name: "Broken", Does: "fail", Kinds: []string{"finding"}, Run: run("broken")},
		"open-case":           {ID: "open-case", Name: "Open a case", Does: "open one", Kinds: []string{"finding", "person"}, Run: run("open-case")},
		"okta-suspend-user":   {ID: "okta-suspend-user", Name: "Suspend in Okta", Does: "suspend", Kinds: []string{"finding"}, Run: run("okta-suspend-user")},
		"okta-clear-sessions": {ID: "okta-clear-sessions", Name: "Clear Okta sessions", Does: "clear", Kinds: []string{"finding", "signin"}, Run: run("okta-clear-sessions")},
	}
}

func engine(t *testing.T) (*Engine, *recorder) {
	rec := &recorder{}
	return &Engine{Path: filepath.Join(t.TempDir(), "automate.json"), Actions: actions(rec)}, rec
}

func travelEvent(who string) Event {
	return Event{Kind: "signin", Subject: who, Summary: "London, then Sydney",
		Fields: map[string]string{"signal": "impossible-travel", "role": "author", "kmh": "51000", "how": "token"}}
}

// The rule that matters: impossible travel steps the sign-in up, then
// and there, and tells the security team.
func TestImpossibleTravelStepsTheSignInUpAtOnce(t *testing.T) {
	e, rec := engine(t)
	tpl := Templates[0]
	tpl.Enabled = true
	if _, err := e.Save(tpl, "boss"); err != nil {
		t.Fatal(err)
	}
	out, err := e.Handle(travelEvent("ada"))
	if err != nil {
		t.Fatal(err)
	}
	if !out.StepUp || len(out.Runs) != 1 || out.Runs[0].State != "done" {
		t.Fatalf("outcome %+v", out)
	}
	if strings.Join(rec.did, ";") != "notify:ada:security" {
		t.Errorf("did %v", rec.did)
	}
	if out, _ := e.Handle(Event{Kind: "signin", Subject: "bo", Fields: map[string]string{"signal": "new-device"}}); out.StepUp || len(out.Runs) != 0 {
		t.Error("a sign-in the rule is not about was stepped up")
	}
}

// Watch records what it would do and does nothing; ask waits, and does it
// only when approved; a declined run does nothing.
func TestWatchAndAskDoNothingUntilAPersonSays(t *testing.T) {
	e, rec := engine(t)
	r := Rule{Name: "leaver", Enabled: true, Mode: "watch", When: "finding",
		If:   []Condition{{Field: "source", Op: "is", Value: "estate/leaver-still-active"}},
		Then: []Step{{Action: "okta-suspend-user"}, {Action: "end-sessions"}}}
	r, _ = e.Save(r, "boss")
	ev := Event{Kind: "finding", Subject: "okta:00u1", Fields: map[string]string{"source": "estate/leaver-still-active", "severity": "high"}}
	out, _ := e.Handle(ev)
	if len(rec.did) != 0 || out.Runs[0].State != "watched" || !strings.HasPrefix(out.Runs[0].Steps[0].Said, "would have") {
		t.Fatalf("watching acted: %v %+v", rec.did, out.Runs)
	}
	r.Mode = "ask"
	e.Save(r, "boss")
	out, _ = e.Handle(ev)
	if len(rec.did) != 0 || out.Runs[0].State != "waiting" {
		t.Fatalf("asking acted: %v", rec.did)
	}
	if _, err := e.Decide(out.Runs[0].ID, false, "lee"); err != nil {
		t.Fatal(err)
	}
	if len(rec.did) != 0 {
		t.Error("a declined run acted")
	}
	out, _ = e.Handle(ev)
	run, err := e.Decide(out.Runs[0].ID, true, "lee")
	if err != nil || run.State != "approved" || run.By != "lee" {
		t.Fatalf("approving: %+v %v", run, err)
	}
	if strings.Join(rec.did, ";") != "okta-suspend-user:okta:00u1:;end-sessions:okta:00u1:" {
		t.Errorf("approval did %v", rec.did)
	}
	if _, err := e.Decide(run.ID, true, "lee"); err == nil {
		t.Error("a run was approved twice")
	}
}

// Past its hourly limit, a rule watches instead of acting, and says so.
func TestARuleOverItsLimitWatchesInstead(t *testing.T) {
	e, rec := engine(t)
	e.Save(Rule{Name: "noisy", Enabled: true, Mode: "act", When: "finding", PerHour: 2,
		Then: []Step{{Action: "open-case"}}}, "boss")
	var last Outcome
	for i := 0; i < 4; i++ {
		last, _ = e.Handle(Event{Kind: "finding", Subject: "x"})
	}
	if len(rec.did) != 2 || last.Runs[0].State != "limited" {
		t.Errorf("did %d, last %s", len(rec.did), last.Runs[0].State)
	}
}

// Severity compares in order; numbers compare as numbers; lists and
// containment are without case.
func TestConditionsCompareByMeaning(t *testing.T) {
	ev := Event{Fields: map[string]string{"severity": "High", "kmh": "900", "country": "AU", "title": "Leaver still active"}}
	for _, c := range []struct {
		cond Condition
		want bool
	}{
		{Condition{"severity", "at-least", "medium"}, true},
		{Condition{"severity", "at-least", "critical"}, false},
		{Condition{"kmh", "at-least", "805"}, true},
		{Condition{"kmh", "at-most", "805"}, false},
		{Condition{"country", "one-of", "gb, au"}, true},
		{Condition{"country", "not-one-of", "gb,au"}, false},
		{Condition{"title", "contains", "STILL"}, true},
		{Condition{"missing", "is", ""}, true},
		{Condition{"kmh", "at-least", "fast"}, false},
	} {
		if got := c.cond.Holds(ev); got != c.want {
			t.Errorf("%+v: %v", c.cond, got)
		}
	}
}

// A rule that could not be what it says is refused before it is kept.
func TestARuleThatCannotBeWhatItSaysIsRefused(t *testing.T) {
	e, _ := engine(t)
	base := Rule{Name: "r", Mode: "act", When: "signin", Then: []Step{{Action: "step-up"}}}
	for name, mut := range map[string]func(*Rule){
		"no name":           func(r *Rule) { r.Name = " " },
		"unknown mode":      func(r *Rule) { r.Mode = "yolo" },
		"unknown event":     func(r *Rule) { r.When = "lunch" },
		"unknown field":     func(r *Rule) { r.If = []Condition{{Field: "password", Op: "is", Value: "x"}} },
		"unknown op":        func(r *Rule) { r.If = []Condition{{Field: "signal", Op: "matches", Value: ".*"}} },
		"not a number":      func(r *Rule) { r.If = []Condition{{Field: "kmh", Op: "at-least", Value: "fast"}} },
		"nothing to do":     func(r *Rule) { r.Then = nil },
		"unknown action":    func(r *Rule) { r.Then = []Step{{Action: "rm-rf"}} },
		"wrong event":       func(r *Rule) { r.Then = []Step{{Action: "open-case"}} },
		"param not allowed": func(r *Rule) { r.Then = []Step{{Action: "notify", With: map[string]string{"to": "everybody"}}} },
		"param not known":   func(r *Rule) { r.Then = []Step{{Action: "notify", With: map[string]string{"url": "http://x"}}} },
	} {
		r := base
		mut(&r)
		if _, err := e.Save(r, "boss"); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := e.Save(base, "boss"); err != nil {
		t.Errorf("a good rule was refused: %v", err)
	}
}

// Every template is a rule this engine accepts.
func TestEveryTemplateIsAValidRule(t *testing.T) {
	acts := actions(&recorder{})
	for _, tpl := range Templates {
		if err := tpl.Validate(acts); err != nil {
			t.Errorf("%s: %v", tpl.Name, err)
		}
	}
}

// A failed step is recorded as failed and the rest still run.
func TestAFailingStepIsRecordedAndTheRestRun(t *testing.T) {
	e, rec := engine(t)
	e.Save(Rule{Name: "r", Enabled: true, Mode: "act", When: "finding",
		Then: []Step{{Action: "broken"}, {Action: "open-case"}}}, "boss")
	out, _ := e.Handle(Event{Kind: "finding", Subject: "x", At: time.Now()})
	s := out.Runs[0].Steps
	if s[0].OK || s[0].Said != "the other system said no" || !s[1].OK || len(rec.did) != 2 {
		t.Errorf("steps %+v did %v", s, rec.did)
	}
}

// A slow action does not hold the sign-in: Handle answers at once, and
// what the action said is written to the run when it finishes.
func TestASlowActionDoesNotHoldTheSignIn(t *testing.T) {
	e, _ := engine(t)
	release := make(chan struct{})
	done := make(chan Run, 1)
	e.Async, e.Done = true, func(r Run) { done <- r }
	e.Actions["notify"] = Action{ID: "notify", Name: "Tell somebody", Does: "send", Kinds: []string{"signin"},
		Params: []Param{{Name: "to", Choices: []string{"security", "person"}}},
		Run:    func(Event, map[string]string) (string, error) { <-release; return "told the team", nil }}
	tpl := Templates[0]
	tpl.Enabled = true
	e.Save(tpl, "boss")
	start := time.Now()
	out, err := e.Handle(travelEvent("ada"))
	if err != nil || !out.StepUp {
		t.Fatalf("%+v %v", out, err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("the sign-in waited for the mail")
	}
	if !out.Runs[0].Steps[1].Pending {
		t.Error("the slow step is not shown as being done")
	}
	close(release)
	select {
	case r := <-done:
		if !r.Steps[1].OK || r.Steps[1].Said != "told the team" {
			t.Errorf("finished as %+v", r.Steps[1])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the background action never finished")
	}
	runs, _ := e.Runs()
	if runs[0].Steps[1].Pending || runs[0].Steps[1].Said != "told the team" {
		t.Errorf("the history does not say what it did: %+v", runs[0].Steps[1])
	}
}

// Two processes writing the same file lose nothing.
func TestTwoProcessesLoseNoRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "automate.json")
	rec := &recorder{}
	a := &Engine{Path: path, Actions: actions(rec)}
	b := &Engine{Path: path, Actions: actions(rec)}
	a.Save(Rule{Name: "count", Enabled: true, Mode: "watch", When: "finding", PerHour: 1000,
		Then: []Step{{Action: "open-case"}}}, "boss")
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := a
			if i%2 == 1 {
				e = b
			}
			if _, err := e.Handle(Event{Kind: "finding", Subject: "x"}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	runs, _ := a.Runs()
	if len(runs) != 40 {
		t.Errorf("%d of 40 runs survived two writers", len(runs))
	}
}

// An action that panics is a failed step; the rest still run.
func TestAPanickingActionIsAFailedStep(t *testing.T) {
	e, rec := engine(t)
	e.Actions["broken"] = Action{ID: "broken", Name: "Broken", Does: "x", Kinds: []string{"finding"},
		Run: func(Event, map[string]string) (string, error) { panic("nil map") }}
	e.Save(Rule{Name: "r", Enabled: true, Mode: "act", When: "finding",
		Then: []Step{{Action: "broken"}, {Action: "open-case"}}}, "boss")
	out, err := e.Handle(Event{Kind: "finding", Subject: "x"})
	if err != nil {
		t.Fatal(err)
	}
	s := out.Runs[0].Steps
	if s[0].OK || !strings.Contains(s[0].Said, "failed") || !s[1].OK || len(rec.did) != 1 {
		t.Errorf("steps %+v", s)
	}
}

// Approving does what was shown, even if the rule has changed since.
func TestApprovalDoesWhatWasShown(t *testing.T) {
	e, rec := engine(t)
	r, _ := e.Save(Rule{Name: "tell", Enabled: true, Mode: "ask", When: "finding",
		Then: []Step{{Action: "notify", With: map[string]string{"to": "security"}}}}, "boss")
	out, _ := e.Handle(Event{Kind: "finding", Subject: "x"})
	r.Then = []Step{{Action: "notify", With: map[string]string{"to": "person"}}}
	e.Save(r, "boss")
	e.Decide(out.Runs[0].ID, true, "lee")
	if strings.Join(rec.did, ";") != "notify:x:security" {
		t.Errorf("approval did %v", rec.did)
	}
}

func TestTwoRulesMayNotShareAName(t *testing.T) {
	e, _ := engine(t)
	base := Rule{Name: "Impossible travel", Enabled: true, Mode: "act", When: "signin", Then: []Step{{Action: "step-up"}}}
	if _, err := e.Save(base, "boss"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Save(base, "boss"); err == nil {
		t.Error("a second rule with the same name was kept")
	}
}

// A lock left by a process that died is taken over, not waited on for ever.
func TestAnAbandonedLockIsTakenOver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Minute)
	_ = os.Chtimes(path, old, old)
	unlock, err := lockFile(path, 100*time.Millisecond, time.Minute)
	if err != nil {
		t.Fatalf("an abandoned lock was not taken: %v", err)
	}
	unlock()
	held, _ := lockFile(path, time.Second, time.Minute)
	if _, err := lockFile(path, 50*time.Millisecond, time.Minute); err == nil {
		t.Error("a held lock was taken twice")
	}
	held()
}

// A sign-in carries all its signals; a condition on one finds it among
// them, and risk compares in order.
func TestASignInsSignalsAreASet(t *testing.T) {
	ev := Event{Fields: map[string]string{"signal": "new-ip,new-country,unusual-hour", "risk": "medium"}}
	for _, c := range []struct {
		cond Condition
		want bool
	}{
		{Condition{"signal", "is", "new-country"}, true},
		{Condition{"signal", "is", "impossible-travel"}, false},
		{Condition{"signal", "is-not", "new-country"}, false},
		{Condition{"signal", "one-of", "anonymous-network, unusual-hour"}, true},
		{Condition{"signal", "not-one-of", "anonymous-network,hosting-network"}, true},
		{Condition{"risk", "at-least", "medium"}, true},
		{Condition{"risk", "at-least", "high"}, false},
	} {
		if got := c.cond.Holds(ev); got != c.want {
			t.Errorf("%+v: %v", c.cond, got)
		}
	}
}
