// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"
	"time"
)

// What changes between runs of one task is taken out of its goal, so the
// runs group as one kind of work.
func TestGoalsGroupByWhatTheyAskFor(t *testing.T) {
	for _, pair := range [][2]string{
		{"Refund order 1234 for sam@example.com", "Refund order 98 for ivo@example.org"},
		{`Summarise "Q3 results" from https://a.example/x`, `Summarise "Annual report" from https://b.example/y`},
	} {
		if a, b := GoalPattern(pair[0]), GoalPattern(pair[1]); a != b {
			t.Errorf("%q and %q grouped as %q and %q", pair[0], pair[1], a, b)
		}
	}
	if GoalPattern("Refund order 12") == GoalPattern("Publish the returns page") {
		t.Error("two kinds of work grouped as one")
	}
}

// The report adds what each run spent into its group, leaves out runs from
// before the window and evaluation runs, and says which model-decided runs
// nobody priced.
func TestTheCostReportAddsRunsIntoTheirGroups(t *testing.T) {
	now := time.Now().UTC()
	run := func(agentName, by, goal string, ago time.Duration, tokens int, micros int64, model string) Record {
		return Record{Agent: agentName, By: by, Goal: goal, Started: now.Add(-ago), Model: model,
			Trace: Trace{Steps: make([]Step, 3),
				Spent: Spend{Tokens: tokens, Cost: micros}}}
	}
	runs := []Record{
		run("helper", "dana", "Refund order 1", time.Hour, 100, 2_000, "gpt"),
		run("helper", "sam", "Refund order 2", 2*time.Hour, 300, 6_000, "gpt"),
		run("writer", "dana", "Draft the page", 3*time.Hour, 50, 0, "local"),
		run("helper", "dana", "Refund order 3", 40*24*time.Hour, 999, 99_000, "gpt"),
	}
	evalRun := run("helper", "dana", "planted", time.Hour, 10, 10, "gpt")
	evalRun.Eval = "case-1"
	runs = append(runs, evalRun)

	rep := CostOf(runs, "agent", now.Add(-30*24*time.Hour))
	if rep.Total.Runs != 3 || rep.Total.Cost != 8_000 || rep.Total.Tokens != 450 || rep.Total.Steps != 9 {
		t.Fatalf("the total is %+v", rep.Total)
	}
	if rep.Rows[0].Key != "helper" || rep.Rows[0].Cost != 8_000 || rep.Rows[0].Runs != 2 {
		t.Fatalf("the most expensive agent is not first: %+v", rep.Rows)
	}
	if rep.Rows[1].Key != "writer" || rep.Rows[1].Unpriced != 1 {
		t.Errorf("a model-decided run nobody priced is not counted as unpriced: %+v", rep.Rows[1])
	}
	if byGoal := CostOf(runs, "goal", now.Add(-30*24*time.Hour)); byGoal.Rows[0].Runs != 2 {
		t.Errorf("two refunds are not one kind of goal: %+v", byGoal.Rows)
	}
	if got := MoneyText(8_000, "USD"); got != "0.0080 USD" {
		t.Errorf("8000 millionths read as %q", got)
	}
	if got := MoneyText(42, ""); got != "0.000042" {
		t.Errorf("42 millionths read as %q", got)
	}
}
