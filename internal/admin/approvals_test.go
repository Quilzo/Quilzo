// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
)

// waitingRun keeps a run waiting at step 2 on an action, for a reason.
func waitingRun(st *studio, id, agentName string, a agent.Action, why string, since time.Time) {
	tr := agent.Trace{Agent: agentName, Goal: "work",
		Waiting: &agent.Pending{N: 2, Since: since, Action: a, Why: why}}
	st.runs[id] = agent.Keep(id, "dana", "a-model", time.Now(), tr, agent.Receipt{})
}

// Everything an agent waits on is listed, grouped by agent, with what
// deciding commits to; identical actions that only read are offered
// together, and anything that pays is not.
func TestApprovalsListsWhatWaitsAndBatchesOnlyWhatIsHonest(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	var answered []string
	srv.Agents.Answer = func(id string, step int, approve bool, answers map[string]string, by string) error {
		answered = append(answered, fmt.Sprintf("%s %d %v %s", id, step, approve, by))
		return nil
	}
	now := time.Now()
	look := agent.Action{Op: "browser_click", Input: map[string]any{"ref": "e4"}}
	why := `it presses link "Next page" on shop.example.com, and it asks first`
	waitingRun(st, "run-20261013-000000a1", "buyer", look, why, now.Add(-time.Minute))
	waitingRun(st, "run-20261013-000000a2", "buyer", look, why, now.Add(-2*time.Minute))
	pay := agent.Action{Op: "browser_click", Input: map[string]any{"ref": "e9"}}
	waitingRun(st, "run-20261013-000000a3", "buyer", pay, `it presses button "Pay now" on shop.example.com, and it is called "Pay now"`, now)
	waitingRun(st, "run-20261013-000000a4", "buyer", pay, `it presses button "Pay now" on shop.example.com, and it is called "Pay now"`, now)
	old := agent.Action{Op: "read_page", Input: map[string]any{"page": "x"}}
	waitingRun(st, "run-20261013-000000a5", "editor", old, "it asks first", now.Add(-agent.PendingTTL-time.Hour))

	body := get(t, srv, "/approvals", token).Body.String()
	whole(t, body)
	for _, want := range []string{"buyer", "editor", "pays", "acts", "asked too long ago to agree to",
		"2 runs wait on the same action"} {
		if !strings.Contains(body, want) {
			t.Errorf("the approvals screen does not show %q", want)
		}
	}
	if strings.Contains(body, "Let all 2 go ahead</button>") && strings.Count(body, "Let all 2 go ahead") != 1 {
		t.Error("the payment was offered to approve together")
	}

	// Approving the batch approves exactly the runs still waiting on it.
	key := batchKey("buyer", st.runs["run-20261013-000000a1"].Trace.Waiting)
	_, loc := postFormLoc(t, srv, token, "/approvals/act", url.Values{"batch": {key},
		"run": {"run-20261013-000000a1:2", "run-20261013-000000a2:2", "run-20261013-000000a3:2"}})
	if !strings.Contains(loc, "m=2+went+ahead") || len(answered) != 2 {
		t.Fatalf("the batch went to %s and answered %v", loc, answered)
	}
	for _, a := range answered {
		if strings.Contains(a, "000000a3") {
			t.Fatal("a payment was let through with the batch")
		}
	}
	// A key for the payments approves nothing: paying is never batched.
	answered = nil
	payKey := batchKey("buyer", st.runs["run-20261013-000000a3"].Trace.Waiting)
	postFormLoc(t, srv, token, "/approvals/act", url.Values{"batch": {payKey},
		"run": {"run-20261013-000000a3:2", "run-20261013-000000a4:2"}})
	if len(answered) != 0 {
		t.Fatalf("payments were approved together: %v", answered)
	}
}

func postFormLoc(t *testing.T, srv *Server, token, path string, v url.Values) (int, string) {
	t.Helper()
	w := postForm(t, srv, path, token, v.Encode())
	return w.Code, w.Header().Get("Location")
}

// What deciding commits to is read from the action and its reason.
func TestCommitClassesAreReadFromTheActionAndItsReason(t *testing.T) {
	for _, c := range []struct {
		a    agent.Action
		why  string
		kind string
		want string
	}{
		{agent.Action{Op: "read_page"}, "", "", "reads"},
		{agent.Action{Op: "write_page"}, "", "", "writes"},
		{agent.Action{Op: "publish"}, "", "", "publishes"},
		{agent.Action{Op: "browser_type"}, "", "", "sends"},
		{agent.Action{Op: "browser_click"}, `it presses button "Pay now"`, "", "pays"},
		{agent.Action{Op: "browser_click"}, `it presses button "Delete account"`, "", "deletes"},
		{agent.Action{Op: "browser_click"}, `it presses link "Next"`, "", "acts"},
		{agent.Action{Op: "shell_run"}, "it destroys: rm -rf build", "", "deletes"},
		{agent.Action{Op: "decide"}, "", agent.WaitQuestion, "answers"},
		{agent.Action{Tool: "crm"}, "", "", "reads"},
	} {
		if got := agent.CommitOf(c.a, c.why, c.kind, false); got != c.want {
			t.Errorf("%+v (%q) commits to %q, not %q", c.a, c.why, got, c.want)
		}
	}
	if agent.CommitOf(agent.Action{Tool: "crm"}, "", "", true) != "writes" {
		t.Error("a tool that writes was not counted as writing")
	}
}

// Somebody who may decide one agent's runs, and is not an administrator,
// is shown what that agent waits for, opens the run and decides it; another
// agent's runs are neither shown nor theirs to decide.
func TestAnApproverSeesAndDecidesOnlyTheirAgentsRuns(t *testing.T) {
	srv, _ := setup(t)
	st := wireStudio(srv)
	if err := srv.Policy.Grant(auth.Binding{Principal: "ria", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	tok, _, err := srv.Tokens.Issue("ria", "ria", auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv.Agents.MayApprove = func(rec agent.Record, by string) bool { return by == "ria" && rec.Agent == "newsletter" }
	var answered []string
	srv.Agents.Answer = func(id string, step int, approve bool, answers map[string]string, by string) error {
		answered = append(answered, id+" "+by)
		return nil
	}
	look := agent.Action{Op: "read_page", Input: map[string]any{"page": "x"}}
	waitingRun(st, "run-20261014-000000b1", "newsletter", look, "it asks first", time.Now())
	waitingRun(st, "run-20261014-000000b2", "payroll", look, "it asks first", time.Now())

	body := get(t, srv, "/approvals", tok).Body.String()
	if !strings.Contains(body, "newsletter") || strings.Contains(body, "payroll") {
		t.Errorf("ria is shown the wrong runs:\n%s", body)
	}
	if w := get(t, srv, "/agents/run/run-20261014-000000b1", tok); w.Code != 200 {
		t.Errorf("ria could not open the run she decides: %d", w.Code)
	}
	if w := get(t, srv, "/agents/run/run-20261014-000000b2", tok); w.Code == 200 {
		t.Error("ria opened another agent's run")
	}
	if w := get(t, srv, "/agents", tok); w.Code == 200 {
		t.Error("deciding one agent's runs opened the agents studio")
	}
	for _, id := range []string{"run-20261014-000000b1", "run-20261014-000000b2"} {
		studioAct(t, srv, tok, url.Values{"do": {"answer"}, "run": {id}, "step": {"2"}, "verdict": {"decline"}})
	}
	if len(answered) != 1 || answered[0] != "run-20261014-000000b1 ria" {
		t.Errorf("answered %v", answered)
	}
}
