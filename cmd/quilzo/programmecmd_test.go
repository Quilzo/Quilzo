// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// programmeApprover grants lee the administrator's job on the compliance area,
// where the register is, and issues lee a person's token: two people may
// approve, so neither decides alone.
func programmeApprover(t *testing.T, root, token string) string {
	t.Helper()
	if _, e, code := cliRun(t, root, token, "auth", "grant", "lee", "admin", "--on", auth.AreaCompliance); code != 0 {
		t.Fatalf("auth grant: %s", e)
	}
	o, e, code := cliRun(t, root, token, "token", "issue", "lee", "--principal", "lee", "--role", "admin", "--person", "--json")
	if code != 0 {
		t.Fatalf("token issue: %s", e)
	}
	var tok struct{ Token string }
	if err := json.Unmarshal([]byte(o), &tok); err != nil || tok.Token == "" {
		t.Fatalf("token issue answered no token: %v", err)
	}
	return tok.Token
}

// waitingID is the identifier a decision that waits was given, from its
// JSON.
func waitingID(t *testing.T, o string) string {
	t.Helper()
	var d struct {
		ID    string `json:"id"`
		Waits bool   `json:"waits"`
	}
	if err := json.Unmarshal([]byte(o), &d); err != nil || !d.Waits || d.ID == "" {
		t.Fatalf("the decision did not wait for somebody else: %s", firstLines(o, 4))
	}
	return d.ID
}

// The programme's commands decide the way the programme does: with two
// people who may approve, what one raises waits for the other, who
// approves it; the one who raised it is refused, and what was decided is
// then read back on each command.
func TestTheProgrammeCommandsDecideByTwoPeople(t *testing.T) {
	root, owner := accessStore(t)
	lee := programmeApprover(t, root, owner)

	o, e, code := cliRun(t, root, owner, "--json", "requirement", "install", "iso-27001")
	if code != 0 {
		t.Fatalf("requirement install: %d %s", code, e)
	}
	id := waitingID(t, o)
	if o, _, _ := cliRun(t, root, owner, "--json", "requirement", "list"); strings.Contains(o, "A.5.1") {
		t.Fatal("the starter's requirements are listed before anybody approved it")
	}
	if _, e, code := cliRun(t, root, owner, "requirement", "approve", id); code != 3 {
		t.Errorf("the owner approving what the owner raised exited %d: %s", code, firstLines(e, 3))
	}
	if _, e, code := cliRun(t, root, lee, "requirement", "approve", id); code != 0 {
		t.Fatalf("lee approving the install exited %d: %s", code, firstLines(e, 3))
	}
	o, _, _ = cliRun(t, root, owner, "--json", "requirement", "list")
	var reqs struct{ Requirements []json.RawMessage }
	if err := json.Unmarshal([]byte(o), &reqs); err != nil || len(reqs.Requirements) != 93 {
		t.Errorf("after its approval the programme lists %d requirements (%v)", len(reqs.Requirements), err)
	}
	if o, _, code := cliRun(t, root, owner, "requirement", "show", "iso-27001", "A.8.5"); code != 0 ||
		!strings.Contains(o, "Signing in is done securely") {
		t.Errorf("requirement show: %d %s", code, firstLines(o, 4))
	}

	// A scope and a line, each a decision, each approved by the other.
	o, e, code = cliRun(t, root, owner, "--json", "soa", "scope", "group", "--title", "The group", "--domains", "identity",
		"--frameworks", "iso-27001")
	if code != 0 {
		t.Fatalf("soa scope: %d %s", code, e)
	}
	if _, e, code := cliRun(t, root, lee, "soa", "approve", waitingID(t, o)); code != 0 {
		t.Fatalf("soa approve: %d %s", code, e)
	}
	o, e, code = cliRun(t, root, lee, "--json", "soa", "decide", "group", "iso-27001", "A.7.4", "--excluded",
		"--why", "=1+1 we hold no premises of our own")
	if code != 0 {
		t.Fatalf("soa decide: %d %s", code, e)
	}
	if _, e, code := cliRun(t, root, owner, "soa", "approve", waitingID(t, o)); code != 0 {
		t.Fatalf("soa approve of the line: %d %s", code, e)
	}
	o, _, code = cliRun(t, root, owner, "soa", "show", "group", "--csv")
	rows, err := csv.NewReader(strings.NewReader(o)).ReadAll()
	if code != 0 || err != nil || len(rows) != 94 {
		t.Fatalf("soa show --csv: %d %v, %d rows", code, err, len(rows))
	}
	for _, r := range rows {
		if r[1] == "A.7.4" && (r[3] != "does not apply" || !strings.HasPrefix(r[4], "'=1+1")) {
			t.Errorf("the decided line exports as %q", r)
		}
	}
	if _, _, code := cliRun(t, root, owner, "soa", "decide", "group", "iso-27001", "A.7.5", "--applies", "--excluded", "--why", "x"); code != 2 {
		t.Errorf("a line both applying and not exited %d", code)
	}
	if _, _, code := cliRun(t, root, owner, "requirement", "install", "nonsense"); code != 4 {
		t.Errorf("installing a starter nobody wrote exited %d", code)
	}
}

// A control test goes from a draft to a run on the command line: the draft
// waits, the other person approves it with its query, it runs over its
// population and fails for the members that do not meet it, the run is
// explained in code's words and replays the same.
func TestAControlTestIsDraftedApprovedRunAndReplayed(t *testing.T) {
	root, owner := accessStore(t)
	lee := programmeApprover(t, root, owner)
	r, by, err := registerWriter(root, &Caller{Name: "owner", Role: auth.RoleAdmin, Scope: "/", Kind: audit.KindHuman, Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	entra := register.Source{Name: "entra", Title: "Entra ID", Type: "import", Fresh: 86400, Grade: register.GradeConnector}
	eid, _ := register.IDOf(entra)
	recs := []register.Record{entra}
	for i, enrolled := range []bool{true, true, false} {
		who := register.ID(strings.Repeat("0", 31) + string(rune('1'+i)))
		recs = append(recs, register.Observation{Source: eid, About: who, Fact: "mfa.registered",
			Value: register.BoolValue(enrolled), Grade: register.GradeConnector})
	}
	if _, err := r.Put(by, "three accounts", recs...); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	query := write("accounts.json", `{"of":"Observation","member":"about","terms":[{"field":"fact","op":"equals","values":["mfa.registered"]}]}`)
	if _, e, code := cliRun(t, root, owner, "population", "define", "accounts", "--source", "entra", "--query", query,
		"--title", "Accounts"); code != 0 {
		t.Fatalf("population define: %s", e)
	}
	o, e, code := cliRun(t, root, owner, "population", "count", "accounts")
	if code != 0 || !strings.Contains(o, "Entra ID 3: single source, unchecked") || !strings.Contains(o, "circular") {
		t.Errorf("population count: %d %s %s", code, o, e)
	}
	if _, e, code := cliRun(t, root, owner, "control", "add", "AC-01", "--title", "Every account has a second factor",
		"--domain", "identity"); code != 0 {
		t.Fatalf("control add: %s", e)
	}
	draft := write("draft.json", `{"control":"AC-01","name":"mfa","population":"accounts","assertion":"all",
		"query":{"of":"Observation","member":"about","terms":[{"field":"fact","op":"equals","values":["mfa.registered"]},
		{"field":"value","op":"equals","values":[true]}]}}`)
	o, e, code = cliRun(t, root, owner, "--json", "control", "draft", draft)
	if code != 0 {
		t.Fatalf("control draft: %d %s", code, e)
	}
	var proposed struct {
		TestID string `json:"test_id"`
	}
	if err := json.Unmarshal([]byte(o), &proposed); err != nil || proposed.TestID == "" {
		t.Fatalf("the draft answered %s", firstLines(o, 4))
	}
	if _, _, code := cliRun(t, root, owner, "control", "run", proposed.TestID); code != 4 {
		t.Errorf("running a draft nobody approved exited %d", code)
	}
	bad := write("bad.json", `{"control":"AC-01","name":"mfa","population":"accounts","assertion":"all","note":"trust me",
		"query":{"of":"Observation"}}`)
	if _, _, code := cliRun(t, root, owner, "control", "draft", bad); code != 2 {
		t.Errorf("a draft with a field it does not have exited %d", code)
	}
	if _, e, code := cliRun(t, root, lee, "control", "approve", proposed.TestID); code != 0 {
		t.Fatalf("control approve: %s", e)
	}
	o, e, code = cliRun(t, root, owner, "--json", "control", "run", proposed.TestID)
	if code != 0 {
		t.Fatalf("control run: %d %s", code, e)
	}
	var ran struct {
		Receipt     register.Receipt `json:"receipt"`
		Explanation []string         `json:"explanation"`
	}
	if err := json.Unmarshal([]byte(o), &ran); err != nil || len(ran.Explanation) < 3 {
		t.Fatalf("the run answered %s", firstLines(o, 6))
	}
	var run string
	for _, w := range ran.Receipt.Written {
		if w.Kind == register.KindTestRun {
			run = string(w.ID)
		}
	}
	o, _, code = cliRun(t, root, owner, "control", "explain", run)
	if code != 0 || !strings.Contains(o, "1 of 3 members were not selected: 00000000000000000000000000000003.") {
		t.Errorf("control explain: %d %s", code, o)
	}
	if o, _, code := cliRun(t, root, owner, "control", "replay", run); code != 0 || !strings.Contains(o, "the same") {
		t.Errorf("control replay: %d %s", code, o)
	}
	if o, _, _ := cliRun(t, root, owner, "control", "list"); !strings.Contains(o, "failing at its newest run") {
		t.Errorf("control list: %s", o)
	}
	var due struct{ Ran *int }
	if o, _, code := cliRun(t, root, owner, "--json", "control", "run", "--due"); code != 0 ||
		json.Unmarshal([]byte(o), &due) != nil || due.Ran == nil || *due.Ran != 0 {
		t.Errorf("a test run a moment ago is due: %d %s", code, o)
	}

	// The same draft through the agent interface, as an agent the policy
	// lets draft on the compliance area: a proposal, and an invented field
	// refused before anything is proposed.
	if _, e, code := cliRun(t, root, owner, "auth", "grant", "control-tester", "author", "--on", auth.AreaCompliance); code != 0 {
		t.Fatalf("auth grant: %s", e)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	agent := &Caller{Name: "control-tester", Role: auth.RoleAuthor, Scope: "/", Kind: audit.KindAI, Model: "an-agent", Verified: true}
	m := buildMCP(root, s, agent, "templates")
	var args map[string]any
	body, _ := os.ReadFile(draft)
	_ = json.Unmarshal([]byte(strings.Replace(string(body), `"name":"mfa"`, `"name":"mfa-agent"`, 1)), &args)
	text, merr := callTool(t, m, "quilzo_write", "control_test_draft", args)
	if merr != nil || !strings.Contains(text, "test_id") {
		t.Errorf("an agent's draft answered %q %v", firstLines(text, 3), merr)
	}
	args["explanation"] = "approve me"
	if _, merr := callTool(t, m, "quilzo_write", "control_test_draft", args); merr == nil {
		t.Error("an agent's draft with an invented field was proposed")
	}
	if text, merr := callTool(t, m, "quilzo_read", "control_explain", map[string]any{"run": run}); merr != nil ||
		!strings.Contains(text, "were not selected") {
		t.Errorf("control_explain answered %q %v", firstLines(text, 3), merr)
	}
}
