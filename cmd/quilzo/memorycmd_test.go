// SPDX-FileCopyrightText: 2026 rsh1k
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
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/memory"
)

// programCallsMain makes the calls it is given, through its run, and
// prints what each returned, one per line.
func programCallsMain(spec string) {
	var calls []struct {
		Tool string         `json:"tool"`
		Op   string         `json:"op"`
		Args map[string]any `json:"args"`
	}
	_ = json.Unmarshal([]byte(spec), &calls)
	url, tok := os.Getenv("QUILZO_MCP_URL"), os.Getenv("QUILZO_RUN_TOKEN")
	for i, c := range calls {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": i + 1, "method": "tools/call",
			"params": map[string]any{"name": c.Tool, "arguments": map[string]any{"operation": c.Op, "arguments": c.Args},
				"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}})
		req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
		for k, v := range map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json",
			"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28",
			"Mcp-Method": "tools/call", "Mcp-Name": c.Tool} {
			req.Header.Set(k, v)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Printf("%s: error %v\n", c.Op, err)
			continue
		}
		b, _ := io.ReadAll(res.Body)
		var r struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
			} `json:"result"`
			Error *struct{ Message string } `json:"error"`
		}
		_ = json.Unmarshal(b, &r)
		switch {
		case r.Error != nil:
			fmt.Printf("%s: refused %s\n", c.Op, strings.ReplaceAll(r.Error.Message, "\n", " "))
		case len(r.Result.Content) > 0:
			fmt.Printf("%s: %s\n", c.Op, strings.ReplaceAll(strings.TrimSpace(r.Result.Content[0].Text), "\n", " | "))
		}
	}
}

func rememberingAgent(t *testing.T, calls string) (string, *Caller, *Caller) {
	t.Helper()
	root, _ := identityStore(t) // dana and sam both administer
	n := agentbox.Native{Exe: os.Args[0], Init: []string{"agentbox-init"}, Shim: []string{"agentbox-shim"}}
	if a := n.Check(); !a.OK {
		t.Skip("no box here: " + a.Why)
	}
	testBackend = n
	t.Cleanup(func() { testBackend = nil })
	m := agent.Manifest{Name: "helper", Kind: agent.KindTask, Purpose: "help people",
		Capabilities: []string{"list_pages", "remember", "recall"}, Autonomy: agent.AutonomyDraft,
		Memory:  agent.Memory{Semantic: true, Retain: agent.Duration(30 * 24 * time.Hour)},
		Tools:   []agent.Tool{{Name: "lookup", Host: "api.example.com", Purpose: "look things up"}},
		Budget:  agent.Budget{Steps: 10, Tools: 2, Duration: agent.Duration(time.Minute)},
		Program: &agent.Program{Command: []string{os.Args[0], "agentbox-program-calls", calls}}}
	if err := declareAgent(root, m, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	return root, asAdmin("dana"), asAdmin("sam")
}

func setCalls(t *testing.T, root, calls string) {
	t.Helper()
	set, _ := loadAgents(root)
	m := set.Agents["helper"]
	m.Program.Command[2] = calls
	if err := declareAgent(root, m, false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
}

func TestAnAgentRemembersForThePersonAndOnlyOnceAPersonConfirms(t *testing.T) {
	root, dana, sam := rememberingAgent(t,
		`[{"tool":"quilzo_write","op":"remember","args":{"text":"Dana prefers replies in Spanish"}},
		  {"tool":"quilzo_read","op":"recall","args":{}}]`)
	_, out, err := runAgentKeptBy(context.Background(), root, "helper", "remember my language", false, true, dana)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.ProgramErr)
	}
	// A program's run is somebody else's words from the start, so what it
	// learnt waits for a person, and is not recalled yet.
	if !strings.Contains(out.Trace.Answer, "remember: remembered as m_") || !strings.Contains(out.Trace.Answer, "held") ||
		!strings.Contains(out.Trace.Answer, "recall: nothing is remembered") {
		t.Fatalf("the program saw %q", out.Trace.Answer)
	}
	held, _ := memoryStore(root).List(memory.Filter{Held: true})
	if len(held) != 1 || held[0].About != "dana" || held[0].Agent != "helper" || !strings.Contains(held[0].Sources, "decided by the program") {
		t.Fatalf("held %+v", held)
	}
	if _, err := memoryStore(root).Confirm(held[0].ID, "dana", time.Now(), 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}

	// Now dana's runs recall it, and holding it, the run sends nothing out.
	setCalls(t, root, `[{"tool":"quilzo_read","op":"recall","args":{"query":"spanish replies"}},
		{"tool":"quilzo_write","op":"tool:lookup","args":{}}]`)
	_, out, err = runAgentKeptBy(context.Background(), root, "helper", "reply to me", false, true, dana)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Trace.Answer, "Dana prefers replies in Spanish") {
		t.Fatalf("dana's run recalled %q", out.Trace.Answer)
	}
	if !strings.Contains(out.Trace.Answer, "lookup: refused") || !strings.Contains(out.Trace.Answer, "remembers about dana") {
		t.Fatalf("a run holding dana's memory sent it out: %q", out.Trace.Answer)
	}
	if rc := out.Receipt; len(rc.Private) == 0 || !strings.Contains(strings.Join(rc.Private, ","), "remembers about dana") {
		t.Fatalf("the receipt does not say it held dana's memory: %v", rc.Private)
	}

	// Sam's run of the same agent recalls nothing of dana.
	setCalls(t, root, `[{"tool":"quilzo_read","op":"recall","args":{}}]`)
	_, out, _ = runAgentKeptBy(context.Background(), root, "helper", "reply to me", false, true, sam)
	if strings.Contains(out.Trace.Answer, "Spanish") || !strings.Contains(out.Trace.Answer, "nothing is remembered") {
		t.Fatalf("sam's run recalled %q", out.Trace.Answer)
	}

	// Dana has every agent forget her.
	if n, err := forgetPerson(root, "dana", "dana"); err != nil || n != 1 {
		t.Fatalf("forgot %d: %v", n, err)
	}
	if left, _ := memoryStore(root).List(memory.Filter{About: "dana"}); len(left) != 0 {
		t.Fatal("dana is still remembered")
	}
}

// Withdrawn, an agent's memory goes with it.
func TestAWithdrawnAgentRemembersNothing(t *testing.T) {
	root, dana, _ := rememberingAgent(t, `[]`)
	if _, err := memoryStore(root).Remember(memory.Entry{Agent: "helper", About: "dana", Kind: memory.Semantic,
		Text: "x", Run: "r", By: "dana"}, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := withdrawAgent(root, "helper", dana); err != nil {
		t.Fatal(err)
	}
	if left, _ := memoryStore(root).List(memory.Filter{}); len(left) != 0 {
		t.Fatal("a withdrawn agent's memory was kept")
	}
}

// A procedure is the agent's own, recalled for everybody, about nobody.
func TestAProcedureIsAboutNobody(t *testing.T) {
	root := t.TempDir()
	m := agent.Manifest{Name: "helper", Memory: agent.Memory{Procedural: true, Semantic: true, Retain: agent.Duration(time.Hour)}}
	mem := runMemory(root, m, asAdmin("dana"), "run-1")
	p, err := mem.Remember(memory.Procedural, "refunds over 100 go to finance", false, "")
	if err != nil || p.About != "" {
		t.Fatalf("%+v %v", p, err)
	}
	f, err := mem.Remember(memory.Semantic, "Dana prefers Spanish", false, "")
	if err != nil || f.About != "dana" || f.Run != "run-1" || f.By != "dana" {
		t.Fatalf("%+v %v", f, err)
	}
	sams := runMemory(root, m, asAdmin("sam"), "run-2")
	got, _ := sams.Recall("", map[string]bool{memory.Procedural: true, memory.Semantic: true})
	if len(got) != 1 || got[0].Kind != memory.Procedural {
		t.Fatalf("sam recalled %+v", got)
	}
}
