// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// callCounter counts the tool calls that reach a tool server.
type callCounter struct {
	h     http.Handler
	calls int
}

func (c *callCounter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	if bytes.Contains(b, []byte(`"tools/call"`)) {
		c.calls++
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	c.h.ServeHTTP(w, r)
}

// filingStore is a store whose tracker files issues, pinned, and an agent
// called filer that may call create_issue there and asks nobody first.
func filingStore(t *testing.T, autonomy agent.Autonomy, label, integration bool) (string, *callCounter) {
	t.Helper()
	root, _ := identityStore(t)
	far := &callCounter{h: &tracker{description: "File an issue."}}
	mcpTransport = viaHandler(far)
	t.Cleanup(func() { mcpTransport = nil })
	set := agent.Integrations{Declared: []agent.Integration{{Name: "tracker", Kind: agent.IntegrationMCP, Enabled: true,
		Purpose: "file issues", Endpoint: "tracker.example", Uses: []string{"create_issue"}, Writes: integration}}}
	if err := saveJSON(integrationsPath(root), set); err != nil {
		t.Fatal(err)
	}
	if err := integrationsPin(root, []string{"tracker"}); err != nil {
		t.Fatal(err)
	}
	m := agent.Manifest{Name: "filer", Kind: agent.KindTask, Purpose: "File what the pages are missing",
		Capabilities: []string{"list_pages"}, Autonomy: autonomy,
		Tools:  []agent.Tool{{Name: "create_issue", Host: "tracker.example", Purpose: "file it", Writes: label}},
		Budget: agent.Budget{Steps: 6, Tools: 3, Duration: agent.Duration(time.Minute)}}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	return root, far
}

// A tool that writes is not called, at propose autonomy, without a person.
//
// Propose writes nothing: the CMS's writes are refused at it, and the
// browser and the workspace read only. A tool declared as changing
// something on the far side was gated on its host, the budget and the
// breaker alone, so a propose-only agent that read a planted instruction
// in a tool's answer called the destructive tool beside it with nobody
// asked. That is also every run a reader starts, or a read-only token, and
// every run of an agent its evaluations put back to proposing, because
// each of those runs at propose. Either declaration saying the tool writes
// is enough, as it is for whose approval counts.
func TestAWritingToolWaitsForAPersonAtProposeAutonomy(t *testing.T) {
	reader := &Caller{Name: "rae", Role: auth.RoleReader, Kind: audit.KindHuman, Verified: true}
	for _, c := range []struct {
		name               string
		autonomy           agent.Autonomy
		label, integration bool
		by                 *Caller
	}{
		{"declared propose, the manifest says it writes", agent.AutonomyPropose, true, false, asAdmin("dana")},
		{"declared propose, the integration says it writes", agent.AutonomyPropose, false, true, asAdmin("dana")},
		{"declared draft, started by a reader", agent.AutonomyDraft, true, false, reader},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, far := filingStore(t, c.autonomy, c.label, c.integration)
			id, err := runAgentOnce(root, "filer", "", false, c.by)
			if err != nil {
				t.Fatal(err)
			}
			if far.calls != 0 {
				t.Fatalf("the writing tool was called %d time(s) with nobody asked", far.calls)
			}
			rec, err := loadAgentRun(root, id)
			if err != nil {
				t.Fatal(err)
			}
			if w := rec.Trace.Waiting; w == nil || w.Action.Tool != "create_issue" {
				t.Fatalf("the run is not waiting for a person on the tool: %+v", rec.Trace.Waiting)
			}
		})
	}
	// Draft is the autonomy that writes on its own, as write_page does at
	// it, and its tools go ahead as they did.
	root, far := filingStore(t, agent.AutonomyDraft, true, false)
	if _, err := runAgentOnce(root, "filer", "", false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if far.calls != 1 {
		t.Fatalf("a draft agent's writing tool was called %d times", far.calls)
	}
}

// A tool that writes waits for a person, too, for an agent declared to have
// one agree before anything it did is public.
//
// A draft agent with human_approval called the integration's writing tool
// with nobody asked: its pages waited for that person as drafts, and what
// it did on the far side, which has no draft, did not.
func TestAWritingToolWaitsForThePersonTheAgentDeclares(t *testing.T) {
	root, far := filingStore(t, agent.AutonomyDraft, false, true)
	set, err := loadAgents(root)
	if err != nil {
		t.Fatal(err)
	}
	m := set.Agents["filer"]
	m.HumanApproval = true
	if err := declareAgent(root, m, false, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, err := runAgentOnce(root, "filer", "", false, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if far.calls != 0 {
		t.Fatalf("the writing tool was called %d time(s) with nobody asked", far.calls)
	}
	rec, err := loadAgentRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if w := rec.Trace.Waiting; w == nil || w.Action.Tool != "create_issue" {
		t.Fatalf("the run is not waiting for a person on the tool: %+v", rec.Trace.Waiting)
	}
}
