// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/store"
)

// waitingRunWithPolicy is a run waiting for a person, in a store where dana
// and sam administer and other people hold only what each test grants.
func waitingRunWithPolicy(t *testing.T, grants ...auth.Binding) (string, string) {
	t.Helper()
	root, pol := identityStore(t)
	for _, b := range grants {
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	id, err := runAgentOnce(root, "tidy", "", false, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if rec, _ := loadAgentRun(root, id); rec.Trace.Waiting == nil {
		t.Fatalf("the run did not stop to ask: %+v", rec.Trace)
	}
	return root, id
}

// someone is a person signed in with their own token, which carries the
// role they hold: reader, for everybody these tests grant.
func someone(name string) *Caller {
	return &Caller{Name: name, Role: auth.RoleReader, Kind: audit.KindHuman, Verified: true}
}

func decideRun(root, id string, caller *Caller) error {
	rec, _ := loadAgentRun(root, id)
	_, err := continueAgentRun(context.Background(), root, id, &agent.Verdict{N: rec.Trace.Waiting.N, Approve: false}, caller)
	return err
}

// Approving follows ownership: the approve permission on the agent decides
// its runs, and nobody else's; without it, holding a role is not enough.
func TestApprovalFollowsThePermissionOnTheAgent(t *testing.T) {
	root, id := waitingRunWithPolicy(t,
		auth.Binding{Principal: "mo", Role: auth.RoleAuthor, Resource: "/"},
		auth.Binding{Principal: "ria", Role: auth.RoleReader, Resource: "/"},
		auth.Binding{Principal: "ria", Permission: auth.ActApprove, Resource: auth.AgentResource("tidy")},
		auth.Binding{Principal: "lou", Permission: auth.ActApprove, Resource: auth.AgentResource("newsletter")},
	)
	for _, who := range []string{"mo", "lou"} {
		if err := decideRun(root, id, someone(who)); err == nil || !strings.Contains(err.Error(), "approve permission") {
			t.Errorf("%s decided: %v", who, err)
		}
	}
	model := someone("ria")
	model.Kind = audit.KindAI
	if err := decideRun(root, id, model); err == nil {
		t.Error("a model decided")
	}
	items, err := waitingFor(root, someone("ria"), time.Now())
	if err != nil || len(items) != 1 || items[0].Agent != "tidy" {
		t.Fatalf("ria is shown %+v %v", items, err)
	}
	if items, _ := waitingFor(root, someone("mo"), time.Now()); len(items) != 0 {
		t.Errorf("mo is shown %+v", items)
	}
	if err := decideRun(root, id, someone("ria")); err != nil {
		t.Fatalf("ria, holding approve on tidy, could not decide: %v", err)
	}
}

// The person who answers for an agent decides what it waits for without
// any further grant, and so does whoever holds approve on the page it
// would change.
func TestTheSponsorAndThePagesApproverDecide(t *testing.T) {
	root, id := waitingRunWithPolicy(t,
		auth.Binding{Principal: "ola", Role: auth.RoleReader, Resource: "/"},
		auth.Binding{Principal: "pat", Role: auth.RoleReader, Resource: "/"},
	)
	if err := agentIdentityCmdAs(root, "sponsor", []string{"tidy", "ola"}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if err := decideRun(root, id, someone("ola")); err != nil {
		t.Fatalf("the sponsor could not decide: %v", err)
	}

	// A change to a page, waiting: decided by approve on that page.
	pol, _ := loadPolicy(root)
	pol.Grant(auth.Binding{Principal: "pat", Permission: auth.ActApprove, Resource: "/blog"})
	saveJSON(policyPath(root), pol)
	rec := agent.Record{Agent: "tidy", Trace: agent.Trace{Waiting: &agent.Pending{
		Action: agent.Action{Op: "write_page", Input: map[string]any{"page": "blog/hello"}}}}}
	if err := mayApprove(root, someone("pat"), rec); err != nil {
		t.Fatalf("approve on /blog could not decide a change to blog/hello: %v", err)
	}
	rec.Trace.Waiting.Action.Input["page"] = "about"
	if err := mayApprove(root, someone("pat"), rec); err == nil {
		t.Error("approve on /blog decided a change to another page")
	}
	rec.Trace.Waiting.Action = agent.Action{Op: "write_record", Input: map[string]any{"name": "blog"}}
	if err := mayApprove(root, someone("pat"), rec); err == nil {
		t.Error("a record's collection was taken for a page")
	}
}

// Naming who answers for an agent stays an administrator's: whoever could
// name the sponsor could name themselves, and approve what they changed.
func TestManagingAnAgentDoesNotNameItsSponsor(t *testing.T) {
	root, _ := waitingRunWithPolicy(t,
		auth.Binding{Principal: "kai", Role: auth.RoleReader, Resource: "/"},
		auth.Binding{Principal: "kai", Permission: auth.ActManageAgents, Resource: auth.AgentResource("tidy")},
	)
	if err := agentIdentityCmdAs(root, "sponsor", []string{"tidy", "kai"}, someone("kai")); err == nil {
		t.Error("managing an agent named its sponsor")
	}
	if err := manageAgent(root, someone("kai"), "tidy"); err != nil {
		t.Errorf("manage-agents on tidy did not manage tidy: %v", err)
	}
	if err := manageAgent(root, someone("kai"), "newsletter"); err == nil {
		t.Error("manage-agents on tidy managed another agent")
	}
}

// The command line asks about the agent a run is of, so a grant on that
// agent alone is enough to run it.
func TestRunningIsAskedAboutTheAgent(t *testing.T) {
	if got, ok := commandArea("agent", []string{"run", "tidy", "tidy up"}); !ok || got != "/@agents/tidy" {
		t.Errorf("%q %v", got, ok)
	}
	if got, _ := commandArea("agent", []string{"lessons", "tidy"}); got != auth.AreaAgents {
		t.Errorf("%q", got)
	}
	if n, _ := lookupNeed("agent", []string{"run"}); n.action != auth.ActRunAgents {
		t.Errorf("agent run needs %s", n.action)
	}
	if n, _ := lookupNeed("assist", nil); n.action != auth.ActUseModels {
		t.Errorf("assist needs %s", n.action)
	}
}

// Records are asked about their collection: on the command line, and for
// an agent or an app through the agent interface.
func TestRecordsAreAskedAboutTheirCollection(t *testing.T) {
	root, pol := identityStore(t)
	pol.Grant(auth.Binding{Principal: "tech", Role: auth.RoleAuthor, Resource: auth.DataResource("samples")})
	saveJSON(policyPath(root), pol)
	for _, c := range []string{"samples", "payroll"} {
		if _, err := putCheckedRecords(root, c, []map[string]any{{"name": c}}, asAdmin("dana")); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok := commandArea("records", []string{"list", "samples"}); !ok || got != "/@data/samples" {
		t.Errorf("%q %v", got, ok)
	}
	if got, _ := commandArea("records", []string{"collections"}); got != auth.AreaData {
		t.Errorf("%q", got)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	tech := &Caller{Name: "tech", Role: auth.RoleAuthor, Kind: audit.KindHuman, Verified: true}
	srv := buildMCP(root, s, tech, "templates")
	call := func(tool, op string, args map[string]any) string {
		params, _ := json.Marshal(map[string]any{"name": tool, "arguments": map[string]any{"operation": op, "arguments": args}})
		b, _ := json.Marshal(srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params}))
		return string(b)
	}
	if got := call("quilzo_read", "list_collections", map[string]any{}); !strings.Contains(got, "samples") || strings.Contains(got, "payroll") {
		t.Errorf("tech was listed %s", got)
	}
	if got := call("quilzo_read", "list_records", map[string]any{"collection": "payroll"}); !strings.Contains(got, "no binding gives tech") {
		t.Errorf("tech read payroll: %s", got)
	}
	if got := call("quilzo_write", "write_record", map[string]any{"collection": "payroll", "fields": map[string]any{"name": "x"}}); !strings.Contains(got, "no binding gives tech") {
		t.Errorf("tech wrote payroll: %s", got)
	}
	if got := call("quilzo_write", "write_record", map[string]any{"collection": "samples", "fields": map[string]any{"name": "x"}}); strings.Contains(got, "no binding") || strings.Contains(got, `"error"`) {
		t.Errorf("tech could not write samples: %s", got)
	}
}
