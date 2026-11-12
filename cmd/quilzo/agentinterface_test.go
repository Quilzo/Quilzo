// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agentwatch"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/store"
)

func callOp(t *testing.T, srv *mcp.Server, tool, op string) *mcp.Response {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": map[string]any{"operation": op}})
	return srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params})
}

// The agent interface over HTTP serves no store that has no access policy:
// the command line treats "nothing granted" as "nothing to enforce", which
// is right for a person at their own machine and wrong for a door anybody
// on the network can knock on.
func TestTheRemoteInterfaceNeedsAPolicy(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	tok := auth.Token{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}
	resp := callOp(t, buildMCP(root, s, remoteCaller(tok), "templates"), "quilzo_read", "list_pages")
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "access policy") {
		t.Fatalf("served a store with no policy: %+v", resp)
	}
	// The same caller on the command line is let through, as before.
	resp = callOp(t, buildMCP(root, s, &Caller{Name: "dana", Kind: audit.KindHuman}, "templates"), "quilzo_read", "list_pages")
	if resp.Error != nil && strings.Contains(resp.Error.Message, "access policy") {
		t.Fatalf("the command line was held to the remote rule: %+v", resp.Error)
	}
}

// An app given too small a scope is told which scope would reach the
// operation; a plain token too small is simply refused.
func TestAnAppIsToldTheScopeItNeeds(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	pol.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"})
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	err := remoteRefusal(root, remoteCaller(auth.Token{Principal: "dana", Role: auth.RoleReader, Grant: "gr_1"}), auth.RoleAuthor)
	var se *mcp.ScopeError
	if !errors.As(err, &se) || se.Scope != "mcp:write" {
		t.Fatalf("an app: %v", err)
	}
	if err := remoteRefusal(root, remoteCaller(auth.Token{Principal: "dana", Role: auth.RoleReader}), auth.RoleAuthor); err != nil {
		t.Fatalf("a plain token is refused by the ordinary checks, not asked to widen: %v", err)
	}
	if err := remoteRefusal(root, remoteCaller(auth.Token{Principal: "dana", Role: auth.RoleAdmin, Grant: "gr_1"}), auth.RoleAuthor); err != nil {
		t.Fatalf("enough scope: %v", err)
	}
	c := remoteCaller(auth.Token{Principal: "dana", Role: auth.RoleReader, Grant: "gr_1", Scope: auth.Scope{ReadOnly: true}})
	if !c.Remote || c.Kind != audit.KindAI || !c.Verified || !c.Limits.ReadOnly {
		t.Fatalf("%+v", c)
	}
}

// Each call at the interface is the app's record, for the person, with the
// connection it came through: what agentwatch counts, what an
// administrator suspends, and what a receipt is of.
func TestAnAppsCallIsRecordedWithItsConnection(t *testing.T) {
	tok := auth.Token{Principal: "dana", Grant: "gr_00000000000000aa", Client: "https://app.example.com/meta"}
	c := &mcp.Caller{Principal: "dana", Client: tok.Client, Data: tok}
	r := appCallRecord(c, "tools/call", "publish", &mcp.Error{Code: mcp.CodeRefused, Message: "needs approval"})
	if r.Action != "mcp.call" || r.Principal != "app:"+tok.Client || r.Model != tok.Client || r.Kind != audit.KindAI ||
		r.Outcome != audit.Denied || r.Detail["grant"] != tok.Grant || r.Detail["on_behalf_of"] != "dana" ||
		r.Detail["error"] != "needs approval" || r.Detail["operation"] != "publish" {
		t.Fatalf("%+v", r)
	}
	if r := appCallRecord(c, "tools/call", "", &mcp.Error{Code: -32603, Message: "broke"}); r.Outcome != audit.Failure {
		t.Errorf("a failure recorded as %s", r.Outcome)
	}
	// Quilzo's own token: no connection, and no app to name. The person's
	// client, recorded under the person.
	own := appCallRecord(&mcp.Caller{Principal: "dana", Data: auth.Token{Principal: "dana"}}, "tools/list", "", nil)
	if _, has := own.Detail["grant"]; has || own.Principal != "dana" || own.Model != "mcp-client" ||
		own.Kind != audit.KindAI || own.Outcome != audit.Success {
		t.Errorf("%+v", own)
	}
	for k := range r.Detail {
		if why := audit.ForbiddenKey(k); why != "" {
			t.Error(why)
		}
	}
}

// Each person's client is an agent of its own. Every call made with a
// person's own token was recorded as one principal, mcp-client, so thirteen
// people's clients each finding out once what they might do were one agent
// to the agent watch, with hundreds of "the same request has now been
// refused" strikes, and the shield case it opened named nobody.
func TestEachPersonsClientIsAnAgentOfItsOwn(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	people := []string{"ana", "bo", "cy", "dana", "eli", "fay", "gus", "hal", "ivy", "jo", "kai", "lee", "mo"}
	for i, who := range people {
		tok := auth.Token{ID: fmt.Sprintf("tok%02d", i), Principal: who}
		c := &mcp.Caller{Principal: who, Data: tok}
		for _, op := range []string{"verify_store", "inventory", "policy_status", "agent_activity", "site_report"} {
			record(root, appCallRecord(c, "quilzo_read", op,
				&mcp.Error{Code: mcp.CodeRefused, Message: who + " is author on /; grant needs admin"}))
		}
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	reports := agentwatch.Look(events, time.Now())
	if len(reports) != len(people) {
		t.Fatalf("%d people's clients were seen as %d agent(s)", len(people), len(reports))
	}
	for _, r := range reports {
		if r.Actions != 5 || r.Counts[agentwatch.RepeatedRefusal] != 0 {
			t.Errorf("%s: %d actions, %v", r.Principal, r.Actions, r.Counts)
		}
		// The case names the client and whose it is.
		if s := r.Subject(); !strings.HasPrefix(s, "mcp-client for ") {
			t.Errorf("subject %q", s)
		}
	}
	// And the record says which of the person's tokens it was.
	r := appCallRecord(&mcp.Caller{Principal: "dana", Data: auth.Token{ID: "tok03", Principal: "dana"}}, "quilzo_read", "list_pages", nil)
	if r.Principal != "dana" || r.Kind != audit.KindAI || r.Model != "mcp-client" ||
		r.Detail["credential"] != "tok03" || r.Detail["on_behalf_of"] != "dana" {
		t.Errorf("%+v", r)
	}
	s := appCallRecord(&mcp.Caller{Principal: "dana", Data: auth.Token{ID: "s1", Parent: "tok03", Principal: "dana"}}, "quilzo_read", "", nil)
	if s.Detail["credential"] != "tok03" {
		t.Errorf("a session is named by the token it was exchanged from: %+v", s.Detail)
	}
}
