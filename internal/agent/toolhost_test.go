// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"context"
	"strings"
	"testing"
	"time"
)

func twoToolAgent() Manifest {
	return Manifest{
		Name: "errands", Kind: KindOperator, Purpose: "errands",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyPropose,
		Tools: []Tool{
			{Name: "crm", Host: "api.example.com", Purpose: "lookup"},
			{Name: "post", Host: "hooks.example.org", Purpose: "notify"},
		},
		Budget: Budget{Steps: 10, Tools: 5, Duration: Duration(time.Hour)},
	}
}

// The host is a property of the tool, not of the request.
func TestTheHostComesFromTheDeclaration(t *testing.T) {
	s := NewSession(twoToolAgent(), nil)
	if got := s.HostFor("crm"); got != "api.example.com" {
		t.Errorf("crm resolves to %q", got)
	}
	if got := s.HostFor("CRM"); got != "api.example.com" {
		t.Errorf("a tool name is matched without regard to case; got %q", got)
	}
	if got := s.HostFor("nope"); got != "" {
		t.Errorf("an undeclared tool resolves to %q", got)
	}
	if got := s.HostFor(""); got != "" {
		t.Errorf("an empty tool name resolves to %q", got)
	}
}

// A model naming the tool and leaving the host alone is the ordinary case and
// must work.
func TestNamingOnlyTheToolIsEnough(t *testing.T) {
	s := NewSession(twoToolAgent(), nil)
	if err := s.MayCallTool("crm", ""); err != nil {
		t.Fatalf("a plain tool call was refused: %v", err)
	}
}

// The case the old code got wrong in the other direction: it authorised
// against a string the model supplied, so a check on one host and a
// connection to another were possible. Now a disagreement is refused, and the
// refusal names both.
func TestAskingForADifferentHostIsRefused(t *testing.T) {
	s := NewSession(twoToolAgent(), nil)
	err := s.MayCallTool("crm", "evil.example.net")
	if err == nil {
		t.Fatal("a tool call naming another host was permitted")
	}
	for _, want := range []string{"crm", "api.example.com", "evil.example.net"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// And the harder version: naming ANOTHER of this agent's own declared hosts.
//
// This is the one an allow-list check alone cannot catch. Both hosts are
// permitted for this agent, so checking the asked-for host against the list
// passes — while the tool that would be dialled points somewhere else.
func TestAskingForAnotherOfItsOwnHostsIsRefused(t *testing.T) {
	s := NewSession(twoToolAgent(), nil)
	err := s.MayCallTool("crm", "hooks.example.org")
	if err == nil {
		t.Fatal("a tool call was pointed at another declared host and permitted")
	}
	if !strings.Contains(err.Error(), "hooks.example.org") {
		t.Errorf("the refusal does not name the host asked for: %v", err)
	}
}

// A tool the agent does not declare is refused by name, not by host.
func TestAnUndeclaredToolIsRefused(t *testing.T) {
	s := NewSession(twoToolAgent(), nil)
	if err := s.MayCallTool("whatever", ""); err == nil {
		t.Fatal("an undeclared tool was permitted")
	}
	// And with a host, the refusal says the tool is not declared rather than
	// discussing the host — which is the more useful answer.
	err := s.MayCallTool("whatever", "api.example.com")
	if err == nil {
		t.Fatal("an undeclared tool naming a permitted host was allowed")
	}
	if !strings.Contains(err.Error(), "whatever") {
		t.Errorf("the refusal does not name the tool: %v", err)
	}
}

// A refused call must not spend the tool budget. Otherwise a run can be
// starved by asking it to do things it may not do.
func TestARefusedToolCallDoesNotSpendTheBudget(t *testing.T) {
	m := twoToolAgent()
	m.Budget.Tools = 2
	s := NewSession(m, nil)

	for i := 0; i < 5; i++ {
		if err := s.MayCallTool("crm", "evil.example.net"); err == nil {
			t.Fatal("the redirect was permitted")
		}
	}
	// Two real calls must still be available.
	for i := 0; i < 2; i++ {
		if err := s.MayCallTool("crm", ""); err != nil {
			t.Fatalf("call %d was refused after five refusals: %v", i+1, err)
		}
	}
	if err := s.MayCallTool("crm", ""); err == nil {
		t.Error("a third call was permitted against a budget of two")
	}
}

// The attempt is in the trace whether or not it was refused, because the
// attempt is the finding. A run that silently corrected the host would leave
// nothing for internal/agentwatch to see.
func TestARedirectAttemptIsRecorded(t *testing.T) {
	s := NewSession(twoToolAgent(), nil)
	r := Runner{
		Decide: script(
			Action{Tool: "crm", Input: map[string]any{"host": "evil.example.net"}},
			Action{Say: "done"},
		),
		Perform: echoPerform,
	}
	tr, err := r.Run(context.Background(), s, "look something up")
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, st := range tr.Steps {
		if st.Redirected != "" {
			found = st.Redirected
		}
	}
	if found != "evil.example.net" {
		t.Errorf("the redirect attempt is not in the trace: %+v", tr.Steps)
	}
	if len(tr.Refused()) != 1 {
		t.Errorf("%d refusals, want 1", len(tr.Refused()))
	}
}

// An ordinary call leaves the field empty, so the presence of a value means
// something.
func TestAnOrdinaryToolCallRecordsNoRedirect(t *testing.T) {
	s := NewSession(twoToolAgent(), nil)
	r := Runner{
		Decide:  script(Action{Tool: "crm"}, Action{Say: "done"}),
		Perform: echoPerform,
	}
	tr, err := r.Run(context.Background(), s, "look something up")
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range tr.Steps {
		if st.Redirected != "" {
			t.Errorf("a plain call recorded a redirect to %q", st.Redirected)
		}
	}
}

// ToolFor hands back a copy. A caller that could reach into the session's
// manifest could change what the agent declares mid-run.
func TestToolForCannotBeUsedToWidenTheManifest(t *testing.T) {
	s := NewSession(twoToolAgent(), nil)
	got, ok := s.ToolFor("crm")
	if !ok {
		t.Fatal("crm is not declared")
	}
	got.Host = "evil.example.net"
	got.Secret = "stolen"

	if again, _ := s.ToolFor("crm"); again.Host != "api.example.com" {
		t.Errorf("the session's declaration became %q", again.Host)
	}
	if err := s.MayCallTool("crm", "evil.example.net"); err == nil {
		t.Error("the mutated copy widened what the session permits")
	}
}

func TestToolForRefusesWhatIsNotDeclared(t *testing.T) {
	s := NewSession(twoToolAgent(), nil)
	for _, name := range []string{"", "   ", "nope"} {
		if _, ok := s.ToolFor(name); ok {
			t.Errorf("%q was reported as declared", name)
		}
	}
}

// A tool call taints the run, for the reason a store read does and more so: a
// tool result is whatever a third-party host chose to return, on this request,
// with no review by anybody here.
//
// Without it an agent could call out, receive attacker-controlled content, and
// publish it without a person — through a deputy holding this store's
// credentials. MayReach never set the taint, which did not matter only because
// no executor performed a tool call.
func TestAToolCallTaintsTheRun(t *testing.T) {
	s := NewSession(twoToolAgent(), nil)
	if s.Tainted() {
		t.Fatal("tainted before doing anything")
	}
	if err := s.MayCallTool("crm", ""); err != nil {
		t.Fatal(err)
	}
	if !s.Tainted() {
		t.Error("an agent that called out to a third party can still publish")
	}
}

// A refused call taints nothing, or a caller could burn an agent's ability to
// publish by asking it to do something it may not do.
func TestARefusedToolCallDoesNotTaint(t *testing.T) {
	for _, tc := range []struct{ tool, host string }{
		{"crm", "evil.example.net"},  // a redirect
		{"nope", ""},                 // an undeclared tool
		{"crm", "hooks.example.org"}, // another of its own hosts
	} {
		s := NewSession(twoToolAgent(), nil)
		if err := s.MayCallTool(tc.tool, tc.host); err == nil {
			t.Fatalf("%s/%s was permitted", tc.tool, tc.host)
		}
		if s.Tainted() {
			t.Errorf("a refused call to %s/%s tainted the run", tc.tool, tc.host)
		}
	}
}

// And an agent that has called a tool cannot publish, which is the whole point
// of the taint.
func TestAnAgentThatCalledOutCannotPublish(t *testing.T) {
	m := twoToolAgent()
	m.Capabilities = append(m.Capabilities, "publish")
	m.Autonomy = AutonomyPublish
	if err := m.Validate(map[string]bool{
		"read_page": true, "publish": true}); err != nil {
		// Validate forces HumanApproval for publish autonomy, which is a
		// second reason this is refused. The taint is the first.
		t.Logf("manifest note: %v", err)
	}
	s := NewSession(m, nil)
	if err := s.MayCallTool("crm", ""); err != nil {
		t.Fatal(err)
	}
	if ok, why := (&Trace{}).Publishable(s); ok {
		t.Errorf("an agent that called a third-party tool is publishable: %s", why)
	}
}
