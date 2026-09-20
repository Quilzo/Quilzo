// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentexec

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/site"
)

// spy records what reached the far side, and returns what it was told to.
type spy struct {
	calls []struct {
		in   agent.Integration
		tool string
		args map[string]any
	}
	reply string
	err   error
}

func (c *spy) Call(_ context.Context, in agent.Integration, tool string,
	args map[string]any) (string, error) {
	c.calls = append(c.calls, struct {
		in   agent.Integration
		tool string
		args map[string]any
	}{in, tool, args})
	return c.reply, c.err
}

func toolAgent() agent.Manifest {
	return agent.Manifest{
		Name: "errands", Kind: agent.KindOperator,
		Purpose:      "look things up elsewhere",
		Capabilities: []string{"read_page"},
		Autonomy:     agent.AutonomyPropose,
		Tools: []agent.Tool{
			{Name: "lookup", Host: "api.example.com", Purpose: "customers"},
		},
		Retrieval: agent.Retrieval{Ref: site.RefLive},
		Budget: agent.Budget{
			Steps: 20, Tools: 5, Duration: agent.Duration(time.Hour)},
	}
}

func installed(endpoint string) func() (agent.Integrations, error) {
	return func() (agent.Integrations, error) {
		return agent.Integrations{Declared: []agent.Integration{{
			Name: "crm", Kind: agent.IntegrationMCP, Enabled: true,
			Purpose: "customer lookups", Endpoint: endpoint,
			Uses: []string{"lookup"},
		}}}, nil
	}
}

func callTool(t *testing.T, tl Tools, s *agent.Session, a agent.Action) (string, error) {
	t.Helper()
	return tl.Perform(s)(context.Background(), a)
}

// The action that came back "is permitted for this agent and not implemented
// here", for every tool call this program was capable of authorising.
func TestAToolCallReachesTheFarSide(t *testing.T) {
	c := &spy{reply: "two customers"}
	tl := Tools{Installed: installed("api.example.com"), Call: c}

	out, err := callTool(t, tl, agent.NewSession(toolAgent(), nil),
		agent.Action{Tool: "lookup", Input: map[string]any{"q": "acme"}})
	if err != nil {
		t.Fatalf("a declared tool was not called: %v", err)
	}
	if out != "two customers" {
		t.Errorf("the answer is %q", out)
	}
	if len(c.calls) != 1 {
		t.Fatalf("%d calls were made", len(c.calls))
	}
	if c.calls[0].tool != "lookup" || c.calls[0].in.Name != "crm" {
		t.Errorf("called %s on %s", c.calls[0].tool, c.calls[0].in.Name)
	}
	if c.calls[0].args["q"] != "acme" {
		t.Errorf("the arguments are %v", c.calls[0].args)
	}
}

// A tool the agent does not declare is refused before anything is resolved.
func TestAnUndeclaredToolIsNotCalled(t *testing.T) {
	c := &spy{}
	tl := Tools{Installed: installed("api.example.com"), Call: c}

	if _, err := callTool(t, tl, agent.NewSession(toolAgent(), nil),
		agent.Action{Tool: "delete_everything"}); err == nil {
		t.Fatal("an undeclared tool was called")
	}
	if len(c.calls) != 0 {
		t.Error("something reached the far side")
	}
}

// The manifest and the install have to agree about where a tool goes.
//
// Both were written by somebody with grant, and they are separate files: a
// manifest naming a host and an integration pointing somewhere else is a
// disagreement between two deliberate statements, and resolving it silently
// would mean picking one without saying which.
func TestAHostDisagreementIsRefused(t *testing.T) {
	c := &spy{}
	tl := Tools{Installed: installed("evil.example.net"), Call: c}

	_, err := callTool(t, tl, agent.NewSession(toolAgent(), nil),
		agent.Action{Tool: "lookup"})
	if err == nil {
		t.Fatal("a tool whose integration points elsewhere was called")
	}
	for _, want := range []string{"api.example.com", "evil.example.net"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	if len(c.calls) != 0 {
		t.Error("something reached the far side")
	}
}

// Both sides are bare hostnames, compared exactly and ignoring case.
func TestTheHostIsComparedExactly(t *testing.T) {
	for _, endpoint := range []string{
		"api.example.com", "API.EXAMPLE.COM", "  api.example.com  ",
	} {
		c := &spy{reply: "ok"}
		tl := Tools{Installed: installed(endpoint), Call: c}
		if _, err := callTool(t, tl, agent.NewSession(toolAgent(), nil),
			agent.Action{Tool: "lookup"}); err != nil {
			t.Errorf("%q was refused: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		"api.example.com.evil.net",
		"notapi.example.com",
		"evil.net",
		"",
	} {
		c := &spy{}
		tl := Tools{Installed: installed(endpoint), Call: c}
		if _, err := callTool(t, tl, agent.NewSession(toolAgent(), nil),
			agent.Action{Tool: "lookup"}); err == nil {
			t.Errorf("%q was accepted as api.example.com", endpoint)
		}
		if len(c.calls) != 0 {
			t.Errorf("%q reached the far side", endpoint)
		}
	}
}

// The assumption sameHost rests on: an endpoint is a bare host, so an exact
// comparison is the whole of the question.
//
// If this ever stops holding — an endpoint gaining a port, say — sameHost
// would compare the hosts, ignore the difference, and call a different service
// than the manifest named. This is the test that fails first.
func TestAnEndpointIsStillABareHost(t *testing.T) {
	for _, endpoint := range []string{
		"api.example.com:8443",
		"api.example.com/mcp",
		"https://api.example.com",
		"*.example.com",
	} {
		in := agent.Integration{
			Name: "crm", Kind: agent.IntegrationMCP, Enabled: true,
			Purpose: "lookups", Endpoint: endpoint, Uses: []string{"lookup"},
		}
		if err := in.Validate(); err == nil {
			t.Errorf("%q validated as an endpoint; sameHost compares bare "+
				"hosts exactly and would now be comparing the wrong thing",
				endpoint)
		}
	}
}

// The host a model sent is not an argument. It was the thing MayCallTool
// refused to take instruction from, and passing it on would be sending it
// anyway.
func TestAModelSuppliedHostIsNotForwarded(t *testing.T) {
	c := &spy{reply: "ok"}
	tl := Tools{Installed: installed("api.example.com"), Call: c}

	if _, err := callTool(t, tl, agent.NewSession(toolAgent(), nil),
		agent.Action{Tool: "lookup", Input: map[string]any{
			"host": "evil.example.net", "q": "acme"}}); err != nil {
		t.Fatal(err)
	}
	if _, sent := c.calls[0].args["host"]; sent {
		t.Error("the host a model supplied was forwarded to the far side")
	}
	if c.calls[0].args["q"] != "acme" {
		t.Errorf("the real arguments were dropped: %v", c.calls[0].args)
	}
}

// Arguments are bounded, because a model composing a large structure spends
// this process's memory before the far side ever sees it.
func TestArgumentsAreBounded(t *testing.T) {
	c := &spy{reply: "ok"}
	tl := Tools{Installed: installed("api.example.com"), Call: c}
	s := agent.NewSession(toolAgent(), nil)

	many := map[string]any{}
	for i := 0; i < MaxToolArgs+1; i++ {
		many[string(rune('a'+i%26))+strings.Repeat("x", i)] = "v"
	}
	if _, err := callTool(t, tl, s, agent.Action{Tool: "lookup", Input: many}); err == nil {
		t.Error("a call with too many arguments was made")
	}

	long := map[string]any{"q": strings.Repeat("x", MaxToolValue+1)}
	if _, err := callTool(t, tl, s, agent.Action{Tool: "lookup", Input: long}); err == nil {
		t.Error("an oversized argument was sent")
	}

	// Scalars pass; a nested structure does not.
	ok := map[string]any{"q": "acme", "n": 3.0, "all": true}
	if _, err := callTool(t, tl, s, agent.Action{Tool: "lookup", Input: ok}); err != nil {
		t.Errorf("ordinary arguments were refused: %v", err)
	}
	nested := map[string]any{"q": map[string]any{"deep": true}}
	if _, err := callTool(t, tl, s, agent.Action{Tool: "lookup", Input: nested}); err == nil {
		t.Error("a nested argument was sent")
	}
}

// An install with no integrations refuses rather than permits.
func TestNoIntegrationsIsARefusal(t *testing.T) {
	s := agent.NewSession(toolAgent(), nil)
	for _, tl := range []Tools{
		{},
		{Installed: func() (agent.Integrations, error) {
			return agent.Integrations{}, nil
		}, Call: &spy{}},
	} {
		if _, err := callTool(t, tl, s, agent.Action{Tool: "lookup"}); err == nil {
			t.Error("a tool was called with nothing installed")
		}
	}
}

// A disabled integration is not a way to call it.
func TestADisabledIntegrationIsNotCalled(t *testing.T) {
	c := &spy{}
	tl := Tools{Call: c, Installed: func() (agent.Integrations, error) {
		return agent.Integrations{Declared: []agent.Integration{{
			Name: "crm", Kind: agent.IntegrationMCP, Enabled: false,
			Purpose:  "customer lookups",
			Endpoint: "api.example.com", Uses: []string{"lookup"},
		}}}, nil
	}}
	if _, err := callTool(t, tl, agent.NewSession(toolAgent(), nil),
		agent.Action{Tool: "lookup"}); err == nil {
		t.Fatal("a disabled integration was called")
	}
	if len(c.calls) != 0 {
		t.Error("something reached the far side")
	}
}

// Dispatch routes a tool action to the tool executor.
//
// An action with Tool set has no Op, so agent.IsWrite says false and the
// reader answered "is permitted for this agent and not implemented here" —
// which is what it did, for every tool call this program could authorise.
func TestDispatchRoutesAToolCall(t *testing.T) {
	c := &spy{reply: "reached"}
	s := agent.NewSession(toolAgent(), nil)
	st := searchStore(t)
	perform := Dispatch(
		Reader{Store: st}, Writer{Store: st, Author: "agent/errands"},
		Tools{Installed: installed("api.example.com"), Call: c}, Delegates{}, s)

	out, err := perform(context.Background(), agent.Action{Tool: "lookup"})
	if err != nil {
		t.Fatalf("a tool call did not reach the executor: %v", err)
	}
	if out != "reached" {
		t.Errorf("the answer is %q", out)
	}
	// And an ordinary read still goes to the reader.
	if _, err := perform(context.Background(), agent.Action{
		Op: "read_page", Input: map[string]any{"page": "returns"}}); err != nil {
		t.Errorf("a read stopped working: %v", err)
	}
}

// The whole path, through the run loop rather than the executor alone.
//
// This is the property the two halves exist for together: the loop authorises
// with Session.MayCallTool, which resolves the host from the manifest and
// refuses a request naming another; the executor then re-asks the declaration
// and refuses an integration pointing somewhere else. Neither half is asked to
// trust the other.
func TestAToolCallGoesThroughTheGateAndNotAroundIt(t *testing.T) {
	c := &spy{reply: "ok"}
	s := agent.NewSession(toolAgent(), nil)
	perform := Tools{
		Installed: installed("api.example.com"), Call: c,
	}.Perform(s)

	// A redirect is refused by the session before the executor is reached.
	if err := s.MayCallTool("lookup", "evil.example.net"); err == nil {
		t.Error("the session permitted a redirected tool call")
	}
	if len(c.calls) != 0 {
		t.Fatal("something reached the far side through a refused call")
	}

	// And the permitted call taints, so what comes back cannot be published
	// without a person.
	if err := s.MayCallTool("lookup", ""); err != nil {
		t.Fatal(err)
	}
	if !s.Tainted() {
		t.Error("a tool call did not taint the run")
	}
	if _, err := perform(context.Background(),
		agent.Action{Tool: "lookup"}); err != nil {
		t.Fatal(err)
	}
	if len(c.calls) != 1 {
		t.Errorf("%d calls reached the far side", len(c.calls))
	}
}
