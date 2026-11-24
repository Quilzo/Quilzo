// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/fetch"
)

func integration(uses ...string) agent.Integration {
	return agent.Integration{
		Name: "tracker", Kind: agent.IntegrationMCP, Enabled: true,
		Purpose: "file issues", Endpoint: "tracker.example", Uses: uses,
	}
}

// The allow-list is the whole control, and it refuses a tool the server offers.
//
// Tool poisoning is a server adding or redefining a tool after the day somebody
// decided to trust it. A client that calls whatever is advertised has handed
// its capability list to a third party's next release.
func TestAToolTheServerOffersIsNotTherebyAToolThisMayCall(t *testing.T) {
	c := &Client{}
	err := c.permits(integration("create_issue"), "delete_project")
	if err == nil {
		t.Fatal("a tool outside the agreed list was permitted")
	}
	// The refusal names the agreed set, because the operator reading it is
	// deciding whether to add the tool.
	for _, want := range []string{"delete_project", "create_issue", "tracker"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
	if err := c.permits(integration("create_issue"), "create_issue"); err != nil {
		t.Errorf("an agreed tool was refused: %v", err)
	}
}

// A declared-but-disabled integration is off, and so is one of a kind
// nothing calls.
func TestOnlyEnabledMCPIntegrationsAreCallable(t *testing.T) {
	c := &Client{}
	off := integration("create_issue")
	off.Enabled = false
	if err := c.permits(off, "create_issue"); err == nil {
		t.Error("a declared integration nobody enabled was callable")
	}
	wrong := integration("create_issue")
	wrong.Kind = agent.IntegrationProcess
	if err := c.permits(wrong, "create_issue"); err == nil {
		t.Error("a process integration was called")
	}
}

// Tools marks what may be called and does not filter.
//
// The difference between what a server advertises and what this install agreed
// to is the thing worth looking at: a list that quietly drops the tool that
// appeared last week is a list that hides tool poisoning rather than surfacing
// it.
func TestToolsShowsWhatIsOfferedAndWhatWasAgreed(t *testing.T) {
	got := markAllowed([]Tool{
		{Name: "create_issue"},
		{Name: "delete_project"}, // appeared since somebody agreed
	}, []string{"create_issue"})

	if len(got) != 2 {
		t.Fatalf("the listing dropped a tool, so an operator cannot see what "+
			"the server has started offering: %+v", got)
	}
	if !got[0].Allowed {
		t.Error("an agreed tool is not marked as agreed")
	}
	if got[1].Allowed {
		t.Error("a tool that appeared since is marked as agreed")
	}
}

// The endpoint is reached over https, and the transport refuses anything else.
//
// Asserted here rather than assumed: Integration.Validate refuses a URL, so
// the scheme is this package's to choose, and an MCP call carries a credential
// and whatever the tool was given.
func TestTheEndpointIsReachedOverHTTPSOnly(t *testing.T) {
	if _, err := fetch.ValidateURL("http://tracker.example"); err == nil {
		t.Error("the transport accepts plain http, so the scheme this package " +
			"chooses is the only thing keeping a bearer token off the wire")
	}
	if _, err := fetch.ValidateURL("https://tracker.example"); err != nil {
		t.Errorf("https was refused, so nothing here can call anything: %v", err)
	}
}

// An integration naming a secret with no vault is refused, not called anonymously.
func TestASecretWithNoVaultIsRefusedRatherThanCalledAnonymously(t *testing.T) {
	in := integration("create_issue")
	in.Secret = "tracker-token"
	c := &Client{} // no Secrets
	_, err := c.Call(context.Background(), in, "create_issue", nil)
	if err == nil {
		t.Fatal("an authenticated integration was called with no credential")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("the refusal does not explain why calling anonymously is "+
			"worse than refusing: %v", err)
	}
}

// A tool result is rendered as text, and only from parts that are text.
//
// The non-text part here carries a "text" field of its own, because servers do
// put captions there — and that is what makes the type check load-bearing
// rather than decorative. An earlier version of this test used a part with no
// text at all, so removing the type check changed nothing and the sabotage
// passed.
func TestOnlyTextPartsOfAResultAreRead(t *testing.T) {
	got, _ := renderContent(json.RawMessage(`{"content":[
		{"type":"text","text":"opened #41"},
		{"type":"image","data":"AAAA","text":"a screenshot of the tracker"},
		{"type":"resource","text":"file:///etc/passwd"},
		{"type":"text","text":"assigned to nobody"}]}`))

	for _, want := range []string{"opened #41", "assigned to nobody"} {
		if !strings.Contains(got, want) {
			t.Errorf("a text part was lost: %q", got)
		}
	}
	if strings.Contains(got, "AAAA") {
		t.Error("a binary payload was handed to the model as if it were an answer")
	}
	// The caption on a non-text part is not the tool's answer. Reading it
	// means a server can put whatever it likes in front of the model under a
	// part type this does not otherwise render.
	if strings.Contains(got, "a screenshot") {
		t.Error("the caption on an image part was rendered as tool output")
	}
	if strings.Contains(got, "/etc/passwd") {
		t.Error("a resource part was rendered as tool output")
	}
}

// An error result says so rather than reading as a successful answer.
func TestAToolErrorIsNotRenderedAsASuccessfulAnswer(t *testing.T) {
	got, failed := renderContent(json.RawMessage(
		`{"isError":true,"content":[{"type":"text","text":"no such project"}]}`))
	if !strings.Contains(got, "error") || !failed {
		t.Errorf("a tool error reads as a normal result: %q %v", got, failed)
	}
	if _, failed := renderContent(json.RawMessage(`{"content":[{"type":"text","text":"filed"}]}`)); failed {
		t.Error("a result that did not report failing was read as a failure")
	}
}

// A result this cannot parse is handed back bounded rather than as an error.
func TestAnUnrecognisedResultShapeIsStillBounded(t *testing.T) {
	long := `{"weird":"` + strings.Repeat("x", MaxResult*2) + `"}`
	got, _ := renderContent(json.RawMessage(long))
	if len(got) > MaxResult+8 {
		t.Errorf("an unrecognised result came back at %d bytes; the ceiling "+
			"is what stops a server filling a model's context", len(got))
	}
}

// A server's hints that are not the booleans the revision says they are do
// not cost it its tools.
//
// The hints were read so the gateway could pass on a tool a server calls
// destructive, as typed fields, so one server writing "readOnlyHint": "false"
// or a number made its whole answer to tools/list unreadable, and every
// agent and caller of that integration lost every tool, where the field had
// been ignored before. A hint that is not a boolean says nothing.
func TestHintsThatAreNotBooleansDoNotLoseTheTools(t *testing.T) {
	c := &Client{Do: func(context.Context, string, []byte, map[string]string) (*fetch.Result, error) {
		return &fetch.Result{Status: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[` +
				`{"name":"create_issue","description":"File one.","inputSchema":{"type":"object"},` +
				`"annotations":{"title":"File","readOnlyHint":"false","destructiveHint":1,"idempotentHint":null}},` +
				`{"name":"close_issue","description":"Close one.","inputSchema":{"type":"object"},"annotations":"none"},` +
				`{"name":"delete_issue","description":"Delete one.","inputSchema":{"type":"object"},` +
				`"annotations":{"readOnlyHint":true,"destructiveHint":true}}]}}`)}, nil
	}}
	tools, err := c.Tools(context.Background(), integration("create_issue", "close_issue", "delete_issue"))
	if err != nil {
		t.Fatalf("the server's tools could not be read: %v", err)
	}
	if len(tools) != 3 {
		t.Fatalf("read %d tools", len(tools))
	}
	for _, tool := range tools[:2] {
		if tool.Annotations.MayChange() || tool.Annotations.SaysDestructive() {
			t.Errorf("%s: a hint that is not a boolean was taken as one: %+v", tool.Name, tool.Annotations)
		}
	}
	// What is a boolean is still read.
	if !tools[2].Annotations.SaysDestructive() || !tools[2].Annotations.MayChange() {
		t.Errorf("a server's own destructive hint was lost: %+v", tools[2].Annotations)
	}
}
