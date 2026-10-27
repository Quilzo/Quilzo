// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func testServer() *Server {
	s := NewServer("quilzo", "test")
	s.Authorise = allowAll
	s.Register(Operation{
		Name: "list_pages", Summary: "list the pages in the draft",
		Keywords: []string{"pages", "list", "content"},
	}, func(a map[string]any) (any, error) { return "index, about", nil })

	s.Register(Operation{
		Name: "write_page", Summary: "create or change a page in the draft",
		Writes: true, NeedsRole: "author",
		Args:     map[string]string{"page": "page name", "fields": "object of field values"},
		Keywords: []string{"write", "edit", "create", "page"},
	}, func(a map[string]any) (any, error) { return "saved", nil })

	s.Register(Operation{
		Name: "publish", Summary: "make the draft live", Writes: true, Publishes: true,
		NeedsRole: "publisher", Keywords: []string{"publish", "live", "release"},
	}, func(a map[string]any) (any, error) {
		return nil, &Refusal{Reason: "2 blocking accessibility failures"}
	})

	s.Register(Operation{
		Name: "check_accessibility", Summary: "run the accessibility checks",
		Keywords: []string{"check", "accessibility", "a11y"},
	}, func(a map[string]any) (any, error) { return "no blocking failures", nil })
	return s
}

func call(t *testing.T, s *Server, method string, params any) *Response {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return s.Handle(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`),
		Method: method, Params: raw})
}

func text(t *testing.T, r *Response) string {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("unexpected error: %v", r.Error.Message)
	}
	m, ok := r.Result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result shape: %#v", r.Result)
	}
	content, _ := m["content"].([]map[string]any)
	if len(content) == 0 {
		t.Fatal("no content")
	}
	return content[0]["text"].(string)
}

// The whole point of the design: what an agent pays for unasked is a handful
// of short definitions, not one per command. A server that grew a tool per
// operation would be the thing the measurements condemned. Four, and a fifth
// for publishing when something publishes.
func TestOnlyFiveToolsAreEverPreloaded(t *testing.T) {
	s := testServer()
	r := s.Handle(Request{JSONRPC: "2.0", Method: "tools/list"})
	m := r.Result.(map[string]any)
	tools := m["tools"].([]Tool)

	if len(tools) != 5 {
		t.Fatalf("expected 5 tools regardless of operation count, got %d", len(tools))
	}
	// Adding operations must not add tools, or the property is accidental.
	s.Register(Operation{Name: "extra", Summary: "another one"},
		func(map[string]any) (any, error) { return "", nil })
	s.Register(Operation{Name: "extra_publish", Summary: "another way live", Writes: true, Publishes: true},
		func(map[string]any) (any, error) { return "", nil })
	r = s.Handle(Request{JSONRPC: "2.0", Method: "tools/list"})
	if got := len(r.Result.(map[string]any)["tools"].([]Tool)); got != 5 {
		t.Errorf("registering an operation added a tool: %d", got)
	}
	// And a server where nothing publishes offers no publish tool.
	bare := NewServer("t", "0")
	bare.Register(Operation{Name: "list_pages", Summary: "list"},
		func(map[string]any) (any, error) { return "", nil })
	for _, tl := range bare.Tools() {
		if tl.Name == "quilzo_publish" {
			t.Error("quilzo_publish was offered by a server with nothing to publish")
		}
	}
}

// Publishing is its own tool, both ways round.
//
// A host asks a person before a tool runs by the tool's name and what it says
// it does. quilzo_write said "Never publishes" and carried publish, so a
// person who let an agent draft had let it put the draft in front of readers.
func TestPublishingHasAToolOfItsOwn(t *testing.T) {
	s := testServer()
	r := call(t, s, "tools/call", callParams{
		Name: "quilzo_write", Arguments: map[string]any{"operation": "publish"}})
	if r.Error == nil || !strings.Contains(r.Error.Message, "quilzo_publish") {
		t.Fatalf("the write tool, which says it never publishes, reached publish: %+v", r.Error)
	}
	r = call(t, s, "tools/call", callParams{
		Name: "quilzo_publish", Arguments: map[string]any{"operation": "write_page"}})
	if r.Error == nil || !strings.Contains(r.Error.Message, "quilzo_write") {
		t.Fatalf("the publish tool reached an ordinary write: %+v", r.Error)
	}
	var write, publish Tool
	for _, tl := range s.Tools() {
		switch tl.Name {
		case "quilzo_write":
			write = tl
		case "quilzo_publish":
			publish = tl
		}
	}
	if !strings.Contains(write.Description, "Never publishes") {
		t.Errorf("quilzo_write no longer says it never publishes: %q", write.Description)
	}
	if publish.Annotations["destructiveHint"] != true || publish.Annotations["readOnlyHint"] != false {
		t.Errorf("quilzo_publish does not tell a host it changes what readers see: %v", publish.Annotations)
	}
	if !strings.Contains(text(t, call(t, s, "tools/call", callParams{
		Name: "quilzo_find", Arguments: map[string]any{"query": "publish"}})), "call: quilzo_publish") {
		t.Error("quilzo_find does not send an agent to quilzo_publish")
	}
}

func TestFindDescribesOnlyWhatWasAskedFor(t *testing.T) {
	s := testServer()
	out := text(t, call(t, s, "tools/call", callParams{
		Name: "quilzo_find", Arguments: map[string]any{"query": "publish the site"}}))

	if !strings.Contains(out, "publish") {
		t.Errorf("the matching operation is missing: %q", out)
	}
	if !strings.Contains(out, "needs role: publisher") {
		t.Error("the role requirement should be stated, so an agent can tell " +
			"a permission problem from a broken call")
	}
}

func TestFindWithNoMatchReturnsTheMenu(t *testing.T) {
	s := testServer()
	out := text(t, call(t, s, "tools/call", callParams{
		Name: "quilzo_find", Arguments: map[string]any{"query": "xyzzy"}}))

	// An agent that searched badly should see what exists rather than a dead
	// end it will guess around.
	for _, want := range []string{"list_pages", "write_page", "publish"} {
		if !strings.Contains(out, want) {
			t.Errorf("a failed search should list everything; %s missing", want)
		}
	}
}

// Without this the four-tool split is a labelling convention, and a client
// permitted only to read could write by naming the operation.
func TestAReadToolCannotReachAWriteOperation(t *testing.T) {
	s := testServer()
	r := call(t, s, "tools/call", callParams{
		Name:      "quilzo_read",
		Arguments: map[string]any{"operation": "write_page"}})

	if r.Error == nil {
		t.Fatal("a write operation was reachable through the read tool")
	}
	if !strings.Contains(r.Error.Message, "quilzo_write") {
		t.Errorf("the error should name the right tool, got %q", r.Error.Message)
	}
}

func TestAWriteToolCannotBeUsedForAReadOperation(t *testing.T) {
	s := testServer()
	r := call(t, s, "tools/call", callParams{
		Name:      "quilzo_write",
		Arguments: map[string]any{"operation": "list_pages"}})
	if r.Error == nil {
		t.Error("a read operation should not be invoked through the write tool")
	}
}

// A refusal is a decision. An agent that reads "denied by policy" as "the server
// broke" will retry, and retrying a refusal turns one blocked action into many.
func TestARefusalIsDistinguishableFromAFailure(t *testing.T) {
	s := testServer()
	r := call(t, s, "tools/call", callParams{
		Name:      "quilzo_publish",
		Arguments: map[string]any{"operation": "publish"}})

	if r.Error == nil {
		t.Fatal("the gate should have refused")
	}
	if r.Error.Code != CodeRefused {
		t.Errorf("a refusal should not use the internal-error code, got %d", r.Error.Code)
	}
	if r.Error.Code == CodeInternal {
		t.Error("refusal and malfunction must not share a code")
	}
	data, _ := r.Error.Data.(map[string]any)
	if data["retryable"] != false {
		t.Error("a refusal should say it is not worth retrying")
	}
	if !strings.Contains(r.Error.Message, "accessibility") {
		t.Errorf("the refusal should say what blocked it: %q", r.Error.Message)
	}
}

func TestAnInternalFailureIsNotDressedAsARefusal(t *testing.T) {
	s := NewServer("t", "1")
	s.Authorise = allowAll
	s.Register(Operation{Name: "broken", Summary: "fails", Writes: true},
		func(map[string]any) (any, error) { return nil, fmt.Errorf("disk on fire") })

	r := call(t, s, "tools/call", callParams{
		Name: "quilzo_write", Arguments: map[string]any{"operation": "broken"}})
	if r.Error.Code != CodeInternal {
		t.Errorf("a genuine failure should be an internal error, got %d", r.Error.Code)
	}
}

func TestUnknownOperationsAndToolsAreRefusedClearly(t *testing.T) {
	s := testServer()

	r := call(t, s, "tools/call", callParams{
		Name: "quilzo_read", Arguments: map[string]any{"operation": "nonsense"}})
	if r.Error == nil || !strings.Contains(r.Error.Message, "quilzo_find") {
		t.Error("an unknown operation should point at how to discover the real ones")
	}

	r = call(t, s, "tools/call", callParams{Name: "quilzo_delete_everything"})
	if r.Error == nil || r.Error.Code != CodeMethodNotFound {
		t.Error("an unknown tool should be a method-not-found")
	}
}

func TestInitializeAnnouncesTheConstraints(t *testing.T) {
	s := testServer()
	r := s.Handle(Request{JSONRPC: "2.0", Method: "initialize"})
	m := r.Result.(map[string]any)

	if m["protocolVersion"] != Legacy[0] {
		t.Errorf("wrong protocol version: %v", m["protocolVersion"])
	}
	instructions, _ := m["instructions"].(string)
	// The two things an agent must know before it writes anything.
	if !strings.Contains(instructions, "quilzo_find") {
		t.Error("initialize should tell the agent to search first")
	}
	if !strings.Contains(strings.ToLower(instructions), "never publish") {
		t.Error("initialize should say writes do not publish")
	}
	if !strings.Contains(strings.ToLower(instructions), "ai-generated") {
		t.Error("initialize should say written content is marked, since the " +
			"agent is the reason it needs to be")
	}
}

func TestUnknownMethodIsNotFound(t *testing.T) {
	s := testServer()
	r := s.Handle(Request{JSONRPC: "2.0", Method: "resources/list"})
	if r.Error == nil || r.Error.Code != CodeMethodNotFound {
		t.Error("an unimplemented method should say so rather than fail oddly")
	}
}

// allowAll is the hook for tests about something other than authority.
//
// It has to be written out rather than left nil, because a nil hook refuses
// every operation — which is the point of it, and which is how the suite
// found out: the refusal-semantics test above started failing the moment the
// gate went in, reporting a refusal it had not asked for.
func allowAll(Operation) error { return nil }

// On standard input the client is answered in the revision it asked for,
// when this speaks it, as over HTTP; asked for one it does not speak, the
// newest with a handshake.
func TestStandardInputAnswersTheRevisionAskedFor(t *testing.T) {
	s := NewServer("quilzo", "test")
	for asked, want := range map[string]string{
		"2025-11-25": "2025-11-25", "2025-06-18": "2025-06-18", "2025-03-26": "2025-03-26",
		"2024-11-05": "2025-11-25", "": "2025-11-25",
	} {
		r := call(t, s, "initialize", map[string]any{"protocolVersion": asked, "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "c", "version": "1"}})
		if got := r.Result.(map[string]any)["protocolVersion"]; got != want {
			t.Errorf("asked %q, answered %v", asked, got)
		}
	}
}
