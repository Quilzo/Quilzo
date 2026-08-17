package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func testServer() *Server {
	s := NewServer("quilzo", "test")
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
		Name: "publish", Summary: "make the draft live", Writes: true,
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

// The whole point of the design: what an agent pays for unasked is four short
// definitions, not one per command. A server that grew a tool per operation
// would be the thing the measurements condemned.
func TestOnlyFourToolsAreEverPreloaded(t *testing.T) {
	s := testServer()
	r := s.Handle(Request{JSONRPC: "2.0", Method: "tools/list"})
	m := r.Result.(map[string]any)
	tools := m["tools"].([]Tool)

	if len(tools) != 4 {
		t.Fatalf("expected 4 tools regardless of operation count, got %d", len(tools))
	}
	// Adding operations must not add tools, or the property is accidental.
	s.Register(Operation{Name: "extra", Summary: "another one"},
		func(map[string]any) (any, error) { return "", nil })
	r = s.Handle(Request{JSONRPC: "2.0", Method: "tools/list"})
	if got := len(r.Result.(map[string]any)["tools"].([]Tool)); got != 4 {
		t.Errorf("registering an operation added a tool: %d", got)
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
		Name:      "quilzo_write",
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

	if m["protocolVersion"] != Protocol {
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
