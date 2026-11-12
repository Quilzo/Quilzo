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

// An operation asked in an area of the admin says so: "needs role:
// reader" alone told an agent that any reader may, where the role is asked
// of the compliance area, which a reader of the site is not.
func TestFindNamesTheAreaARoleIsAskedIn(t *testing.T) {
	s := testServer()
	s.Register(Operation{
		Name: "site_report", Summary: "what the law asks of the site", NeedsRole: "reader",
		Area: "/@compliance", Keywords: []string{"compliance"},
	}, func(a map[string]any) (any, error) { return "clear", nil })
	out := text(t, call(t, s, "tools/call", callParams{
		Name: "quilzo_find", Arguments: map[string]any{"query": "compliance"}}))
	if !strings.Contains(out, "needs role: reader on /@compliance") {
		t.Errorf("the area is not named: %q", out)
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

// quilzo_check is listed as running the checks that gate publishing, and a
// host that asks a person by a tool's name and description is granted only
// that. The only rules it was held to were the ones about publishing, so it
// ran any other operation named to it: a read that is no check, and even a
// write, under a tool that tells hosts it only reads.
func TestTheCheckToolRunsOnlyTheChecks(t *testing.T) {
	s := testServer()
	r := call(t, s, "tools/call", callParams{Name: "quilzo_check",
		Arguments: map[string]any{"operation": "check_accessibility"}})
	if got := text(t, r); got != "no blocking failures" {
		t.Errorf("the check answered %q", got)
	}
	for op, tool := range map[string]string{"list_pages": "quilzo_read", "write_page": "quilzo_write",
		"publish": "quilzo_publish"} {
		r := call(t, s, "tools/call", callParams{Name: "quilzo_check", Arguments: map[string]any{"operation": op}})
		if r.Error == nil || !strings.Contains(r.Error.Message, tool) {
			t.Errorf("%s ran through quilzo_check, or the refusal does not name %s: %+v", op, tool, r.Error)
		}
	}
	// A check still reads, through the read tool, as it always could.
	text(t, call(t, s, "tools/call", callParams{Name: "quilzo_read",
		Arguments: map[string]any{"operation": "check_accessibility"}}))
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

// What an operation answers with is text an agent can read: a string as it
// is, and anything else as JSON. shield_status answered with a map, and the
// text was Go's own notation for one, "map[active:[] held:false ...]",
// which no client can parse.
func TestAnAnswerThatIsNotTextIsJSON(t *testing.T) {
	type entry struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	answers := map[string]any{
		"a_map":    map[string]any{"active": []any{}, "held": false, "count": 2},
		"a_struct": entry{Name: "lockdown", Count: 3},
		"a_list":   []entry{{Name: "freeze", Count: 1}},
		"nothing":  nil,
	}
	s := NewServer("t", "1")
	s.Authorise = allowAll
	for name, answer := range answers {
		s.Register(Operation{Name: name, Summary: "answers"},
			func(map[string]any) (any, error) { return answer, nil })
	}
	s.Register(Operation{Name: "words", Summary: "answers"},
		func(map[string]any) (any, error) { return "no blocking failures", nil })
	for name, answer := range answers {
		got := text(t, call(t, s, "tools/call", callParams{
			Name: "quilzo_read", Arguments: map[string]any{"operation": name}}))
		var back, want any
		if err := json.Unmarshal([]byte(got), &back); err != nil {
			t.Errorf("%s answered %q, which is not JSON", name, got)
			continue
		}
		raw, _ := json.Marshal(answer)
		_ = json.Unmarshal(raw, &want)
		if a, b := fmt.Sprint(back), fmt.Sprint(want); a != b {
			t.Errorf("%s answered %s, not %s", name, got, raw)
		}
	}
	if got := text(t, call(t, s, "tools/call", callParams{
		Name: "quilzo_read", Arguments: map[string]any{"operation": "words"}})); got != "no blocking failures" {
		t.Errorf("a string answered %q", got)
	}
}

// find compares words, not letters. Every query word was looked for as a
// substring, so the "a" of "triage a support ticket" scored on almost every
// operation and three more on one with an "a" in its name, which came
// first; the operation the words were about did not.
func TestFindComparesWords(t *testing.T) {
	s := NewServer("t", "1")
	s.Authorise = allowAll
	ok := func(map[string]any) (any, error) { return "", nil }
	s.Register(Operation{Name: "agent_activity", Summary: "what agents have been doing",
		Keywords: []string{"agents", "activity", "audit"}}, ok)
	s.Register(Operation{Name: "list_deciders", Summary: "the site's typed questions",
		Keywords: []string{"decide", "classify"}}, ok)
	s.Register(Operation{Name: "decide", Summary: "answer a decider's typed questions",
		Keywords: []string{"decide", "classify", "triage"}}, ok)
	for query, want := range map[string]string{
		"triage a support ticket":     "decide",
		"which deciders are there":    "list_deciders",
		"what agents have been doing": "agent_activity",
	} {
		if got := s.find(query); len(got) == 0 || got[0].Name != want {
			t.Errorf("%q found %v first, not %s", query, got, want)
		}
	}
}

// A tool or operation nobody has is named back by a short form of what was
// asked for, not by all of it: the name is whatever the caller sent, up to
// the whole body, and the answer went into the log as well.
func TestAnUnknownNameIsQuotedShort(t *testing.T) {
	s := testServer()
	huge := "x" + strings.Repeat("y", 1<<20)
	for name, args := range map[string]map[string]any{
		huge:          {"operation": "list_pages"},
		"quilzo_read": {"operation": huge},
	} {
		r := call(t, s, "tools/call", map[string]any{"name": name, "arguments": args})
		if r.Error == nil {
			t.Fatal("a name nobody has was answered")
		}
		if len(r.Error.Message) > 512 || !strings.Contains(r.Error.Message, "xyyy") {
			t.Errorf("answered %d bytes, not a short form of the name: %.120s", len(r.Error.Message), r.Error.Message)
		}
	}
}

// An argument that is not what a tool or an operation takes is invalid
// params, naming it, before anything runs.
//
// # What this found
//
// Every handler read an argument as name, _ := a["page"].(string), so a
// number for a page name, the operation's arguments sent as a string, or
// the page under another name all became an empty name: the agent was told
// there is no page "" and concluded the content was missing. quilzo_find,
// whose schema requires a query, answered a call with none, or with a
// number, with every operation there is.
func TestArgumentsThatAreNotWhatIsTakenAreInvalidParams(t *testing.T) {
	s := NewServer("t", "1")
	s.Authorise = allowAll
	ran := 0
	s.Register(Operation{Name: "read_page", Summary: "read a page",
		Args: map[string]string{"page": "the page name"}},
		func(a map[string]any) (any, error) { ran++; p, _ := a["page"].(string); return "read " + p, nil })
	s.Register(Operation{Name: "search", Summary: "search",
		Args:  map[string]string{"query": "the words", "limit": "optional, at most 20", "near": "anything"},
		Types: map[string]string{"limit": "number", "near": "any"}},
		func(map[string]any) (any, error) { ran++; return "found", nil })
	s.Register(Operation{Name: "list_pages", Summary: "list"},
		func(map[string]any) (any, error) { ran++; return "listed", nil })

	invalid := func(name string, p callParams, says ...string) {
		t.Helper()
		before := ran
		r := call(t, s, "tools/call", p)
		if r.Error == nil || r.Error.Code != CodeInvalidParams {
			t.Errorf("%s: %+v %+v", name, r.Error, r.Result)
			return
		}
		for _, w := range says {
			if !strings.Contains(r.Error.Message, w) {
				t.Errorf("%s: %q does not say %q", name, r.Error.Message, w)
			}
		}
		if ran != before {
			t.Errorf("%s: the handler ran", name)
		}
	}
	read := func(args any) callParams {
		return callParams{Name: "quilzo_read", Arguments: map[string]any{"operation": "read_page", "arguments": args}}
	}
	invalid("find with no query", callParams{Name: "quilzo_find", Arguments: map[string]any{}}, "query")
	invalid("find with no arguments", callParams{Name: "quilzo_find"}, "query")
	invalid("find by a number", callParams{Name: "quilzo_find", Arguments: map[string]any{"query": 5}}, "query", "string")
	invalid("arguments as a string", read("page=about"), "arguments", "object")
	invalid("arguments as a list", read([]any{"about"}), "arguments", "object")
	invalid("operation as a number", callParams{Name: "quilzo_read", Arguments: map[string]any{"operation": 5}}, "operation")
	invalid("a page by a number", read(map[string]any{"page": 12}), "page", "string")
	invalid("the page under another name", read(map[string]any{"name": "about"}), "name", "page")
	invalid("a limit as text", callParams{Name: "quilzo_read", Arguments: map[string]any{"operation": "search",
		"arguments": map[string]any{"query": "x", "limit": "5"}}}, "limit", "number")

	ok := func(name string, p callParams) {
		t.Helper()
		if r := call(t, s, "tools/call", p); r.Error != nil {
			t.Errorf("%s: %+v", name, r.Error)
		}
	}
	ok("a page by its name", read(map[string]any{"page": "about"}))
	ok("a limit as a number, and anything where anything is taken", callParams{Name: "quilzo_read",
		Arguments: map[string]any{"operation": "search", "arguments": map[string]any{"query": "x", "limit": 5, "near": []any{1}}}})
	// Null is an argument left out, as clients that fill every optional
	// field with null send it.
	ok("null for a limit", callParams{Name: "quilzo_read",
		Arguments: map[string]any{"operation": "search", "arguments": map[string]any{"query": "x", "limit": nil}}})
	// An operation that names no arguments reads none, and is not held to any.
	ok("an operation that takes none", callParams{Name: "quilzo_read",
		Arguments: map[string]any{"operation": "list_pages", "arguments": map[string]any{"anything": 1}}})
	ok("find with a query", callParams{Name: "quilzo_find", Arguments: map[string]any{"query": "pages"}})
}

// Another server's tool, offered as it is, takes what its input schema
// says, and anything else is invalid params here and never sent on.
//
// A gateway listed the schema a person pinned and forwarded whatever came:
// a field the tool does not name was held for a person's approval as an
// ordinary call, and once approved went out with it.
func TestADirectToolTakesWhatItsSchemaSays(t *testing.T) {
	s := NewServer("gw", "1")
	var sent []map[string]any
	s.Direct = &Direct{Tools: []Tool{{Name: "delete_everything", InputSchema: map[string]any{
		"type": "object", "properties": map[string]any{"confirm": map[string]any{"type": "boolean"}},
		"required": []any{"confirm"}}}},
		Call: func(tool string, args map[string]any) (string, error) {
			sent = append(sent, args)
			return "deleted", nil
		}}
	for name, args := range map[string]map[string]any{
		"without confirm":         {},
		"confirm as text":         {"confirm": "yes"},
		"with a field it has not": {"confirm": true, "note": "x"},
	} {
		r := call(t, s, "tools/call", callParams{Name: "delete_everything", Arguments: args})
		if r.Error == nil || r.Error.Code != CodeInvalidParams {
			t.Errorf("%s: %+v", name, r.Error)
		}
	}
	if len(sent) != 0 {
		t.Fatalf("sent on: %v", sent)
	}
	if got := text(t, call(t, s, "tools/call", callParams{Name: "delete_everything",
		Arguments: map[string]any{"confirm": true}})); got != "deleted" {
		t.Fatalf("%q", got)
	}
}

// A tool of another server that ran and said it failed is answered as a
// result marked isError, as that server answered it.
//
// Direct's Call could only answer text or an error, so a gateway gave the
// failure's text as a plain result: the calling agent read "the partner
// system answered 503" as what the tool did, and carried on as though the
// action had happened, while the record said failure and the command line
// exited 1.
func TestADirectToolThatFailedIsAnsweredAsAnError(t *testing.T) {
	s := NewServer("gw", "1")
	s.Direct = &Direct{Tools: []Tool{{Name: "fail", InputSchema: map[string]any{"type": "object"}}},
		Call: func(string, map[string]any) (string, error) {
			return "", &ToolFailed{Text: "the partner system answered 503"}
		}}
	r := call(t, s, "tools/call", callParams{Name: "fail"})
	if r.Error != nil {
		t.Fatalf("a failure the tool reported is a result, not a protocol error: %+v", r.Error)
	}
	m, _ := r.Result.(map[string]any)
	if m["isError"] != true || !strings.Contains(text(t, r), "the partner system answered 503") {
		t.Fatalf("%#v", r.Result)
	}
}

// A server whose handlers read their arguments by their own rules hands
// each operation what it was sent, and still holds a call to the tool's own
// schema.
//
// A run's interface lists the store's operations and hands every call to
// the run, whose executor reads a page from "page" or "name". Held to the
// store's names, a program that sent name was answered invalid params
// before its call was a step of the run.
func TestAServerThatReadsItsOwnArgumentsIsHandedThemAsGiven(t *testing.T) {
	s := NewServer("run", "1")
	s.Authorise = allowAll
	s.ArgumentsAsGiven = true
	var got map[string]any
	s.Register(Operation{Name: "read_page", Summary: "read a page", Args: map[string]string{"page": "the page name"}},
		func(a map[string]any) (any, error) { got = a; return "read", nil })
	r := call(t, s, "tools/call", callParams{Name: "quilzo_read", Arguments: map[string]any{
		"operation": "read_page", "arguments": map[string]any{"name": "about", "depth": 2}}})
	if r.Error != nil || got["name"] != "about" {
		t.Fatalf("%+v, handed %v", r.Error, got)
	}
	// The tool's schema is the same four tools' everywhere.
	r = call(t, s, "tools/call", callParams{Name: "quilzo_read", Arguments: map[string]any{
		"operation": "read_page", "arguments": "name=about"}})
	if r.Error == nil || r.Error.Code != CodeInvalidParams {
		t.Fatalf("arguments as a string: %+v", r.Error)
	}
}
