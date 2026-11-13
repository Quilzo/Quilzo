// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/store"
)

// Every operation this program registers declares a role that can be checked.
//
// The central gate refuses an operation with no role, so an ungated one fails
// closed at call time rather than leaking. This catches it in CI instead,
// which is the difference between a build somebody fixes and a refusal
// somebody debugs.
//
// It exists because the shape it guards against is what happened: NeedsRole
// was set on three of twenty-three operations and read in one place that only
// printed it, so twenty operations were reachable by anybody who could start
// the process — including the four that return the posture and inventory
// reports the admin restricts to an administrator.
func TestEveryMCPOperationDeclaresACheckableRole(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, &Caller{Name: "test"}, "templates")

	ops := srv.Operations()
	if len(ops) < 20 {
		t.Fatalf("only %d operations registered; this is checking the wrong "+
			"server", len(ops))
	}
	// Reads that are an author's on purpose: what visitors wrote, which a
	// reader does not read anywhere else either.
	visitorsWords := map[string]string{
		"list_chatbot_gaps": "visitors' unanswered questions, masked, an author's as the Inbox is",
	}
	for _, op := range ops {
		action, err := actionForRole(op.NeedsRole)
		if err != nil {
			t.Errorf("%s declares role %q, which cannot be checked: %v — so "+
				"the operation is refused at call time and nobody finds out "+
				"until they try it", op.Name, op.NeedsRole, err)
			continue
		}
		// A write must not be gated as a read. The four-tool split already
		// refuses calling a write through quilzo_read, but that is a
		// labelling boundary; this is the privilege one.
		if op.Writes && action == auth.ActView {
			t.Errorf("%s changes content and is gated on %s", op.Name, action)
		}
		if _, ok := visitorsWords[op.Name]; ok && action == auth.ActEditDraft {
			continue
		}
		if !op.Writes && (action == auth.ActEditDraft || action == auth.ActPublish) {
			t.Errorf("%s reads and is gated on %s, which is stricter than it "+
				"needs and will refuse a reader the read", op.Name, action)
		}
	}
}

// The gate is wired, not merely available.
//
// buildMCP sets Authorise. A server built without it refuses everything,
// which is safe but would take the whole agent interface down — so the thing
// worth asserting is that the real constructor wires it.
func TestBuildMCPWiresTheGate(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if srv := buildMCP(root, s, &Caller{Name: "test"}, "templates"); srv.Authorise == nil {
		t.Fatal("buildMCP left Authorise nil, so every operation refuses")
	}
}

// An argument of the wrong type, under another name, or that no page could
// hold is invalid params naming it, from the store's own operations.
//
// read_page given its page as a number answered there is no page "", and
// an agent concluded the page was missing; quilzo_find without its query
// listed every operation; write_page kept a field with no name and a null
// in the draft, which no other door can write.
func TestTheStoresOperationsRefuseArgumentsTheyDoNotTake(t *testing.T) {
	root := publishedShop(t)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, asAdmin("dana"), "templates")
	invalid := func(name, tool, op string, args map[string]any, says ...string) {
		t.Helper()
		_, e := callTool(t, srv, tool, op, args)
		if e == nil || e.Code != mcp.CodeInvalidParams {
			t.Errorf("%s: %+v", name, e)
			return
		}
		for _, w := range says {
			if !strings.Contains(e.Message, w) {
				t.Errorf("%s: %q does not say %q", name, e.Message, w)
			}
		}
	}
	invalid("a page by a number", "quilzo_read", "read_page", map[string]any{"page": 12}, "page", "string")
	invalid("a page under another name", "quilzo_read", "read_page", map[string]any{"name": "returns"}, "name", "page")
	invalid("a field with no name", "quilzo_write", "write_page",
		map[string]any{"page": "returns", "fields": map[string]any{"": "x"}}, "no name")
	invalid("a null field", "quilzo_write", "write_page",
		map[string]any{"page": "returns", "fields": map[string]any{"title": nil}}, "title", "null")
	invalid("a listing under another name", "quilzo_read", "run_listing", map[string]any{"name": "in_stock"}, "name", "listing")

	resp := srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"quilzo_find","arguments":{}}`)})
	if resp.Error == nil || resp.Error.Code != mcp.CodeInvalidParams || !strings.Contains(resp.Error.Message, "query") {
		t.Errorf("quilzo_find without a query: %+v", resp.Error)
	}

	// What a content type may declare is still written: a number, true or
	// false, a list.
	if _, e := callTool(t, srv, "quilzo_write", "write_page", map[string]any{"page": "returns",
		"fields": map[string]any{"title": "Returns", "order": 3, "members_only": false, "tags": []any{"help"}}}); e != nil {
		t.Fatalf("a page with typed fields: %+v", e)
	}
	got, e := callTool(t, srv, "quilzo_read", "read_page", map[string]any{"page": "returns"})
	if e != nil || !strings.Contains(got, `"order": 3`) {
		t.Fatalf("%v %s", e, got)
	}

	// And every type an operation declares is for an argument it names.
	for _, op := range srv.Operations() {
		for k, typ := range op.Types {
			if _, ok := op.Args[k]; !ok {
				t.Errorf("%s gives %s a type and does not name it", op.Name, k)
			}
			switch typ {
			case "number", "boolean", "object", "array", "any":
			default:
				t.Errorf("%s gives %s the type %q, which is not one checked", op.Name, k, typ)
			}
		}
	}
}

// What an operation tells an agent to do names its arguments, never a
// flag or an argument it does not have. run_listing said "call it with no
// name", where its argument is listing, and an agent sent name, which was
// ignored, and got the catalogue of listings instead of rows.
func TestTheOperationsTellAnAgentTheirOwnArguments(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, &Caller{Name: "test"}, "templates")
	for _, op := range srv.Operations() {
		said := op.Summary + " " + op.Detail
		for _, d := range op.Args {
			said += " " + d
		}
		if strings.Contains(said, " --") || strings.Contains(said, "with no name") {
			t.Errorf("%s tells an agent what its call cannot do: %s", op.Name, said)
		}
		if op.Name == "run_listing" && !strings.Contains(op.Detail, "listing out") {
			t.Errorf("run_listing does not say to leave listing out: %s", op.Detail)
		}
	}
}

// read_page with no page is invalid params naming the argument, not an
// answer that there is no page "".
//
// A page of the wrong type or under another name was refused as invalid
// params, and one left out, or given as "" or null as clients that fill
// every field send it, still read as the empty name: an agent was told
// there is no page "" and concluded the content was missing, as it had
// been told for a number.
func TestReadPageWithNoPageIsToldItNeedsOne(t *testing.T) {
	root := publishedShop(t)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, asAdmin("dana"), "templates")
	for name, args := range map[string]map[string]any{
		"no page":    {},
		"an empty":   {"page": ""},
		"blank":      {"page": "  "},
		"a null one": {"page": nil},
	} {
		_, e := callTool(t, srv, "quilzo_read", "read_page", args)
		if e == nil || e.Code != mcp.CodeInvalidParams || !strings.Contains(e.Message, "page") ||
			strings.Contains(e.Message, `no page ""`) {
			t.Errorf("%s: %+v", name, e)
		}
	}
	// A page that is not there is still said not to be there.
	if _, e := callTool(t, srv, "quilzo_read", "read_page", map[string]any{"page": "nowhere"}); e == nil ||
		e.Code != mcp.CodeRefused || !strings.Contains(e.Message, `there is no page "nowhere"`) {
		t.Errorf("a page that is not there: %+v", e)
	}
}
