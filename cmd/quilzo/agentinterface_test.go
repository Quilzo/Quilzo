// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/render"
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
	// Quilzo's own token: no connection, and no app to name.
	own := appCallRecord(&mcp.Caller{Principal: "dana", Data: auth.Token{Principal: "dana"}}, "tools/list", "", nil)
	if _, has := own.Detail["grant"]; has || own.Principal != "mcp-client" || own.Outcome != audit.Success {
		t.Errorf("%+v", own)
	}
	for k := range r.Detail {
		if why := audit.ForbiddenKey(k); why != "" {
			t.Error(why)
		}
	}
}

// A call's record is a few hundred bytes whatever the caller sent.
//
// A refusal quotes what it was asked about, and this stored the refusal
// whole: a reader's read_page naming a page just under the 2 MiB body limit
// added 2 MB to the log with each request, 39 MB in a second and a half,
// and the log is read whole by verify, /logs and every export. The tool and
// operation names come from the request too.
func TestACallsRecordIsBoundedWhateverTheCallerSent(t *testing.T) {
	huge := "p" + strings.Repeat("x", 2<<20)
	c := &mcp.Caller{Principal: "rae", Data: auth.Token{Principal: "rae"}}
	r := appCallRecord(c, "quilzo_read"+huge, huge, &mcp.Error{Code: mcp.CodeRefused,
		Message: "there is no page " + `"` + huge + `"`})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 2048 {
		t.Fatalf("a refused call made a record of %d bytes", len(b))
	}
	if !strings.HasPrefix(r.Detail["error"], "there is no page") {
		t.Errorf("the record no longer says what was refused: %.80s", r.Detail["error"])
	}
}

// A refusal names a page it could not find by a short form of the name.
//
// The whole name came back: two megabytes to the caller, and two more into
// the log until the record was bounded.
func TestARefusalQuotesAPageNameItCouldNotFindShort(t *testing.T) {
	root, _ := concurrentRig(t)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, asAdmin("rae"), t.TempDir())
	huge := "p" + strings.Repeat("x", 2<<20)
	for _, op := range []string{"read_page", "similar_pages"} {
		_, refused := callTool(t, srv, "quilzo_read", op, map[string]any{"page": huge})
		if refused == nil {
			t.Fatalf("%s found a page nobody wrote", op)
		}
		if len(refused.Message) > 512 || !strings.Contains(refused.Message, "pxxx") {
			t.Errorf("%s answered %d bytes, not a short form of the name: %.120s", op, len(refused.Message), refused.Message)
		}
	}
}

// The agent interface holds a token to the same budget the content API
// does: a burst of api.rate.burst, then api.rate.per_minute, then 429 with
// how long to wait.
//
// It had none. The reader token /api/v1 cut off after twenty requests got
// two hundred concurrent whole-site exports at /mcp, and the same door
// reaches model calls and outbound fetches, so nothing bounded what one
// credential could make this server do or spend.
func TestTheAgentInterfaceHoldsATokenToTheAPIsRate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	old := flagToken
	flagToken = ""
	t.Cleanup(func() { flagToken = old })
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdConfig(root, []string{"set", "mcp.remote", "true", "--accept-risk", "agents reach it"}); err != nil {
		t.Fatal(err)
	}
	seedPolicy(t, root, [2]string{"rae", "reader"})
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := toks.Issue("cli", "rae", auth.RoleReader, "/", 72*time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(s, pol, toks, render.Layouts{})
	if err != nil {
		t.Fatal(err)
	}
	wireInterface(root, s, srv, nil, t.TempDir())
	h := srv.Handler()

	got := map[int]int{}
	var refused *httptest.ResponseRecorder
	for range 30 {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+secret)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		got[rec.Code]++
		if rec.Code == http.StatusTooManyRequests && refused == nil {
			refused = rec
		}
	}
	if got[http.StatusOK] != 20 || got[http.StatusTooManyRequests] != 10 {
		t.Fatalf("thirty calls with one token, against a burst of twenty, were answered %v", got)
	}
	if refused.Header().Get("Retry-After") == "" {
		t.Error("a refusal for going too fast does not say when to come back")
	}
	if !strings.Contains(refused.Body.String(), `"retryable":true`) {
		t.Errorf("a refusal for going too fast is not marked retryable: %s", refused.Body.String())
	}
}
