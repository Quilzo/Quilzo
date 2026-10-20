// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// writerDown makes the store's log writer configured and unreachable: the
// socket's path is there and nothing listens on it.
func writerDown(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(logSocketPath(root), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(logSocketPath(root)) })
}

// listingModel lists the pages first, then is done.
func listingModel(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"done","say":"finished"}`
		if strings.Contains(string(b), "Nothing has been done yet") {
			choice = `{"op":"list_pages","input":{}}`
		}
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": choice}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("QUILZO_MODEL_URL", srv.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")
}

// On the demonstration store: with the log writer down, an agent's run
// performs nothing and says why it stopped; with it back, the same run
// goes ahead.
func TestAnAgentDoesNothingWhileItsRecordCannotBeWritten(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	listingModel(t)
	declaredAutonomy(t, root)
	if err := declareAgent(root, asker("tidy"), true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	writerDown(t, root)
	id, err := runAgentOnce(root, "tidy", "see what pages there are", true, asAdmin("dana"))
	if err == nil {
		rec, _ := loadAgentRun(root, id)
		if len(rec.Trace.Steps) == 0 || rec.Trace.Steps[0].Allowed ||
			!strings.Contains(rec.Trace.Stopped, "audit log cannot take a record") {
			t.Fatalf("a run went on with its log writer down: %+v", rec.Trace)
		}
	} else if !strings.Contains(err.Error(), "audit") {
		t.Fatalf("the run failed for another reason: %v", err)
	}
	os.Remove(logSocketPath(root))
	noteAuditWrite(root, nil)
	id, err = runAgentOnce(root, "tidy", "see what pages there are", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := loadAgentRun(root, id)
	if len(rec.Trace.Steps) == 0 || !rec.Trace.Steps[0].Allowed || !rec.Trace.Complete {
		t.Fatalf("with the log back the run did not go ahead: %+v", rec.Trace)
	}
}

// Over the machine interface a change is refused while the log cannot
// take it, and reading goes on.
func TestAChangeOverMCPIsRefusedWhileTheLogCannotTakeIt(t *testing.T) {
	root, pol := identityStore(t)
	grantAll(t, root, pol, auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/"})
	call := mcpAs(t, root, withRole("pat", auth.RolePublisher))
	writerDown(t, root)
	if got := call("quilzo_write", "write_page", map[string]any{"page": "shop",
		"fields": map[string]any{"title": "Shop"}}); !refused(got) || !strings.Contains(got, "audit log cannot take a record") {
		t.Errorf("a write went ahead with the log writer down: %s", got)
	}
	if got := call("quilzo_read", "list_pages", nil); refused(got) || !strings.Contains(got, "shop") {
		t.Errorf("reading stopped with the log writer down: %s", got)
	}
}

// A write that failed is remembered until one succeeds: a full disk or a
// writer refusing shows only in a write, not in a probe.
func TestAFailedWriteIsRememberedUntilOneSucceeds(t *testing.T) {
	root := demoStore(t)
	if err := auditReady(root); err != nil {
		t.Fatal(err)
	}
	noteAuditWrite(root, errors.New("no space left on device"))
	if err := auditReady(root); err == nil || !strings.Contains(err.Error(), "no space left") {
		t.Fatalf("a failed write was forgotten: %v", err)
	}
	if err := recordE(root, audit.Record{Action: "test.recovered", Resource: "/", Outcome: audit.Success,
		Principal: "dana", Kind: audit.KindHuman, Verified: true}); err != nil {
		t.Fatal(err)
	}
	if err := auditReady(root); err != nil {
		t.Errorf("a write that succeeded did not clear it: %v", err)
	}
}

// A tool that changes something elsewhere is not forwarded while its
// record could not be written.
func TestAForwardedToolWaitsForTheLog(t *testing.T) {
	root, _ := gatewayRig(t, &agent.GatewayPolicy{Role: "author"})
	writerDown(t, root)
	if _, err := gatewayCallAs(t, root, appToken("rae", auth.RoleAuthor)); err == nil ||
		!strings.Contains(err.Error(), "audit log cannot take a record") {
		t.Fatalf("a forwarded write went ahead with the log writer down: %v", err)
	}
	os.Remove(logSocketPath(root))
	noteAuditWrite(root, nil)
	if out, err := gatewayCallAs(t, root, appToken("rae", auth.RoleAuthor)); err != nil || !strings.Contains(out, "filed") {
		t.Fatalf("with the log back: %q %v", out, err)
	}
}

// An outside agent's press in a browser is refused while its record could
// not be written, and reading the page goes on.
func TestAnOutsideAgentsPressWaitsForTheLog(t *testing.T) {
	root, paid := grantShop(t)
	g := browserGrant{Name: "codex", Read: []string{"shop.example.com"}, Write: []string{"shop.example.com"}}
	m, err := g.manifest()
	if err != nil {
		t.Fatal(err)
	}
	if err := saveBrowserGrant(root, g); err != nil {
		t.Fatal(err)
	}
	tok := auth.Token{Principal: "lee", Role: auth.RoleAuthor}
	caller := remoteCaller(tok)
	ctx := context.Background()
	out, err := browserGrantCall(ctx, root, g, m, "codex", "browser_open",
		map[string]any{"url": "https://shop.example.com/"}, caller, tok, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writerDown(t, root)
	ref := outlineRef(t, out, "Pay now")
	if _, err := browserGrantCall(ctx, root, g, m, "codex", "browser_click",
		map[string]any{"ref": ref}, caller, tok, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "audit log cannot take a record") {
		t.Fatalf("a press went ahead with the log writer down: %v", err)
	}
	if paid() != 0 {
		t.Error("the shop was paid")
	}
}
