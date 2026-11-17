// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/store"
)

// A claim on a page is shown on every surface that writes it, not only in
// the browser. pat locked Stockists for an afternoon's rewrite; alice wrote
// it from the terminal and her agent wrote it over MCP, and neither was told,
// because only the browser's editor read the claims. An agent could not list
// them either. The writes still go ahead: a claim is a courtesy, not a lock.
func TestAClaimIsShownWhereverAPageIsWritten(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := storeFolder(t)
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	locks := &collab.Locks{}
	locks.Claim("stockists", "pat", "pat rewriting stockists", time.Now())
	if err := saveJSON(locksPath(root), locks); err != nil {
		t.Fatal(err)
	}

	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf
	if err := cmdAdd(root, []string{"stockists=" + fileOf(t, "s.json", `{"title":"Stockists"}`)}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "pat rewriting stockists") {
		t.Errorf("quilzo add wrote a page pat holds without a word: %q", buf.String())
	}
	w = old

	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, asAdmin("alice"), bundleTemplates(t))
	text, rerr := callTool(t, srv, "quilzo_write", "write_page", map[string]any{
		"page": "stockists", "fields": map[string]any{"title": "Stockists (agent)"}})
	if rerr != nil {
		t.Fatal(rerr.Message)
	}
	if !strings.Contains(text, "pat") || !strings.Contains(text, "pat rewriting stockists") {
		t.Errorf("write_page does not say pat holds the page: %q", text)
	}
	text, rerr = callTool(t, srv, "quilzo_read", "list_locks", map[string]any{})
	if rerr != nil {
		t.Fatal(rerr.Message)
	}
	if !strings.Contains(text, "stockists") || !strings.Contains(text, "pat") {
		t.Errorf("list_locks does not list pat's claim: %q", text)
	}
	// The claim is still pat's: telling the writer is all this does.
	locks, _ = loadLocks(root)
	if l, held := locks.Holder("stockists", time.Now()); !held || l.Holder != "pat" {
		t.Errorf("a write took pat's claim: %+v", l)
	}
}

// patHolds puts pat's claim on each page named, for a test about who is told.
func patHolds(t *testing.T, root string, pages ...string) {
	t.Helper()
	locks := &collab.Locks{}
	for _, page := range pages {
		locks.Claim(page, "pat", "pat rewriting "+page, time.Now())
	}
	if err := saveJSON(locksPath(root), locks); err != nil {
		t.Fatal(err)
	}
}

// printedBy is what a command prints, in words or as its --json document.
func printedBy(t *testing.T, asJSON bool, run func() error) string {
	t.Helper()
	old := w
	defer func() { w = old }()
	var buf bytes.Buffer
	w = out.New(asJSON)
	w.Out = &buf
	if err := run(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// The other ways the command line writes a page somebody holds. `quilzo add`
// said so for a page it wrote and for `--remove stockists`, and said nothing
// for `--remove "old, stockists"`, whose names it read with their spaces; a
// move renamed pat's page from under him without a word; and a script asking
// for --json was told nothing by any of them, its document having no place
// for a claim.
func TestAClaimIsShownHoweverTheCommandLineWritesThePage(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := storeFolder(t)
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	page := fileOf(t, "p.json", `{"title":"A page"}`)
	if err := cmdAdd(root, []string{"old=" + page, "stockists=" + page, "shop=" + page}); err != nil {
		t.Fatal(err)
	}
	patHolds(t, root, "stockists", "shop")

	got := printedBy(t, false, func() error {
		return cmdAdd(root, []string{"--remove", "old, stockists"})
	})
	if !strings.Contains(got, "pat rewriting stockists") {
		t.Errorf("removing a page pat holds, named after a space, said nothing: %q", got)
	}

	got = printedBy(t, false, func() error { return cmdMove(root, []string{"shop", "store"}) })
	if !strings.Contains(got, "pat rewriting shop") {
		t.Errorf("moving a page pat holds said nothing: %q", got)
	}

	patHolds(t, root, "store")
	for name, run := range map[string]func() error{
		"section add": func() error { return cmdSection(root, []string{"add", "store", "faq"}) },
		"move":        func() error { return cmdMove(root, []string{"store", "shop"}) },
	} {
		var doc struct {
			Claimed []collab.Lock `json:"claimed"`
		}
		got := printedBy(t, true, run)
		if err := json.Unmarshal([]byte(got), &doc); err != nil {
			t.Fatalf("%s: %v: %s", name, err, got)
		}
		if len(doc.Claimed) != 1 || doc.Claimed[0].Holder != "pat" || doc.Claimed[0].Page != "store" {
			t.Errorf("%s --json does not say pat holds the page: %s", name, got)
		}
	}
}

// An agent run here is told as an agent at the interface is. Its write_page
// is this program's own (internal/agentexec), not the interface's, so the
// model that wrote over pat's afternoon read "wrote welcome" and went on.
func TestAnAgentsRunIsToldOfAClaimOnThePageItWrote(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	standInModel(t)
	declaredAutonomy(t, root)
	if err := declareAgent(root, asker("tidy"), true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	patHolds(t, root, "welcome")
	id, err := runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := loadAgentRun(root, id)
	if rec.Trace.Waiting == nil {
		t.Fatalf("the run did not stop at the write: %+v", rec.Trace)
	}
	n := rec.Trace.Waiting.N
	done, err := continueAgentRun(context.Background(), root, id,
		&agent.Verdict{N: n, Approve: true}, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	if st := done.Trace.Steps[n-1]; !strings.HasPrefix(st.Result, "wrote welcome") ||
		!strings.Contains(st.Result, "pat rewriting welcome") {
		t.Errorf("the run was not told pat holds the page it wrote: %q", st.Result)
	}
}
