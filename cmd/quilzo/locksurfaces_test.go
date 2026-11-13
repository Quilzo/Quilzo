// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

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
