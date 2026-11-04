// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/out"
)

// storeFolder is a folder for a test's store, removed only once the work
// the test started in the background has finished.
//
// The shield's responses and the notices that go with them are written
// into the store from the background (inBackground), and the folder's
// removal raced the last write: on a loaded machine it failed the test
// with "directory not empty" and no line of the test's own, or the record
// was written to a folder already gone. The wait is registered after the
// folder, so it runs first.
func storeFolder(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() { finishBackground(10 * time.Second) })
	return dir
}

// connectStore is an empty store, with the output quiet and read as JSON.
func connectStore(t *testing.T) string {
	t.Helper()
	old := w
	w = out.New(true)
	t.Cleanup(func() { w = old })
	root := storeFolder(t)
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	return root
}

// human is a person signed in, verified, as the admin hands one over.
func human(name string) *Caller {
	return &Caller{Name: name, Kind: audit.KindHuman, Verified: true}
}

// callTool calls one operation through the machine interface's tool and
// returns the text it answered with.
func callTool(t *testing.T, srv *mcp.Server, tool, op string, args map[string]any) (string, *mcp.Error) {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": map[string]any{
		"operation": op, "arguments": args}})
	resp := srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`),
		Method: "tools/call", Params: params})
	if resp.Error != nil {
		return "", resp.Error
	}
	b, _ := json.Marshal(resp.Result)
	var r struct {
		Content []struct{ Text string } `json:"content"`
	}
	_ = json.Unmarshal(b, &r)
	if len(r.Content) == 0 {
		t.Fatalf("no content: %s", b)
	}
	return r.Content[0].Text, nil
}
