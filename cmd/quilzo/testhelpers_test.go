// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/out"
)

// connectStore is an empty store, with the output quiet and read as JSON.
func connectStore(t *testing.T) string {
	t.Helper()
	old := w
	w = out.New(true)
	t.Cleanup(func() { w = old })
	root := t.TempDir()
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
