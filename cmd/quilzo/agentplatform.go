// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/store"
)

// platformCall performs one of the agent interface's operations for a run
// (internal/agentexec, Bridged), exactly as an outside agent's call would
// be: the read or write tool, the role the operation needs checked against
// the run's caller, and the handler's own checks and records. The
// interface is built once, when the run first needs it.
func platformCall(root string, s *store.Store, caller *Caller) func(context.Context, string, bool, map[string]any) (string, error) {
	var (
		once sync.Once
		srv  *mcp.Server
	)
	return func(_ context.Context, op string, writes bool, args map[string]any) (string, error) {
		once.Do(func() { srv = buildMCP(root, s, caller, "templates") })
		tool := "quilzo_read"
		if writes {
			tool = "quilzo_write"
		}
		params, err := json.Marshal(map[string]any{"name": tool, "arguments": map[string]any{
			"operation": op, "arguments": args}})
		if err != nil {
			return "", err
		}
		resp := srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})
		if resp.Error != nil {
			return "", errors.New(resp.Error.Message)
		}
		b, err := json.Marshal(resp.Result)
		if err != nil {
			return "", err
		}
		var r struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(b, &r); err != nil || len(r.Content) == 0 {
			return "", errors.New(op + " answered nothing")
		}
		return r.Content[0].Text, nil
	}
}
