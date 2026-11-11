// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentexec"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/store"
)

// platformCall performs one of the agent interface's operations for a run
// (internal/agentexec, Bridged), exactly as an outside agent's call would
// be: the read or write tool, the role the operation needs checked against
// the run's caller, and the handler's own checks and records. The
// interface is built once, when the run first needs it, for the caller
// acting in sess, so what its operations spend on models is the run's.
//
// What its operations write in the draft is written for startedBy, the
// person who started the run, as its write_page is (writesFor).
func platformCall(root string, s *store.Store, caller *Caller, sess *agent.Session,
	startedBy string) func(context.Context, string, bool, map[string]any) (string, error) {
	var (
		once sync.Once
		srv  *mcp.Server
	)
	return func(_ context.Context, op string, writes bool, args map[string]any) (string, error) {
		once.Do(func() {
			inRun := *caller
			inRun.run, inRun.runFor = sess, startedBy
			srv = buildMCP(root, s, &inRun, "templates")
		})
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

// writesFor is who a change this caller makes in the draft is recorded
// under, as the person it was written for: the person who started the run
// it acts in, when it acts in one, and otherwise the caller.
//
// A run that waited for a person goes on as whoever answered it, and the
// agent interface is built for that caller. So the record dana's run wrote,
// let through by sam, was recorded under sam, as written for him, and with
// a count of approvals set dana approved what her own run wrote. Who may
// do it is still asked of the caller.
func (c *Caller) writesFor() string {
	if c.runFor != "" {
		return c.runFor
	}
	return c.Name
}

// runPayers are who besides its own consumer a model an operation asks is
// charged to: the person who started the run the caller acts in, as the
// run's own calls are, and nobody when the caller acts in no run.
func (c *Caller) runPayers() []string {
	if c == nil || c.run == nil {
		return nil
	}
	return personConsumer(c)
}

// chargeRun counts a model call the caller's operation made against the
// run it acts in, when it acts in one: the tokens the model reported and
// what the gateway priced them at, as ChargedTo counts a completion. It is
// for a call ChargedTo cannot wrap, such as the vector of a question a
// chatbot embeds (chatbotMeaning).
func (c *Caller) chargeRun(u assist.Usage, cost int64) {
	if c == nil || c.run == nil {
		return
	}
	c.run.Tokens(u.In + u.Out)
	c.run.Charge(cost)
}

// chargedToRun is m charged to the run the caller acts in, when it acts in
// one, as the agent's own calls and its deciders' are.
//
// ask_assistant asked its chatbot's model on the chatbot's account alone,
// so a run with a money budget could spend past it by asking a chatbot,
// and its receipt priced the agent's own calls only.
func (c *Caller) chargedToRun(m assistant.Model) assistant.Model {
	if c == nil || c.run == nil || m == nil {
		return m
	}
	return agentexec.ChargedTo(c.run, m)
}
