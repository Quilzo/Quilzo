// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/store"
)

// shield_status answers in JSON, and so does every operation that answers
// with something other than words. It answered "map[active:[] held:false
// ...]", Go's own notation for a map, which no client can parse; so did
// eval_results.
//
// Every operation that reads is asked, on a fresh store, as an
// administrator: an answer that opens like data is data an agent can read.
func TestEveryAnswerThatLooksLikeDataIsJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, asAdmin("dana"), "templates")

	got, e := callTool(t, srv, "quilzo_read", "shield_status", map[string]any{})
	if e != nil {
		t.Fatal(e.Message)
	}
	var status struct {
		Active    []any `json:"active"`
		Held      *bool `json:"held"`
		Playbooks []struct {
			Name string `json:"name"`
		} `json:"playbooks"`
	}
	if err := json.Unmarshal([]byte(got), &status); err != nil || status.Held == nil || len(status.Playbooks) == 0 {
		t.Fatalf("shield_status answered %.120q (%v)", got, err)
	}

	read := 0
	for _, op := range srv.Operations() {
		if op.Writes || op.Publishes {
			continue
		}
		tool := "quilzo_read"
		if strings.HasPrefix(op.Name, "check") {
			tool = "quilzo_check"
		}
		text, e := callTool(t, srv, tool, op.Name, map[string]any{})
		if e != nil {
			continue
		}
		read++
		if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") ||
			strings.HasPrefix(text, "map[") || strings.HasPrefix(text, "&{") || text == "<nil>" {
			if !json.Valid([]byte(text)) {
				t.Errorf("%s answered %.120q, which is not JSON", op.Name, text)
			}
		}
	}
	if read < 20 {
		t.Fatalf("only %d operations answered", read)
	}
}
