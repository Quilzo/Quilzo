// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
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

// An empty list is [] in every answer, as it is on the command line.
//
// The command line writes an empty list as [] (out.Writer.JSON), and the
// machine interface encoded its answers for itself, so shield_status on a
// store with nothing in force answered "active": null, and the operations
// that marshal their own answer did the same with theirs. Every operation
// that reads is asked on a fresh store, where most lists are empty; a null
// left in an answer is a nil pointer, which says there is no such thing.
func TestAnEmptyListIsAListInEveryAnswer(t *testing.T) {
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
	var status map[string]any
	if err := json.Unmarshal([]byte(got), &status); err != nil {
		t.Fatal(err)
	}
	if active, ok := status["active"].([]any); !ok || len(active) != 0 {
		t.Errorf("shield_status with nothing in force answered active %v, not []", status["active"])
	}
	for _, op := range srv.Operations() {
		if op.Writes || op.Publishes {
			continue
		}
		tool := "quilzo_read"
		if strings.HasPrefix(op.Name, "check") {
			tool = "quilzo_check"
		}
		text, e := callTool(t, srv, tool, op.Name, map[string]any{})
		if e != nil || !json.Valid([]byte(text)) {
			continue
		}
		var doc any
		_ = json.Unmarshal([]byte(text), &doc)
		if path := nullIn(doc, ""); path != "" {
			t.Errorf("%s answered null at %s: %.160s", op.Name, path, text)
		}
	}
}

// nullIn is where in a decoded document a null is, or "".
func nullIn(v any, at string) string {
	switch t := v.(type) {
	case nil:
		return at + " "
	case map[string]any:
		for k, x := range t {
			if p := nullIn(x, at+"."+k); p != "" {
				return p
			}
		}
	case []any:
		for i, x := range t {
			if p := nullIn(x, fmt.Sprintf("%s[%d]", at, i)); p != "" {
				return p
			}
		}
	}
	return ""
}
