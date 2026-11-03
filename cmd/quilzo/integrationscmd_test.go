// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
)

// faulty is a 2026-07-28 server whose tools fail in each way a tool can:
// "fail" runs and reports that it failed, "broken" is answered with a
// JSON-RPC error, and "file" works.
type faulty struct{}

func (faulty) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	json.NewDecoder(r.Body).Decode(&msg)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case msg.Method == "tools/list":
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","tools":[`+
			`{"name":"fail","description":"Fails.","inputSchema":{"type":"object"}},`+
			`{"name":"broken","description":"Breaks.","inputSchema":{"type":"object"}},`+
			`{"name":"file","description":"Files.","inputSchema":{"type":"object"}}]}}`, msg.ID)
	case msg.Params.Name == "fail":
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","isError":true,`+
			`"content":[{"type":"text","text":"no such project"}]}}`, msg.ID)
	case msg.Params.Name == "broken":
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"the tracker fell over"}}`, msg.ID)
	default:
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","content":[{"type":"text","text":"filed"}]}}`, msg.ID)
	}
}

// `quilzo integrations call` fails when the call did, and records what
// happened as what it was.
//
// A tool that ran and reported failing exited 0 and was recorded as a
// success, because the client folds the tool's error into the text it
// returns; and a call the far side failed was recorded as "denied", which
// is the word for a refusal here, so a log reader looking for refused
// calls found outages and one looking for failures found nothing.
func TestAnIntegrationCallFailsWhenTheToolDid(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, _ := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", dana)
	mcpTransport = viaHandler(faulty{})
	t.Cleanup(func() { mcpTransport = nil })
	set := agent.Integrations{Declared: []agent.Integration{{Name: "tracker", Kind: agent.IntegrationMCP, Enabled: true,
		Purpose: "file issues", Endpoint: "tracker.example", Uses: []string{"fail", "broken", "file"}}}}
	if err := saveJSON(integrationsPath(root), set); err != nil {
		t.Fatal(err)
	}
	outcome := func() audit.Outcome {
		t.Helper()
		evs, err := audit.Read(auditPath(root))
		if err != nil {
			t.Fatal(err)
		}
		for i := len(evs) - 1; i >= 0; i-- {
			if evs[i].Action == "integration.call" {
				return evs[i].Outcome
			}
		}
		t.Fatal("the call was not recorded")
		return ""
	}
	for _, c := range []struct {
		tool  string
		fails bool
		want  audit.Outcome
	}{
		{"file", false, audit.Success},
		{"fail", true, audit.Failure},
		{"broken", true, audit.Failure},
		// Not one this install agreed to: that is a refusal.
		{"delete_everything", true, audit.Denied},
	} {
		err := integrationsCall(root, []string{"tracker", c.tool})
		if (err != nil) != c.fails {
			t.Errorf("%s: %v", c.tool, err)
		}
		if got := outcome(); got != c.want {
			t.Errorf("%s was recorded as %s, not %s", c.tool, got, c.want)
		}
	}
}
