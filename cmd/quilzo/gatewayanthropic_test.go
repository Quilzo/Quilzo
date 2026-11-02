// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/provider"
)

// The three packages name the protocols alike: a profile's wire is what a
// route checks against and what the model speaks.
func TestTheWiresAreNamedAlike(t *testing.T) {
	for _, names := range [][3]string{
		{provider.WireAnthropic, assist.WireAnthropic, gateway.WireAnthropic},
		{provider.WireOpenAI, assist.WireOpenAI, gateway.WireOpenAI},
	} {
		if names[0] != names[1] || names[0] != names[2] {
			t.Errorf("the protocols' names differ between packages: %v", names)
		}
	}
}

// Anthropic is in the catalogue, spoken natively: its host and nothing
// else, its key in x-api-key, the version this speaks.
func TestAnthropicIsReachedNatively(t *testing.T) {
	root := demoStore(t)
	t.Setenv("QUILZO_SECRET_ANTHROPIC", "sk-ant-test")
	m, err := routeModel(root, gateway.Route{Name: "claude", Provider: "anthropic", Model: "claude-test", KeySecret: "anthropic"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Wire != assist.WireAnthropic || m.Host != "api.anthropic.com" || m.BaseURL != "https://api.anthropic.com/v1" ||
		m.Auth != "header:x-api-key" || m.Headers["anthropic-version"] != assist.AnthropicVersion {
		t.Fatalf("%+v", m)
	}
}

// A route through a provider that speaks the Messages API goes the whole
// way: added with what Anthropic's models take, built, and called.
func TestAnAnthropicRouteIsAddedAndAnswers(t *testing.T) {
	root := demoStore(t)
	got := make(chan map[string]any, 1)
	head := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		got <- body
		head <- r.Header.Clone()
		w.Write([]byte(`{"model":"claude-test","content":[{"type":"text","text":"Hello."}],"stop_reason":"end_turn",
			"usage":{"input_tokens":12,"output_tokens":3}}`))
	}))
	defer srv.Close()
	writeProviders(t, root, `{"providers":[{"id":"claude-here","name":"Messages API here","group":"local","where":"this machine",
		"wire":"anthropic-messages","base":"`+srv.URL+`/v1","auth":"header:x-api-key","headers":{"anthropic-version":"2026-10-21"},
		"local":true,"key":"claude-here","verified":"unverified","data":{"trains":"no","retention":"none","residency":"here"}}]}`)
	t.Setenv("QUILZO_SECRET_CLAUDE_HERE", "sk-ant-here")
	for _, bad := range [][]string{
		{"--temperature", "0.2"},
		{"--top-p", "0.9"},
		{"--max-tokens-field", "max_completion_tokens"},
		{"--draws"},
		{"--effort", "huge"},
		{"--geo", "mars"},
	} {
		args := append([]string{"route", "add", "c", "--provider", "claude-here", "--model", "claude-test"}, bad...)
		if err := cmdGateway(root, args); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
	if err := cmdGateway(root, []string{"route", "add", "o", "--url", "http://localhost:11434/v1", "--model", "m",
		"--effort", "high"}); err == nil || !strings.Contains(err.Error(), "Anthropic") {
		t.Errorf("an effort on a route speaking OpenAI's chat completions: %v", err)
	}
	if err := cmdGateway(root, []string{"route", "add", "c", "--provider", "claude-here", "--model", "claude-test",
		"--effort", "low", "--geo", "us", "--server-fallback"}); err != nil {
		t.Fatal(err)
	}
	gw, cfg, err := modelGateway(root)
	if err != nil || gw == nil {
		t.Fatal(err)
	}
	if p := cfg.Routes[0].Params; p.Effort != "low" || p.Geo != "us" || !p.Fallback {
		t.Fatalf("%+v", p)
	}
	out, err := gw.For("assist").Complete(context.Background(), "be brief", "say hello")
	if err != nil || out != "Hello." {
		t.Fatalf("%q %v", out, err)
	}
	body, h := <-got, <-head
	if body["inference_geo"] != "us" || body["fallbacks"] != "default" || body["system"] != "be brief" ||
		h.Get("X-Api-Key") != "sk-ant-here" || h.Get("Anthropic-Version") != "2026-10-21" ||
		!strings.Contains(h.Get("Anthropic-Beta"), "server-side-fallback") {
		t.Errorf("%v %v", body, h)
	}
}
