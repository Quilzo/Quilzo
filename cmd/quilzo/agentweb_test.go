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
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/web"
	"github.com/quilzo/quilzo/internal/websearch"
)

// A model searches the web through the provider agents.search names, with
// its sealed key, and reads what it found, through a real run.
func TestAnAgentSearchesAndReadsTheWeb(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	setStaffConfig(t, root, "agents.search", "brave")
	t.Setenv("QUILZO_SECRET_SEARCH_BRAVE", "brave-key")

	var mu sync.Mutex
	var searched, read []string
	oldDo, oldGet := webSearchDo, webGet
	webSearchDo = func(local bool) websearch.Do {
		return func(_ context.Context, method, address string, _ []byte, h map[string]string) (int, []byte, error) {
			mu.Lock()
			searched = append(searched, method+" "+address+" "+h["X-Subscription-Token"])
			mu.Unlock()
			return 200, []byte(`{"web":{"results":[{"title":"Hart's Bakery","url":"https://hartsbakery.co.uk/loaves","description":"Sourdough"}]}}`), nil
		}
	}
	webGet = func(_ context.Context, address string) (web.Page, error) {
		mu.Lock()
		read = append(read, address)
		mu.Unlock()
		return web.Page{URL: address, ContentType: "text/html",
			Body: []byte(`<title>Loaves</title><main><h1>Loaves</h1><p>Rye is back on Fridays.</p></main>`)}, nil
	}
	t.Cleanup(func() { webSearchDo, webGet = oldDo, oldGet })

	plan := []string{
		`{"op":"web_search","input":{"query":"bakery bristol rye"}}`,
		`{"op":"web_fetch","input":{"url":"https://hartsbakery.co.uk/loaves"}}`,
	}
	turn := 0
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		choice := `{"op":"done","say":"rye on Fridays"}`
		if turn < len(plan) {
			choice = plan[turn]
		}
		turn++
		mu.Unlock()
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": choice}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(model.Close)
	t.Setenv("QUILZO_MODEL_URL", model.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")

	m := agent.Manifest{Name: "scout", Kind: agent.KindTask, Purpose: "Find out what local bakeries bake",
		Capabilities: []string{"web_search", "web_fetch"}, Autonomy: agent.AutonomyDraft,
		Web:    &agent.Web{Fetch: []string{"hartsbakery.co.uk"}},
		Budget: agent.Budget{Steps: 6, Tools: 1, Duration: agent.Duration(time.Minute)}}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	_, out, err := runAgentKeptBy(context.Background(), root, "scout", "what do bakeries in Bristol bake on Fridays?",
		true, false, asAdmin("dana"))
	if err != nil || !out.Trace.Complete {
		t.Fatalf("%v\n%s", err, describeRun(out.Trace))
	}
	results := map[string]string{}
	for _, st := range out.Trace.Steps {
		if st.Err != "" {
			t.Fatalf("%s failed: %s\n%s", st.Action.Op, st.Err, describeRun(out.Trace))
		}
		results[st.Action.Op] += st.Result
	}
	if !strings.Contains(results["web_search"], "1. Hart's Bakery") || !strings.Contains(results["web_fetch"], "Rye is back on Fridays.") {
		t.Fatalf("%+v", results)
	}
	if len(searched) != 1 || !strings.HasPrefix(searched[0], "GET https://api.search.brave.com/res/v1/web/search?q=bakery+bristol+rye") ||
		!strings.HasSuffix(searched[0], " brave-key") || len(read) != 1 {
		t.Fatalf("searched %v, read %v", searched, read)
	}
	// The key is not in what the run kept.
	if strings.Contains(describeRun(out.Trace), "brave-key") {
		t.Fatal("the provider's key is in the run's record")
	}
}

// A provider that is not one, or a SearXNG not at an https address, is
// refused when it is set.
func TestTheSearchSettingsAreChecked(t *testing.T) {
	root := demoStore(t)
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"agents.search": "bing", "agents.search_url": "http://search.internal"} {
		if err := cfg.Set(k, v, "", "test"); err == nil {
			t.Errorf("%s=%s was accepted", k, v)
		}
	}
	for k, v := range map[string]string{"agents.search": "searxng", "agents.search_url": "https://search.internal"} {
		if err := cfg.Set(k, v, "", "test"); err != nil {
			t.Errorf("%s=%s: %v", k, v, err)
		}
	}
}
