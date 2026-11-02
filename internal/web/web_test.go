// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/websearch"
)

func reader(w *agent.Web, caps ...string) *agent.Session {
	if len(caps) == 0 {
		caps = agent.WebCapabilities
	}
	return agent.NewSession(agent.Manifest{Name: "reader", Kind: agent.KindTask, Purpose: "read the web",
		Capabilities: caps, Autonomy: agent.AutonomyDraft, Web: w,
		Budget: agent.Budget{Steps: 10, Tools: 1, Duration: agent.Duration(time.Minute)}}, nil)
}

func do(t *testing.T, d *Driver, op string, in map[string]any) (string, error) {
	t.Helper()
	return d.Perform(func(context.Context, agent.Action) (string, error) { return "", errors.New("not the web's") })(
		context.Background(), agent.Action{Op: op, Input: in})
}

const bakery = `<!doctype html><html lang=en><head><title>Hart's Bakery</title>
<meta name=description content="Bread under the arches"></head><body>
<nav><a href="/">Home</a></nav><main><h1>Our loaves</h1><p>Sourdough, <strong>rye</strong> and buns.</p>
<ul><li>Open from 7</li><li>Closed Mondays</li></ul><script>steal()</script>
<form action="/order"><input name=q></form><a href="https://maps.example/arches">Find us</a></main></body></html>`

// A page is read as a person reads it, its words and links, without its
// script or form; a host not declared is not read, nor one a redirect led
// to; and reading taints the run.
func TestAPageIsReadAsAPersonReadsIt(t *testing.T) {
	s := reader(&agent.Web{Fetch: []string{"hartsbakery.co.uk"}})
	var asked []string
	d := &Driver{Session: s, Get: func(_ context.Context, address string) (Page, error) {
		asked = append(asked, address)
		if strings.Contains(address, "/moved") {
			return Page{URL: "https://elsewhere.example/landed", ContentType: "text/html", Body: []byte(bakery)}, nil
		}
		return Page{URL: address, ContentType: "text/html; charset=utf-8", Body: []byte(bakery)}, nil
	}}
	out, err := do(t, d, "web_fetch", map[string]any{"url": "https://hartsbakery.co.uk/loaves"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"read https://hartsbakery.co.uk/loaves (text/html", "# Hart's Bakery", "Bread under the arches",
		"# Our loaves", "Sourdough, **rye** and buns.", "- Open from 7", "https://maps.example/arches"} {
		if !strings.Contains(out, want) {
			t.Errorf("the page does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "steal()") {
		t.Error("the page's script was read as its words")
	}
	if !s.Tainted() {
		t.Error("reading the web did not taint the run")
	}
	for _, bad := range []struct{ url, want string }{
		{"https://evil.example/", "not a host this agent may read"},
		{"http://hartsbakery.co.uk/", "https addresses only"},
		{"https://user:pw@hartsbakery.co.uk/", "user name or password"},
		{"https://hartsbakery.co.uk/moved", "sent it on to elsewhere.example"},
		{"nonsense", "not an address"},
	} {
		if _, err := do(t, d, "web_fetch", map[string]any{"url": bad.url}); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%s: %v", bad.url, err)
		}
	}
	for _, a := range asked {
		if strings.Contains(a, "evil.example") || strings.HasPrefix(a, "http:") {
			t.Errorf("asked for %s", a)
		}
	}
	// Any public host, when the declaration says so in as many words.
	open := &Driver{Session: reader(&agent.Web{Any: true}), Get: d.Get}
	if _, err := do(t, open, "web_fetch", map[string]any{"url": "https://anywhere.example/x"}); err != nil {
		t.Errorf("any: %v", err)
	}
}

// Text and JSON are read as they are; a picture or a PDF is said and not
// read; a long answer is cut and says so.
func TestWhatIsNotAPageIsReadAsWhatItIs(t *testing.T) {
	u := mustURL("https://api.example/v1/opening")
	if out := Render(u, "application/json", []byte(`{"open":"07:00"}`)); !strings.Contains(out, `{"open":"07:00"}`) {
		t.Errorf("%s", out)
	}
	if out := Render(u, "application/pdf", []byte("%PDF-1.7 ...")); !strings.Contains(out, "not read here") {
		t.Errorf("%s", out)
	}
	if out := Render(u, "", []byte("plain words")); !strings.Contains(out, "text/plain") || !strings.Contains(out, "plain words") {
		t.Errorf("%s", out)
	}
	if out := Render(u, "text/plain", []byte(strings.Repeat("x", MaxShown+10))); !strings.Contains(out, "10 bytes more, not shown") {
		t.Errorf("a long answer was not cut: %d", len(out))
	}
}

// A search asks the configured provider with its sealed key and lists what
// it found; with none configured, it says how to set one up.
func TestASearchListsWhatItFound(t *testing.T) {
	brave, _ := websearch.Get("brave")
	var sent map[string]string
	d := &Driver{Session: reader(nil, "web_search"), Search: brave, Key: func() (string, error) { return "K", nil },
		Do: func(_ context.Context, _, _ string, _ []byte, h map[string]string) (int, []byte, error) {
			sent = h
			return 200, []byte(`{"web":{"results":[{"title":"Hart's Bakery","url":"https://hartsbakery.co.uk/","description":"Sourdough"}]}}`), nil
		}}
	out, err := do(t, d, "web_search", map[string]any{"query": "bakery bristol", "count": 3.0})
	if err != nil || !strings.Contains(out, `Brave Search found 1 for "bakery bristol"`) ||
		!strings.Contains(out, "1. Hart's Bakery\n   https://hartsbakery.co.uk/\n   Sourdough") || sent["X-Subscription-Token"] != "K" {
		t.Fatalf("%q %v %v", out, err, sent)
	}
	if !d.Session.Tainted() {
		t.Error("what a search found did not taint the run")
	}
	none := &Driver{Session: reader(nil, "web_search")}
	if _, err := do(t, none, "web_search", map[string]any{"query": "x"}); err == nil || !strings.Contains(err.Error(), "agents.search") {
		t.Errorf("%v", err)
	}
	nokey := &Driver{Session: reader(nil, "web_search"), Search: brave, Do: d.Do,
		Key: func() (string, error) { return "", errors.New("no such secret") }}
	if _, err := do(t, nokey, "web_search", map[string]any{"query": "x"}); err == nil || !strings.Contains(err.Error(), "secret set search-brave") {
		t.Errorf("%v", err)
	}
	// Not held: refused by the session before anything is sent.
	held := &Driver{Session: reader(&agent.Web{Fetch: []string{"a.example"}}, "web_fetch"), Search: brave, Do: d.Do, Key: d.Key}
	if _, err := do(t, held, "web_search", map[string]any{"query": "x"}); err == nil {
		t.Error("searched without holding web_search")
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
