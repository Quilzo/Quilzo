// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentbox

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/mcp"
)

func manifest(steps int) agent.Manifest {
	return agent.Manifest{Name: "worker", Kind: agent.KindTask, Purpose: "work",
		Capabilities: []string{"list_pages", "read_page"}, Autonomy: agent.AutonomyDraft,
		Budget: agent.Budget{Steps: steps, Tools: 1, Duration: agent.Duration(time.Hour)}}
}

// A program is the run's decider: each call is one step through the run's
// gate, and returns what the step returned; a call the manifest refuses
// returns the refusal; the program ending ends the run.
func TestAProgramDecidesThroughTheRunsGate(t *testing.T) {
	b := NewBridge()
	s := agent.NewSession(manifest(5), nil)
	r := agent.Runner{Decide: b.Decide, Perform: func(_ context.Context, a agent.Action) (string, error) {
		if a.Op == "read_page" {
			return "", errors.New("no such page")
		}
		return "did " + a.Op, nil
	}}
	var trace agent.Trace
	done := make(chan struct{})
	go func() {
		trace, _ = r.Run(context.Background(), s, "goal")
		b.Stop(trace.Stopped)
		close(done)
	}()
	ctx := context.Background()
	if rep, err := b.Call(ctx, agent.Action{Op: "list_pages"}); err != nil || rep.Body != "did list_pages" || rep.Refused {
		t.Fatalf("an allowed call: %+v %v", rep, err)
	}
	if rep, _ := b.Call(ctx, agent.Action{Op: "publish"}); !rep.Refused || !strings.Contains(rep.Body, "refused") {
		t.Fatalf("a refused call: %+v", rep)
	}
	if rep, _ := b.Call(ctx, agent.Action{Op: "read_page"}); !rep.Failed {
		t.Fatalf("a failed call: %+v", rep)
	}
	b.Finish("all done")
	<-done
	if !trace.Complete || trace.Answer != "all done" || len(trace.Steps) != 4 {
		t.Fatalf("trace: complete %v answer %q steps %d", trace.Complete, trace.Answer, len(trace.Steps))
	}
	if _, err := b.Call(ctx, agent.Action{Op: "list_pages"}); err == nil {
		t.Fatal("a call after the run ended was taken")
	}
}

// A budget spent on a call ends the run, and that call is told why.
func TestTheCallThatSpendsTheBudgetIsTold(t *testing.T) {
	b := NewBridge()
	s := agent.NewSession(manifest(1), nil)
	r := agent.Runner{Decide: b.Decide, Perform: func(context.Context, agent.Action) (string, error) { return "ok", nil }}
	go func() {
		tr, _ := r.Run(context.Background(), s, "goal")
		b.Stop(tr.Stopped)
	}()
	if rep, _ := b.Call(context.Background(), agent.Action{Op: "list_pages"}); rep.Body != "ok" {
		t.Fatalf("%+v", rep)
	}
	rep, err := b.Call(context.Background(), agent.Action{Op: "list_pages"})
	if err != nil || !rep.Refused || !strings.Contains(rep.Body, "budget") {
		t.Fatalf("the over-budget call: %+v %v", rep, err)
	}
	if _, err := b.Call(context.Background(), agent.Action{Op: "list_pages"}); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("after the run: %v", err)
	}
}

func proxyFor(t *testing.T, allow map[string]bool) (*Proxy, func() []Egress, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s%s", r.Host, r.URL.Path)
	}))
	t.Cleanup(upstream.Close)
	var mu sync.Mutex
	var log []Egress
	p := &Proxy{
		Secret: "s3cret",
		Allow: func(host string, port int) error {
			if allow[host] {
				return nil
			}
			return fmt.Errorf("%s is not one of this agent's hosts", host)
		},
		Dial: func(ctx context.Context, host string, port int) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", upstream.Listener.Addr().String())
		},
		Record: func(e Egress) { mu.Lock(); log = append(log, e); mu.Unlock() },
	}
	snapshot := func() []Egress {
		mu.Lock()
		defer mu.Unlock()
		return append([]Egress(nil), log...)
	}
	return p, snapshot, upstream
}

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestTheProxyReachesOnlyTheManifestsHosts(t *testing.T) {
	// 10.0.0.1 is in the allow list here, as a manifest naming an address
	// would put it: an address is still refused, since a manifest names hosts.
	p, log, _ := proxyFor(t, map[string]bool{"api.example.com": true, "10.0.0.1": true})
	srv := httptest.NewServer(p)
	defer srv.Close()

	get := func(target, auth string) *http.Response {
		req, _ := http.NewRequest("GET", srv.URL, nil)
		req.URL.Opaque = target // absolute-form, as a client speaking to a proxy sends it
		req.Host = strings.TrimPrefix(strings.SplitN(target, "/", 4)[2], "")
		if auth != "" {
			req.Header.Set("Proxy-Authorization", auth)
		}
		res, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	// Without the run's credential, nothing.
	if res := get("http://api.example.com/x", ""); res.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("no credential: %d", res.StatusCode)
	}
	if res := get("http://api.example.com/x", basic("run", "wrong")); res.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("a wrong credential: %d", res.StatusCode)
	}
	ok := get("http://api.example.com/x", basic("run", "s3cret"))
	body, _ := io.ReadAll(ok.Body)
	if ok.StatusCode != 200 || !strings.Contains(string(body), "/x") {
		t.Fatalf("an allowed host: %d %s", ok.StatusCode, body)
	}
	for _, target := range []string{"http://evil.example.com/", "http://10.0.0.1/", "http://api.example.com:8080/"} {
		if res := get(target, basic("run", "s3cret")); res.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", target, res.StatusCode)
		}
	}
	allowed, refused := 0, 0
	for _, e := range log() {
		if e.Allowed {
			allowed++
		} else {
			refused++
		}
	}
	if allowed != 1 || refused != 3 {
		t.Fatalf("recorded %d allowed and %d refused: %+v", allowed, refused, log())
	}
}

func TestTheProxyTunnelsOnlyToTheManifestsHosts(t *testing.T) {
	p, log, _ := proxyFor(t, map[string]bool{"api.example.com": true})
	srv := httptest.NewServer(p)
	defer srv.Close()
	connect := func(target string) (int, net.Conn) {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", target, target, basic("run", "s3cret"))
		br := bufio.NewReader(c)
		res, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, &bufConn{Conn: c, r: br}
	}
	if code, c := connect("evil.example.com:443"); code != http.StatusForbidden {
		c.Close()
		t.Fatalf("a tunnel to another host: %d", code)
	}
	code, c := connect("api.example.com:443")
	if code != 200 {
		t.Fatalf("a tunnel to an allowed host: %d", code)
	}
	// Through the tunnel: here a plain request, standing in for TLS.
	fmt.Fprintf(c, "GET /through HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n")
	body, _ := io.ReadAll(c)
	c.Close()
	if !strings.Contains(string(body), "/through") {
		t.Fatalf("through the tunnel: %s", body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(log()) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if l := log(); len(l) != 2 || l[1].Up == 0 || l[1].Down == 0 {
		t.Fatalf("recorded %+v", l)
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestTheModelEndpointAnswersForTheRunOnly(t *testing.T) {
	var gotSystem, gotUser string
	h := &Models{Secret: "s", Name: "quilzo", Complete: func(_ context.Context, system, user string) (string, int, int, error) {
		gotSystem, gotUser = system, user
		if strings.Contains(user, "spend") {
			return "", 0, 0, errors.New("agent:worker has spent its budget")
		}
		return "the answer", 12, 3, nil
	}}
	srv := httptest.NewServer(h)
	defer srv.Close()
	post := func(auth, body string) (*http.Response, string) {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/chat/completions", strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		return res, string(b)
	}
	msgs := `{"model":"anything","messages":[{"role":"system","content":"be brief"},{"role":"user","content":[{"type":"text","text":"hello"}]}]}`
	if res, _ := post("", msgs); res.StatusCode != 401 {
		t.Fatalf("no credential: %d", res.StatusCode)
	}
	if res, _ := post("wrong", msgs); res.StatusCode != 401 {
		t.Fatalf("a wrong credential: %d", res.StatusCode)
	}
	res, body := post("s", msgs)
	if res.StatusCode != 200 || !strings.Contains(body, `"content":"the answer"`) || !strings.Contains(body, `"total_tokens":15`) {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	if gotSystem != "be brief\n" || gotUser != "user: hello\n" {
		t.Fatalf("flattened to %q / %q", gotSystem, gotUser)
	}
	res, body = post("s", strings.Replace(msgs, `"model"`, `"stream":true,"model"`, 1))
	if !strings.HasPrefix(body, "data: ") || !strings.Contains(body, "[DONE]") || res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("streamed: %s", body)
	}
	if res, body := post("s", `{"messages":[{"role":"user","content":"spend"}]}`); res.StatusCode != 429 || !strings.Contains(body, "budget") {
		t.Fatalf("over budget: %d %s", res.StatusCode, body)
	}
	if res, _ := post("s", `{"messages":[{"role":"system","content":"x"}]}`); res.StatusCode != 400 {
		t.Fatalf("only a system prompt: %d", res.StatusCode)
	}
}

// The run's interface offers the manifest's capabilities and tools, and
// each call is a step.
func TestTheRunsInterfaceIsTheManifest(t *testing.T) {
	m := manifest(5)
	m.Tools = []agent.Tool{{Name: "create_issue", Host: "tracker.example", Purpose: "file what you find"}}
	b := NewBridge()
	srv := RunServer(b, m, []mcp.Operation{{Name: "list_pages", Summary: "list the pages", NeedsRole: "reader"},
		{Name: "publish", Summary: "make the draft live", Writes: true}}, "test")
	names := map[string]mcp.Operation{}
	for _, op := range srv.Operations() {
		names[op.Name] = op
	}
	if len(names) != 4 || names["list_pages"].Summary != "list the pages" || !names["tool:create_issue"].Writes ||
		!strings.Contains(names["publish"].Summary, "does not hold") || !names["publish"].Writes {
		t.Fatalf("%+v", names)
	}
	go func() {
		a, _ := b.Decide(context.Background(), "", nil)
		if a.Op != "list_pages" {
			t.Errorf("decided %+v", a)
		}
		_, _ = b.Decide(context.Background(), "", []agent.Observation{{Body: "refused: not now", Trusted: true}})
	}()
	req := mcp.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call",
		Params: json.RawMessage(`{"name":"quilzo_read","arguments":{"operation":"list_pages"}}`)}
	res := srv.Handle(req)
	if res == nil || res.Error == nil || res.Error.Code != mcp.CodeRefused || !strings.Contains(res.Error.Message, "not now") {
		t.Fatalf("%+v", res)
	}
}
