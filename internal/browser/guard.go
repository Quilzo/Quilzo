// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/cdp"
)

// Every request a page makes, decided as it is made.
//
// The box's proxy already refuses a host the manifest does not name, and
// it sees only the host. This sees the request: its address, its method,
// and what made it (the page, a script, an image, a form). So it can hold
// the line Chrome's own agent design calls origin sets: a host the agent
// may read is only read from, and data goes only to a host it may write
// to. A form posted to a read host, a beacon to a host nobody named, an
// image whose address carries what the page knows: each is refused here,
// before it leaves, whatever the model wanted.
//
// Requests are paused at the browser (the DevTools Fetch domain) and each
// one is continued or failed by this process. The page cannot see the rule,
// change it, or make a request that is not paused.

// Request is one request a page is about to make.
type Request struct {
	URL    *url.URL
	Method string
	// Kind is what made it: Document, Script, Image, XHR, Fetch, Form…
	Kind string
}

// Rule decides a request: nil lets it go, an error refuses it, with why.
type Rule func(Request) error

// Hosts is the rule an agent's declaration makes: read hosts may be read,
// write hosts may also be sent to. Hosts are exact names, as everywhere in
// a manifest; a scheme other than https is refused.
type Hosts struct {
	Read, Write []string
	// Plain allows http as well as https. For tests on loopback only.
	Plain bool
}

// readOnly are the methods that only read.
var readOnly = map[string]bool{"GET": true, "HEAD": true}

// Rule is the hosts as a Rule.
func (h Hosts) Rule() Rule {
	read, write := map[string]bool{}, map[string]bool{}
	for _, x := range h.Read {
		read[strings.ToLower(x)] = true
	}
	for _, x := range h.Write {
		write[strings.ToLower(x)] = true
		read[strings.ToLower(x)] = true
	}
	return func(r Request) error {
		switch r.URL.Scheme {
		case "data", "blob", "about":
			// Nothing leaves: the content is already here.
			return nil
		case "https":
		case "http":
			if !h.Plain {
				return fmt.Errorf("%s is plain http; an agent's browser uses https only", r.URL.Redacted())
			}
		default:
			return fmt.Errorf("%s: an agent's browser does not use %s", r.URL.Redacted(), r.URL.Scheme)
		}
		host := strings.ToLower(r.URL.Hostname())
		switch {
		case !read[host]:
			return fmt.Errorf("%s is not a host this agent may reach", host)
		case !readOnly[strings.ToUpper(r.Method)] && !write[host]:
			return fmt.Errorf("%s may be read and not sent to: a %s there would send it something", host, r.Method)
		}
		return nil
	}
}

// Refusal is a request the rule refused.
type Refusal struct {
	Request Request
	Why     string
}

// Guard pauses every request a page makes and lets it go only if rule
// allows. proxyUser and proxyPass answer the box's proxy when it asks; a
// site asking for a password is refused. Refused requests are reported to
// refused, which may be nil. Stop the guard with the returned function.
//
// A page is more than its tab. A frame from another site runs in a process
// of its own, and a worker, a service worker or a window the page opens is
// a target of its own, whose requests the tab's interception never sees. So
// every target the browser or the page starts is attached as it starts,
// held before it runs anything, and let go only once its requests pass
// here too. One that cannot be watched is never let go, and a page other
// than this one is closed. A target attached twice (a service worker is,
// from the browser and from the page) is watched on both, so it stays
// watched when the page that attached it moves on.
//
// A WebSocket is the one thing the browser does not pause: neither request
// interception nor blocking by address sees one. So the page gets none:
// WebSocket, WebSocketStream and WebTransport are taken out of every page,
// frame and worker before its own script runs, and one opened anyway is
// reported. What it could carry is what the page's own script could put in
// an address it is let read, which the rule already allows; what the agent
// types is held by the breaker.
func Guard(ctx context.Context, b *cdp.Browser, p *cdp.Page, rule Rule, proxyUser, proxyPass string, refused func(Refusal)) (func(), error) {
	g := &guard{b: b, page: p, rule: rule, user: proxyUser, pass: proxyPass, refused: refused,
		watched: map[string]bool{p.Session: true}}
	evs, cancel := b.SubscribeN(4096, func(e cdp.Event) bool {
		switch e.Method {
		case "Fetch.requestPaused", "Fetch.authRequired", "Network.webSocketCreated":
			return g.watching(e.SessionID)
		case "Target.attachedToTarget", "Target.detachedFromTarget":
			return true
		}
		return false
	})
	gctx, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-gctx.Done():
				return
			case e, ok := <-evs:
				if !ok {
					return
				}
				g.handle(gctx, e)
			}
		}
	}()
	end := func() {
		stop()
		cancel()
		wg.Wait()
		g.wg.Wait()
	}
	if err := g.watch(ctx, p.Session, "page"); err != nil {
		end()
		return nil, err
	}
	// What the browser starts on its own account (service and shared
	// workers, a window), and what this page starts (frames, workers).
	for _, session := range []string{"", p.Session} {
		if err := b.Call(ctx, session, "Target.setAutoAttach", autoAttach, nil); err != nil {
			end()
			return nil, err
		}
	}
	return end, nil
}

// autoAttach holds each new target before it runs, until it is watched.
var autoAttach = map[string]any{
	"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
	"filter": []map[string]any{{"type": "browser", "exclude": true}, {"type": "tab", "exclude": true}, {}},
}

// noSockets takes the ways to open a socket out of a page or worker, before
// its own script runs, so they cannot be put back from there.
const noSockets = `(() => { for (const k of ["WebSocket", "WebSocketStream", "WebTransport"]) {
  try { Object.defineProperty(globalThis, k, {value: undefined, writable: false, configurable: false}); } catch (e) {} } })()`

type guard struct {
	b          *cdp.Browser
	page       *cdp.Page
	rule       Rule
	user, pass string
	refused    func(Refusal)

	mu      sync.Mutex
	watched map[string]bool
	wg      sync.WaitGroup
}

func (g *guard) watching(session string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.watched[session]
}

// watch pauses every request one target makes, from here on, and takes
// sockets out of it.
func (g *guard) watch(ctx context.Context, session, kind string) error {
	g.mu.Lock()
	g.watched[session] = true
	g.mu.Unlock()
	if err := g.b.Call(ctx, session, "Fetch.enable", map[string]any{
		"patterns":           []map[string]any{{"urlPattern": "*", "requestStage": "Request"}},
		"handleAuthRequests": true,
	}, nil); err != nil {
		return err
	}
	return g.noSockets(ctx, session, kind)
}

// noSockets takes sockets out of a target and reports any opened anyway.
func (g *guard) noSockets(ctx context.Context, session, kind string) error {
	// Told about every socket, so one that gets past is reported. Nothing
	// is kept of the traffic itself.
	if err := g.b.Call(ctx, session, "Network.enable", map[string]any{"maxTotalBufferSize": 0, "maxResourceBufferSize": 0}, nil); err != nil {
		return err
	}
	switch kind {
	case "page", "iframe":
		// In every document the target loads from here on, before its
		// script, and in the one it has now.
		return g.b.Call(ctx, session, "Page.addScriptToEvaluateOnNewDocument",
			map[string]any{"source": noSockets, "runImmediately": true}, nil)
	default:
		// A worker is held before it runs: this is its first script.
		return g.b.Call(ctx, session, "Runtime.evaluate", map[string]any{"expression": noSockets}, nil)
	}
}

func (g *guard) handle(ctx context.Context, e cdp.Event) {
	switch e.Method {
	case "Target.attachedToTarget":
		var a struct {
			SessionID  string `json:"sessionId"`
			TargetInfo struct {
				TargetID string `json:"targetId"`
				Type     string `json:"type"`
				URL      string `json:"url"`
			} `json:"targetInfo"`
		}
		if json.Unmarshal(e.Params, &a) != nil {
			return
		}
		// Each on its own, so the requests already paused are decided
		// while a new target is set up.
		parent := e.SessionID
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			actx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			g.attached(actx, parent, a.SessionID, a.TargetInfo.TargetID, a.TargetInfo.Type, a.TargetInfo.URL)
		}()
	case "Target.detachedFromTarget":
		var d struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(e.Params, &d) == nil && d.SessionID != g.page.Session {
			g.mu.Lock()
			delete(g.watched, d.SessionID)
			g.mu.Unlock()
		}
	case "Network.webSocketCreated":
		var w struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(e.Params, &w) == nil && g.refused != nil {
			u, err := url.Parse(w.URL)
			if err != nil {
				u = &url.URL{}
			}
			g.refused(Refusal{Request: Request{URL: u, Method: "GET", Kind: "WebSocket"},
				Why: "a page opened a WebSocket, which an agent's browser does not allow and cannot pause"})
		}
	default:
		decide(ctx, g.b, e, g.rule, g.user, g.pass, g.refused)
	}
}

// attached is a target the browser holds until this lets it run. parent is
// the session it was attached through, "" for the browser's own.
func (g *guard) attached(ctx context.Context, parent, session, target, kind, at string) {
	if kind == "page" {
		if target != g.page.Target {
			// A window this page did not get to be: there is one page,
			// and it is the one attached on purpose.
			_ = g.b.Call(ctx, "", "Target.closeTarget", map[string]any{"targetId": target}, nil)
		}
		// This page, attached again from the browser: the first
		// attachment watches it.
		_ = g.b.Call(ctx, parent, "Target.detachFromTarget", map[string]any{"sessionId": session}, nil)
		return
	}
	hold := func(err error) {
		// Left held: what cannot be watched does not run.
		if g.refused != nil {
			u, _ := url.Parse(at)
			if u == nil {
				u = &url.URL{}
			}
			g.refused(Refusal{Request: Request{URL: u, Kind: kind},
				Why: fmt.Sprintf("a %s the page started could not be watched, so it was not run (%v)", kind, err)})
		}
	}
	if kind == "worker" {
		// A dedicated worker's requests are its page's, and paused there
		// (TestNothingThePageStartsGoesUnwatched shows it); it has no
		// interception of its own to turn on, and starts nothing.
		if err := g.b.Call(ctx, session, "Runtime.evaluate", map[string]any{"expression": noSockets}, nil); err != nil {
			hold(err)
			return
		}
		_ = g.b.Call(ctx, session, "Runtime.runIfWaitingForDebugger", nil, nil)
		return
	}
	if err := g.watch(ctx, session, kind); err != nil {
		hold(err)
		return
	}
	// What it starts in turn is held the same way. A frame can start
	// frames, so one whose own starts cannot be held is not run either; a
	// worker may not have the command at all.
	if err := g.b.Call(ctx, session, "Target.setAutoAttach", autoAttach, nil); err != nil && kind == "iframe" {
		hold(err)
		return
	}
	_ = g.b.Call(ctx, session, "Runtime.runIfWaitingForDebugger", nil, nil)
}

func decide(ctx context.Context, b *cdp.Browser, e cdp.Event, rule Rule, user, pass string, refused func(Refusal)) {
	call := func(method string, params map[string]any) {
		_ = b.Call(ctx, e.SessionID, method, params, nil)
	}
	switch e.Method {
	case "Fetch.authRequired":
		var a struct {
			RequestID     string `json:"requestId"`
			AuthChallenge struct {
				Source string `json:"source"`
			} `json:"authChallenge"`
		}
		if json.Unmarshal(e.Params, &a) != nil {
			return
		}
		answer := map[string]any{"response": "CancelAuth"}
		if a.AuthChallenge.Source == "Proxy" && user != "" {
			answer = map[string]any{"response": "ProvideCredentials", "username": user, "password": pass}
		}
		call("Fetch.continueWithAuth", map[string]any{"requestId": a.RequestID, "authChallengeResponse": answer})
	case "Fetch.requestPaused":
		var r struct {
			RequestID string `json:"requestId"`
			Request   struct {
				URL    string `json:"url"`
				Method string `json:"method"`
			} `json:"request"`
			ResourceType string `json:"resourceType"`
		}
		if json.Unmarshal(e.Params, &r) != nil {
			return
		}
		u, err := url.Parse(r.Request.URL)
		req := Request{URL: u, Method: r.Request.Method, Kind: r.ResourceType}
		if err == nil {
			err = rule(req)
		}
		if err != nil {
			if refused != nil {
				refused(Refusal{Request: req, Why: err.Error()})
			}
			call("Fetch.failRequest", map[string]any{"requestId": r.RequestID, "errorReason": "BlockedByClient"})
			return
		}
		call("Fetch.continueRequest", map[string]any{"requestId": r.RequestID})
	}
}
