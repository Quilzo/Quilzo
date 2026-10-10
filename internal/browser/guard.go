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
func Guard(ctx context.Context, b *cdp.Browser, p *cdp.Page, rule Rule, proxyUser, proxyPass string, refused func(Refusal)) (func(), error) {
	evs, cancel := b.Subscribe(func(e cdp.Event) bool {
		return e.SessionID == p.Session && (e.Method == "Fetch.requestPaused" || e.Method == "Fetch.authRequired")
	})
	if err := p.Call(ctx, "Fetch.enable", map[string]any{
		"patterns":           []map[string]any{{"urlPattern": "*", "requestStage": "Request"}},
		"handleAuthRequests": true,
	}, nil); err != nil {
		cancel()
		return nil, err
	}
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
				decide(gctx, p, e, rule, proxyUser, proxyPass, refused)
			}
		}
	}()
	return func() {
		stop()
		cancel()
		wg.Wait()
	}, nil
}

func decide(ctx context.Context, p *cdp.Page, e cdp.Event, rule Rule, user, pass string, refused func(Refusal)) {
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
		_ = p.Call(ctx, "Fetch.continueWithAuth", map[string]any{"requestId": a.RequestID, "authChallengeResponse": answer}, nil)
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
			_ = p.Call(ctx, "Fetch.failRequest", map[string]any{"requestId": r.RequestID, "errorReason": "BlockedByClient"}, nil)
			return
		}
		_ = p.Call(ctx, "Fetch.continueRequest", map[string]any{"requestId": r.RequestID}, nil)
	}
}
