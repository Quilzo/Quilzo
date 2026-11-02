// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/web"
	"github.com/quilzo/quilzo/internal/websearch"
)

// A run's reach onto the web without a browser (internal/web): reading an
// address through the client that refuses private addresses, and searching
// through the provider agents.search names, with its key sealed.

// holdsWeb reports whether a manifest holds any of the web's capabilities.
func holdsWeb(m agent.Manifest) bool {
	for _, c := range m.Capabilities {
		if agent.IsWeb(c) {
			return true
		}
	}
	return false
}

// webGet reads an address for an agent: a variable so a test can stand in
// for the web.
var webGet = func(ctx context.Context, address string) (web.Page, error) {
	c := fetch.For("agent-web")
	c.Limits = fetch.Limits{MaxBytes: web.MaxFetched, Timeout: 20 * time.Second, MaxRedirects: 3}
	r, err := c.Get(ctx, address)
	if err != nil {
		return web.Page{}, err
	}
	return web.Page{URL: r.FinalURL, ContentType: r.ContentType, Body: r.Body}, nil
}

// webSearchDo asks a search provider: a variable so a test can stand in for
// one. A provider on the operator's own network is reached there and only
// there; every other only at a public address.
var webSearchDo = func(local bool) websearch.Do {
	return func(ctx context.Context, method, address string, body []byte, headers map[string]string) (int, []byte, error) {
		c := fetch.For("agent-search")
		c.Limits = fetch.Limits{MaxBytes: 2 << 20, Timeout: 20 * time.Second}
		if local {
			c.Reach = fetch.OnThisNetwork
		}
		r, err := c.Do(ctx, method, address, body, headers)
		if err != nil {
			return 0, nil, err
		}
		return r.Status, r.Body, nil
	}
}

// newWebDriver is a run's web driver.
func newWebDriver(root string, sess *agent.Session) *web.Driver {
	d := &web.Driver{Session: sess, Get: webGet}
	cfg := mustConfig(root)
	if p, ok := websearch.Get(strings.TrimSpace(cfg.Raw("agents.search"))); ok {
		d.Search, d.Do, d.Base = p, webSearchDo(p.Local), cfg.Raw("agents.search_url")
		d.Key = func() (string, error) { return readSecret(root, p.Secret()) }
	}
	return d
}
