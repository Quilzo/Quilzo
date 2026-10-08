// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/a2a"
	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/oauthas"
	"github.com/quilzo/quilzo/internal/store"
)

// The agent interface, wired: Quilzo as the thing agents run against.
//
// Every agent, wherever it runs and whoever wrote it, reaches what Quilzo
// holds through one interface, the way every program on a machine reaches
// its files through the kernel: the same operations, the same access
// policy, the same shield and the same audit log, whether the caller is a
// person's terminal, an AI app on their laptop or an agent in somebody
// else's sandbox. This file connects the admin's /mcp to the operations
// the command line's MCP server already has (buildMCP), and gives apps a
// way to connect on a person's behalf (internal/oauthas).

func oauthDir(root string) string { return filepath.Join(root, "oauth") }

// configCache reads the settings at most every two seconds, for things
// asked on every request.
type configCache struct {
	root string
	mu   sync.Mutex
	cfg  *config.Config
	at   time.Time
}

func (c *configCache) get() *config.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg == nil || time.Since(c.at) > 2*time.Second {
		c.cfg, c.at = mustConfig(c.root), time.Now()
	}
	return c.cfg
}

// grantTokens issues apps' access tokens into the admin's token store.
type grantTokens struct{ srv *admin.Server }

func (g grantTokens) Issue(gr oauthas.Grant, role auth.Role, ttl time.Duration, now time.Time) (string, error) {
	if g.srv.Tokens == nil {
		return "", errors.New("no token store")
	}
	secret, _, err := g.srv.Tokens.IssueForGrant(gr.Principal, role, auth.Scope{}, gr.Client, gr.ID, gr.Resource, ttl, now)
	if err != nil {
		return "", err
	}
	if g.srv.SaveTokens != nil {
		if err := g.srv.SaveTokens(g.srv.Tokens); err != nil {
			return "", fmt.Errorf("the token could not be stored: %w", err)
		}
	}
	return secret, nil
}

func (g grantTokens) RevokeGrant(id string) error {
	if g.srv.Tokens == nil {
		return nil
	}
	if g.srv.Tokens.RevokeGrant(id) > 0 && g.srv.SaveTokens != nil {
		return g.srv.SaveTokens(g.srv.Tokens)
	}
	return nil
}

// admitGrant is asked before a connected app is given tokens. Somebody
// whose access ended (an identity provider's suspension, a deny) gets
// nothing more through an app they connected before it; and a lockdown
// holds connected apps too: a grant from before it that no passkey or
// single sign-on vouched for gets no new tokens.
func admitGrant(root string, sh *shieldHost) func(oauthas.Grant, time.Time) error {
	return func(g oauthas.Grant, now time.Time) error {
		if !hasStanding(root, g.Principal) {
			return errors.New("the person who connected this app no longer has access here")
		}
		if sh == nil {
			return nil
		}
		return sh.admit(auth.Credential{ID: g.ID, Issued: g.Created.Unix(), Vouched: g.Vouched})
	}
}

// appFetcher reads an app's metadata document: https, never inside the
// network, no redirects, five kilobytes at most.
func appFetcher(ctx context.Context, url string) ([]byte, time.Duration, error) {
	c := fetch.New()
	c.Purpose = "apps"
	c.UserAgent = "quilzo/1 (+agent interface)"
	c.Limits = fetch.Limits{MaxBytes: 5 << 10, Timeout: 10 * time.Second, MaxRedirects: -1}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := c.GetAccepting(ctx, url, "application/json")
	if err != nil {
		return nil, 0, err
	}
	if res.Status != http.StatusOK {
		return nil, 0, fmt.Errorf("it answered %d", res.Status)
	}
	if res.Truncated {
		return nil, 0, errors.New("it is more than five kilobytes")
	}
	// Kept an hour: within the bounds the directory applies, and long
	// enough that a busy app is not fetched on every sign-in.
	return res.Body, time.Hour, nil
}

// wireInterface connects the admin's agent interface.
func wireInterface(root string, s *store.Store, srv *admin.Server, sh *shieldHost, tplDir string) {
	cc := &configCache{root: root}
	ostore := &oauthas.Store{Dir: oauthDir(root)}
	cfgOf := func() (oauthas.Config, bool) {
		base := cc.get().Raw("admin.base_url")
		if oauthas.CheckIssuer(base) != nil {
			return oauthas.Config{}, false
		}
		_, hosts, _ := ostore.Clients()
		return oauthas.Config{Issuer: base, Hosts: hosts}, true
	}
	oa := &oauthas.Server{
		Config: func() oauthas.Config { c, _ := cfgOf(); return c },
		Store:  ostore,
		Directory: &oauthas.Directory{
			Registered: func() ([]oauthas.Client, error) { c, _, err := ostore.Clients(); return c, err },
			Fetch:      appFetcher,
		},
		Tokens: grantTokens{srv: srv},
		Admit:  admitGrant(root, sh),
		Record: func(action, principal string, d map[string]string) {
			kind, verified := audit.KindHuman, true
			if principal == "" {
				principal, kind, verified = "oauth", audit.KindService, true
			}
			record(root, audit.Record{Action: action, Resource: "/mcp", Outcome: audit.Success,
				Principal: principal, Kind: kind, Verified: verified, Detail: d})
		},
	}
	srv.Interface = &admin.AgentInterface{
		Enabled: func() bool { return cc.get().Bool("mcp.remote") },
		Config:  cfgOf,
		OAuth:   oa,
		Docs:    admin.DocURL("agent-interface"),
		Receipt: func(connection string) ([]byte, error) {
			rf, err := buildAppReceipt(root, connection, time.Now())
			if err != nil {
				return nil, err
			}
			return json.MarshalIndent(rf, "", " ")
		},
		Build: func(r *http.Request, c *mcp.Caller) (*mcp.Server, error) {
			tok, ok := c.Data.(auth.Token)
			if !ok {
				return nil, errors.New("the caller was not established")
			}
			return buildMCP(root, s, remoteCaller(tok), tplDir), nil
		},
		Offered: func(name string) bool { _, ok := gatewayOffered(root, name); return ok },
		Tasks:   func() bool { return cc.get().Bool("a2a.tasks") },
		A2A:     func(c *mcp.Caller) a2a.Host { return a2aHost(root, c) },
		Gateway: func(r *http.Request, c *mcp.Caller, name string) (*mcp.Server, error) {
			tok, ok := c.Data.(auth.Token)
			if !ok {
				return nil, errors.New("the caller was not established")
			}
			return gatewayServer(r, root, name, tok)
		},
		// Every call, reads included: an agent's reading is how it decides
		// what to do, and the record of an incident starts with what it read.
		Called: func(r *http.Request, c *mcp.Caller, tool, op string, rerr *mcp.Error) {
			record(root, appCallRecord(c, tool, op, rerr))
		},
	}
}

// appCallRecord is the record of one call at the agent interface. It is
// recorded as the app, acting for the person: the person is who it acts
// for, and the app is what acted. Which model the app runs is its own
// business and not something it reports, so the app stands in for it.
func appCallRecord(c *mcp.Caller, tool, op string, rerr *mcp.Error) audit.Record {
	outcome, d := audit.Success, map[string]string{"tool": tool, "on_behalf_of": c.Principal}
	if op != "" {
		d["operation"] = op
	}
	// Which connection: what an administrator suspends or ends when one
	// app misbehaves for one person, and what a receipt is of.
	if tok, ok := c.Data.(auth.Token); ok && tok.Grant != "" {
		d["grant"] = tok.Grant
	}
	who, model := "mcp-client", "mcp-client"
	if c.Client != "" {
		who, model = "app:"+c.Client, c.Client
	}
	if rerr != nil {
		outcome, d["error"] = audit.Denied, rerr.Message
		if rerr.Code != mcp.CodeRefused {
			outcome = audit.Failure
		}
	}
	return audit.Record{Action: "mcp.call", Resource: "/mcp", Outcome: outcome,
		Principal: who, Kind: audit.KindAI, Model: model, Verified: true, Detail: d}
}

// remoteCaller is the caller a token at the agent interface stands for:
// the person it acts for, with the token's own limits, recorded as a model
// acting, because that is what calls an interface built for agents.
func remoteCaller(tok auth.Token) *Caller {
	return &Caller{Name: tok.Principal, Role: tok.Role, Scope: tok.Resource, Limits: tok.Scope,
		Kind: audit.KindAI, Verified: true, Remote: true, Grant: tok.Grant}
}

// remoteRefusal is what the agent interface adds to the command line's
// checks: it never serves a store with no access policy, and a token an
// app was given that is too small for an operation is answered with the
// scope that would reach it, so the app can ask the person for more.
func remoteRefusal(root string, c *Caller, need auth.Role) error {
	inUse, err := policyInUse(root)
	if err != nil {
		return err
	}
	if !inUse {
		return errors.New("the agent interface serves only a store with an access policy: grant somebody a role first (quilzo auth grant)")
	}
	if c.Grant != "" && !c.Role.AtLeast(need) {
		return &mcp.ScopeError{Scope: oauthas.ScopeFor(need),
			Reason: fmt.Sprintf("this app was given %s access, and this needs %s", c.Role, need)}
	}
	return nil
}

// interfaceAddress says where the interface is, for messages.
func interfaceAddress(cfg *config.Config) string {
	if base := cfg.Raw("admin.base_url"); base != "" {
		return strings.TrimSuffix(base, "/") + "/mcp"
	}
	return "/mcp on the admin"
}
