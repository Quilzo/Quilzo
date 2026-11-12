// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/connect"
	"github.com/quilzo/quilzo/internal/fetch"
)

// quilzo connect provider discover NAME https://SERVER/mcp
//
// A remote MCP server that asks people to sign in, made a provider people
// connect their own accounts at: who authorises it read from what it
// publishes, this installation registered there as a public client when the
// server takes registrations, or the client id given. Then an integration
// naming the connection reaches it as each person (internal/connect
// discover.go).

// discoverGet and discoverPost go through the checked client: https, no
// private addresses, bounded answers.
var discoverGet connect.Getter = func(ctx context.Context, u string) (int, http.Header, []byte, error) {
	c := fetch.For("accounts")
	c.Limits = fetch.Limits{MaxBytes: 64 << 10, Timeout: 15 * time.Second, MaxRedirects: -1}
	res, err := c.Do(ctx, http.MethodGet, u, nil, map[string]string{"Accept": "application/json"})
	if err != nil {
		return 0, nil, nil, err
	}
	return res.Status, res.Header, res.Body, nil
}

var discoverPost connect.JSONPoster = func(ctx context.Context, u string, body []byte) (int, []byte, error) {
	c := fetch.For("accounts")
	c.Limits = fetch.Limits{MaxBytes: 64 << 10, Timeout: 15 * time.Second, MaxRedirects: -1}
	res, err := c.Do(ctx, http.MethodPost, u, body, map[string]string{"Content-Type": "application/json", "Accept": "application/json"})
	if err != nil {
		return 0, nil, err
	}
	return res.Status, res.Body, nil
}

func connectDiscover(root string, caller *Caller, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("provider discover", flag.ContinueOnError)
	clientID := fs.String("client-id", "", "the client id the server's authorization server issued; registered there when empty and it takes registrations")
	title := fs.String("title", "", "what people connecting see; the server's host when empty")
	scope := fs.String("scope", "", "the scopes a connection asks for, separated by spaces; what the server lists when empty")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return errors.New("usage: quilzo connect provider discover NAME https://SERVER/mcp [--client-id ID] [--scope S] [--title T]")
	}
	// The scopes the person deciding names, when they name any: what a
	// server lists says what it offers, not what this agent will do there,
	// and with nothing to say otherwise a connection asked for exactly
	// what the list said, mcp:read alone at another Quilzo.
	asked, err := connect.Scopes(*scope)
	if err != nil {
		return err
	}
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	name, server := pos[0], pos[1]
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d, err := connect.Discover(ctx, discoverGet, server)
	if err != nil {
		return err
	}
	redirect, err := connectRedirect(root)
	if err != nil {
		return err
	}
	if len(asked) > 0 {
		d.Scopes = asked
	}
	id := strings.TrimSpace(*clientID)
	registered, byDocument := false, false
	switch {
	case id != "":
	case d.RegisterURL == "" && d.MetadataDocs:
		// A server that takes Client ID Metadata Documents and no
		// registrations, as another Quilzo's is: this installation's own
		// document is its client id. Only where nothing else would do, so
		// a server that also takes registrations is registered with as
		// before, which works for an admin it cannot reach.
		if id, err = connectDocumentURL(root); err != nil {
			return err
		}
		// And the document is one the admin can serve from there. An admin
		// at http on this machine was set up with that address as its
		// client id, which no server takes and none could read, and the
		// person learned it at the other side's sign-in page.
		if _, err := connectClientDocument(root); err != nil {
			return fmt.Errorf("%s takes a client's metadata document and no registrations, and this installation "+
				"has none to give it: %w. Give --client-id for a client registered there by hand", d.Issuer, err)
		}
		byDocument = true
	default:
		if id, err = connect.Register(ctx, discoverPost, d, connectClientName(root), redirect); err != nil {
			return err
		}
		registered = true
	}
	t := strings.TrimSpace(*title)
	if t == "" {
		t = strings.TrimPrefix(strings.TrimPrefix(d.Resource, "https://"), "www.")
	}
	p, err := connect.FromDiscovered(name, t, id, d)
	if err != nil {
		return err
	}
	unlock, err := atomicfile.Lock(connectProvidersPath(root) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	set, err := loadConnectProviders(root)
	if err != nil {
		return err
	}
	kept := []connect.Provider{p}
	for _, x := range set.Providers {
		if x.Name != name {
			kept = append(kept, x)
		}
	}
	set.Providers = kept
	if err := saveJSON(connectProvidersPath(root), set); err != nil {
		return err
	}
	record(root, caller.auditRecord("connect.provider.discovered", "/connections", audit.Success, map[string]string{
		"provider": name, "resource": d.Resource, "issuer": d.Issuer, "registered": fmt.Sprint(registered),
		"metadata_document": fmt.Sprint(byDocument)}))
	if w.JSON(p) {
		return nil
	}
	w.Human("%s%s%s: people connect at %s, for %s\n", bold, name, reset, d.Issuer, d.Resource)
	if registered {
		w.Human("  %sregistered there as a public client; PKCE protects it%s\n", dim, reset)
	}
	if byDocument {
		w.Human("  %sknown there by this installation's client metadata document, %s, which it reads from the admin%s\n",
			dim, id, reset)
	}
	if len(p.Scopes) > 0 {
		w.Human("  %sasks for %s%s\n", dim, strings.Join(p.Scopes, " "), reset)
	}
	w.Human("\nnext: an MCP integration at %s with \"connection\": %q, then each person connects in Your accounts\n",
		p.Hosts[0], name)
	return nil
}
