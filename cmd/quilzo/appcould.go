// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/oauthas"
)

// Could an app do something, through one connection, and why: answered by
// the code that admits its calls. The connection's own state, then what
// admits its token on every request (the person's standing, the shield's
// suspension and lockdown), then the agent interface's own gate for the
// operation: the role the person gave the app, the shield turning the
// interface off, and the person's access. Nothing here restates a rule.

// appCouldAnswer is the answer.
type appCouldAnswer struct {
	Connection string   `json:"connection"`
	App        string   `json:"app"`
	For        string   `json:"for"`
	What       string   `json:"what"`
	Could      bool     `json:"could"`
	Why        string   `json:"why,omitempty"`
	Then       []string `json:"then,omitempty"`
}

// appCould asks whether the app on a connection could perform op, on page
// when one is named.
func appCould(root, connection, op, page string, now time.Time) (appCouldAnswer, error) {
	grants, err := (&oauthas.Store{Dir: oauthDir(root)}).Grants()
	if err != nil {
		return appCouldAnswer{}, err
	}
	var g *oauthas.Grant
	for i := range grants {
		if grants[i].ID == connection {
			g = &grants[i]
		}
	}
	if g == nil {
		return appCouldAnswer{}, fmt.Errorf("no app connection is %q; quilzo apps list shows them", connection)
	}
	a := appCouldAnswer{Connection: g.ID, App: nonEmpty(g.ClientName, g.Client), For: g.Principal, What: op}
	no := func(why string) (appCouldAnswer, error) { a.Why = why; return a, nil }

	switch {
	case !g.Ended.IsZero():
		return no("the connection was ended: " + nonEmpty(g.EndedWhy, "by "+g.EndedBy))
	case !now.Before(g.Expires):
		return no("the connection expired; the person has to connect the app again")
	}
	if !mustConfig(root).Bool("mcp.remote") {
		return no("the agent interface is off (quilzo config set mcp.remote true)")
	}
	if err := admitGrant(root, newShieldHost(root))(*g, now); err != nil {
		return no(err.Error())
	}

	// The token the connection's calls carry, made as the live path makes
	// it, and the interface it is served.
	_, tok, err := (&auth.TokenStore{}).IssueForGrant(g.Principal, oauthas.RoleFor(g.Scopes), auth.Scope{},
		g.Client, g.ID, nonEmpty(g.Resource, "mcp"), time.Hour, now)
	if err != nil {
		return appCouldAnswer{}, err
	}
	s, err := open(root)
	if err != nil {
		return appCouldAnswer{}, err
	}
	caller := remoteCaller(tok)
	srv := buildMCP(root, s, caller, "templates")
	var found *mcp.Operation
	var names []string
	for _, o := range srv.Operations() {
		names = append(names, o.Name)
		if o.Name == op {
			o := o
			found = &o
		}
	}
	if found == nil {
		sort.Strings(names)
		return appCouldAnswer{}, fmt.Errorf("the agent interface has no operation %q; it has %s", op, strings.Join(names, ", "))
	}
	if err := srv.Authorise(*found); err != nil {
		return no(err.Error())
	}
	if page != "" {
		action, err := actionForRole(found.NeedsRole)
		if err != nil {
			return appCouldAnswer{}, err
		}
		if !strings.HasPrefix(page, "/") {
			page = "/" + page
		}
		if err := authorise(root, caller, action, page); err != nil {
			return no(err.Error())
		}
	}
	a.Could = true
	a.Then = append(a.Then, "it is recorded as "+a.App+" acting for "+g.Principal+" (mcp.call), "+
		"and quilzo apps receipt "+g.ID+" proves every call")
	return a, nil
}

// appsCould is `quilzo apps could CONNECTION OPERATION [PAGE]`.
func appsCould(root string, args []string) error {
	usage := errors.New("quilzo apps could CONNECTION OPERATION [PAGE]")
	fs := flag.NewFlagSet("apps could", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	args = fs.Args()
	if len(args) < 2 || len(args) > 3 {
		return usage
	}
	page := ""
	if len(args) == 3 {
		page = args[2]
	}
	a, err := appCould(root, args[0], args[1], page, time.Now())
	if err != nil {
		return err
	}
	// The person who connected it asks about their own; anybody else's is
	// an administrator's.
	caller := resolveCaller(root, flagToken)
	if caller.Name != a.For {
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return fmt.Errorf("asking about somebody else's app is an administrator's: %w", err)
		}
	}
	if w.JSON(a) {
		return nil
	}
	verdict, colour := "no", red
	if a.Could {
		verdict, colour = "yes", green
	}
	w.Human("%s%s%s  %s, for %s, could %s%s\n", colour, verdict, reset, a.App, a.For, a.What,
		map[bool]string{true: " " + page, false: ""}[page != ""])
	if a.Why != "" {
		w.Human("  %s\n", a.Why)
	}
	for _, t := range a.Then {
		w.Human("  then: %s\n", t)
	}
	return nil
}
