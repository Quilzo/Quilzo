// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oauthas"
)

// Apps connected to the agent interface, from the command line: the same as
// the Connected apps screen, for an administrator.

// fileTokens revokes apps' tokens in the token store on disk.
type fileTokens struct{ root string }

func (f fileTokens) Issue(oauthas.Grant, auth.Role, time.Duration, time.Time) (string, error) {
	return "", errors.New("tokens are issued by the admin's server, not the command line")
}

func (f fileTokens) RevokeGrant(id string) error {
	ts, err := loadTokens(f.root)
	if err != nil {
		return err
	}
	if ts.RevokeGrant(id) == 0 {
		return nil
	}
	return saveJSON(tokensPath(f.root), ts)
}

func appsServer(root string, by *Caller) *oauthas.Server {
	st := &oauthas.Store{Dir: oauthDir(root)}
	return &oauthas.Server{
		Config: func() oauthas.Config { return oauthas.Config{} },
		Store:  st, Directory: &oauthas.Directory{}, Tokens: fileTokens{root: root},
		Record: func(action, principal string, d map[string]string) {
			d["by"] = by.Name
			record(root, by.auditRecord(action, "/mcp", audit.Success, d))
		},
	}
}

func cmdApps(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	by := resolveCaller(root, flagToken)
	oa := appsServer(root, by)
	switch args[0] {
	case "list":
		return appsList(root, oa)
	case "receipt":
		return appReceipt(root, args[1:])
	case "allow", "disallow":
		if len(args) != 2 {
			return fmt.Errorf("quilzo apps %s HOST", args[0])
		}
		host := strings.ToLower(strings.TrimSpace(args[1]))
		if err := oauthas.CheckHost(host); err != nil {
			return err
		}
		err := oa.Store.ChangeClients(func(_ *[]oauthas.Client, hosts *[]string) error {
			var keep []string
			for _, h := range *hosts {
				if h != host {
					keep = append(keep, h)
				}
			}
			if args[0] == "allow" {
				keep = append(keep, host)
			}
			sort.Strings(keep)
			*hosts = keep
			return nil
		})
		if err != nil {
			return err
		}
		record(root, by.auditRecord("oauth."+args[0]+"-host", "/mcp", audit.Success, map[string]string{"host": host}))
		if args[0] == "allow" {
			fmt.Printf("apps published from %s may now ask people to connect\n", host)
			return nil
		}
		n := oa.EndWhere(func(g oauthas.Grant) bool {
			return host == "*" || (oauthas.Client{ID: g.Client}).Host() == host
		}, by.Name, "apps from "+host+" are no longer allowed")
		fmt.Printf("apps from %s can no longer connect; %s ended\n", host, count(n, "connection"))
		return nil
	case "register":
		fs := flag.NewFlagSet("apps register", flag.ContinueOnError)
		var redirects stringList
		fs.Var(&redirects, "redirect", "where sign-in may return to; repeat for more")
		if len(args) < 2 {
			return errors.New(`quilzo apps register NAME --redirect URI [--redirect URI]`)
		}
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		c, err := oauthas.NewRegistered(args[1], redirects, by.Name, time.Now())
		if err != nil {
			return err
		}
		if err := oa.Store.ChangeClients(func(cs *[]oauthas.Client, _ *[]string) error {
			if len(*cs) >= 200 {
				return errors.New("200 registered apps is the limit")
			}
			*cs = append(*cs, c)
			return nil
		}); err != nil {
			return err
		}
		record(root, by.auditRecord("oauth.app-registered", "/mcp", audit.Success,
			map[string]string{"client": c.ID, "app": c.Name, "redirects": strings.Join(redirects, " ")}))
		fmt.Printf("registered %s\n  client_id %s\n  a public client: no secret; PKCE with S256\n", c.Name, c.ID)
		return nil
	case "unregister":
		if len(args) != 2 {
			return errors.New("quilzo apps unregister CLIENT_ID")
		}
		removed := false
		if err := oa.Store.ChangeClients(func(cs *[]oauthas.Client, _ *[]string) error {
			var keep []oauthas.Client
			for _, c := range *cs {
				if c.ID == args[1] {
					removed = true
					continue
				}
				keep = append(keep, c)
			}
			*cs = keep
			return nil
		}); err != nil {
			return err
		}
		if !removed {
			return fmt.Errorf("no app %s is registered", args[1])
		}
		record(root, by.auditRecord("oauth.app-removed", "/mcp", audit.Success, map[string]string{"client": args[1]}))
		n := oa.EndWhere(func(g oauthas.Grant) bool { return g.Client == args[1] }, by.Name, "the app was removed from the register")
		fmt.Printf("removed; %s ended\n", count(n, "connection"))
		return nil
	case "disconnect":
		if len(args) != 2 {
			return errors.New("quilzo apps disconnect GRANT_ID")
		}
		return oa.End(args[1], by.Name, "disconnected from the command line")
	default:
		return fmt.Errorf("unknown apps command %q; try list, allow, disallow, register, unregister, disconnect or receipt", args[0])
	}
}

func appsList(root string, oa *oauthas.Server) error {
	cfg := mustConfig(root)
	on := "off (quilzo config set mcp.remote true)"
	if cfg.Bool("mcp.remote") {
		on = "on at " + interfaceAddress(cfg)
	}
	fmt.Printf("agent interface: %s\n", on)
	if cfg.Raw("admin.base_url") == "" {
		fmt.Printf("  %sapps cannot sign in by themselves until admin.base_url is set; Quilzo's own tokens work%s\n", dim, reset)
	}
	grants, err := oa.Store.Grants()
	if err != nil {
		return err
	}
	clients, hosts, err := oa.Store.Clients()
	if err != nil {
		return err
	}
	now := time.Now()
	fmt.Println("\nconnected:")
	n := 0
	for _, g := range grants {
		if !g.Live(now) {
			continue
		}
		n++
		last := "never"
		if !g.LastUsed.IsZero() {
			last = g.LastUsed.UTC().Format("2006-01-02 15:04")
		}
		fmt.Printf("  %s  %s for %s  [%s]  last used %s, asks again %s\n", g.ID, g.ClientName, g.Principal,
			strings.Join(g.Scopes, " "), last, g.Expires.UTC().Format("2006-01-02"))
	}
	if n == 0 {
		fmt.Println("  none")
	}
	fmt.Println("\napps may connect from:")
	if len(hosts) == 0 {
		fmt.Println("  no host yet (quilzo apps allow HOST)")
	}
	for _, h := range hosts {
		fmt.Printf("  %s\n", h)
	}
	fmt.Println("\nregistered here:")
	if len(clients) == 0 {
		fmt.Println("  none")
	}
	for _, c := range clients {
		fmt.Printf("  %s  %s  returns to %s\n", c.ID, c.Name, strings.Join(c.RedirectURIs, " "))
	}
	return nil
}
