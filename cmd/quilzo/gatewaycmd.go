// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/gateway"
)

// Model routes, budgets and the usage ledger, from the command line and for
// the admin's Models screen. See internal/gateway.

func gatewayPath(root string) string { return filepath.Join(root, "gateway.json") }
func usagePath(root string) string   { return filepath.Join(root, "model-usage.jsonl") }

// One gateway per process and root. Per-minute limits live in its memory, so
// a gateway built per call would never limit anything.
var (
	gatewaysMu sync.Mutex
	gateways   = map[string]*gatewayEntry{}
)

type gatewayEntry struct {
	mod time.Time
	gw  *gateway.Gateway
	cfg *gateway.Config
}

// modelGateway is this root's gateway, or nil when none is declared. Rebuilt
// when the declaration changes on disk, so a route or a budget edited from
// the admin or the command line takes effect without a restart.
func modelGateway(root string) (*gateway.Gateway, *gateway.Config, error) {
	fi, err := os.Stat(gatewayPath(root))
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	gatewaysMu.Lock()
	defer gatewaysMu.Unlock()
	if e, ok := gateways[root]; ok && e.mod.Equal(fi.ModTime()) {
		return e.gw, e.cfg, nil
	}
	cfg, err := gateway.Load(gatewayPath(root))
	if err != nil || cfg == nil {
		return nil, nil, err
	}
	ledger, err := gateway.OpenLedger(usagePath(root), time.Now())
	if err != nil {
		return nil, nil, err
	}
	gw := gateway.New(*cfg, func(r gateway.Route) (gateway.Model, error) {
		key := ""
		if r.KeyEnv != "" {
			key = os.Getenv(r.KeyEnv)
			if key == "" {
				return nil, fmt.Errorf("%s is not set", r.KeyEnv)
			}
		}
		return assist.NewHTTPModelAt(r.URL, key, r.Model)
	}, ledger)
	gateways[root] = &gatewayEntry{mod: fi.ModTime(), gw: gw, cfg: cfg}
	return gw, cfg, nil
}

func cmdGateway(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return gatewayStatus(root)
	case "route":
		return gatewayRoute(root, args[1:])
	case "budget":
		return gatewayBudget(root, args[1:])
	default:
		return fmt.Errorf("unknown gateway command %q; try status, route or budget", args[0])
	}
}

func gatewayStatus(root string) error {
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	gw, cfg, err := modelGateway(root)
	if err != nil {
		return err
	}
	if gw == nil {
		w.Human("no gateway declared; every model call goes to the one model " +
			"in QUILZO_MODEL_URL.\n  add a route with quilzo gateway route add NAME --url U --model M\n")
		return nil
	}
	ledger, err := gateway.OpenLedger(usagePath(root), time.Now())
	if err != nil {
		return err
	}
	spend := ledger.Summary(*cfg, time.Now())
	if w.JSON(map[string]any{"routes": gw.Health(), "today": spend}) {
		return nil
	}
	w.Human("%sroutes, in fallback order%s\n", bold, reset)
	for _, h := range gw.Health() {
		key := "no key needed"
		if h.Route.KeyEnv != "" {
			key = "key in $" + h.Route.KeyEnv
			if !h.KeySet {
				key += " (not set)"
			}
		}
		w.Human("  %s  %s %s  %s%s%s\n", h.Route.Name, h.Route.URL, h.Route.Model,
			dim, key, reset)
	}
	w.Human("%stoday%s\n", bold, reset)
	for _, s := range spend {
		limit := "no daily limit"
		if s.Budget > 0 {
			limit = fmt.Sprintf("of %d", s.Budget)
		}
		w.Human("  %s  %d characters %s, %d call(s), %d failed, %d refused\n",
			s.Consumer, s.Chars, limit, s.Calls, s.Failed, s.Refused)
	}
	return nil
}

// changeGateway edits the declaration under the audit log.
//
// Grant, not publish: a route decides where prompts go — what visitors typed
// and what the site holds — and pointing it somewhere new is a decision about
// who receives that, of the same weight as deciding who may sign in.
func changeGateway(root, change, name string, edit func(*gateway.Config) error) error {
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	cfg, err := gateway.Load(gatewayPath(root))
	if err != nil {
		return err
	}
	if cfg == nil {
		cfg = &gateway.Config{}
	}
	if err := edit(cfg); err != nil {
		return err
	}
	if err := gateway.Save(gatewayPath(root), cfg); err != nil {
		return err
	}
	record(root, audit.Record{Action: "gateway." + change, Resource: "/gateway/" + name,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified, Detail: map[string]string{"name": name}})
	return nil
}

func gatewayRoute(root string, args []string) error {
	if len(args) < 2 || (args[0] != "add" && args[0] != "remove") {
		return fmt.Errorf("usage: quilzo gateway route add NAME --url U --model M [--key-env VAR]\n" +
			"       quilzo gateway route remove NAME")
	}
	verb, name := args[0], args[1]
	fs := flag.NewFlagSet("route", flag.ContinueOnError)
	u := fs.String("url", "", "an OpenAI-compatible base URL")
	model := fs.String("model", "", "the model name at that endpoint")
	keyEnv := fs.String("key-env", "", "the environment variable holding the key (never the key)")
	first := fs.Bool("first", false, "try this route before the others")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	return changeGateway(root, "route."+verb, name, func(c *gateway.Config) error {
		var kept []gateway.Route
		for _, r := range c.Routes {
			if r.Name != name {
				kept = append(kept, r)
			}
		}
		if verb == "remove" {
			if len(kept) == len(c.Routes) {
				return fmt.Errorf("no route called %s", name)
			}
			c.Routes = kept
			return nil
		}
		r := gateway.Route{Name: name, URL: *u, Model: *model, KeyEnv: *keyEnv}
		if *first {
			c.Routes = append([]gateway.Route{r}, kept...)
		} else {
			c.Routes = append(kept, r)
		}
		return c.Validate()
	})
}

func gatewayBudget(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("budget", flag.ContinueOnError)
	perMinute := fs.Int("per-minute", 0, "calls per minute (0 is unlimited)")
	perDay := fs.Int("chars-per-day", 0, "characters per day, prompt and reply (0 is unlimited)")
	drop := fs.Bool("remove", false, "remove this caller's budget")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo gateway budget CALLER --per-minute N --chars-per-day N\n" +
			"  CALLER is chatbot:NAME, assist, agent:NAME, or * for everybody else")
	}
	who := pos[0]
	return changeGateway(root, "budget", who, func(c *gateway.Config) error {
		var kept []gateway.Budget
		for _, b := range c.Budgets {
			if b.Consumer != who {
				kept = append(kept, b)
			}
		}
		if !*drop {
			kept = append(kept, gateway.Budget{Consumer: who, PerMinute: *perMinute,
				CharsPerDay: *perDay})
		}
		c.Budgets = kept
		return c.Validate()
	})
}

// gatewayCapability is the gateway for the admin's Models screen.
func gatewayCapability(root string) *admin.Models {
	return &admin.Models{
		Load: func() (*gateway.Config, []gateway.Health, []gateway.Spend, error) {
			gw, cfg, err := modelGateway(root)
			if err != nil || gw == nil {
				return nil, nil, nil, err
			}
			ledger, err := gateway.OpenLedger(usagePath(root), time.Now())
			if err != nil {
				return nil, nil, nil, err
			}
			return cfg, gw.Health(), ledger.Summary(*cfg, time.Now()), nil
		},
		Save: func(cfg *gateway.Config, by, change, name string) error {
			if err := gateway.Save(gatewayPath(root), cfg); err != nil {
				return err
			}
			record(root, audit.Record{Action: "gateway." + change,
				Resource: "/gateway/" + name, Outcome: audit.Success, Principal: by,
				Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"name": name}})
			return nil
		},
	}
}
