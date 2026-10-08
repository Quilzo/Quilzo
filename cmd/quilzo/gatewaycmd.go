// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/pii"
	"github.com/quilzo/quilzo/internal/shield"
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
	// The shield: a route it cut is not used, and what the gateway sees
	// that a person must know (a spent budget, a provider refusing a route
	// for its cap or its key) reaches its playbooks.
	gw.Cut = func(route string) bool {
		p, on := shield.Find(root, shield.Route, route, time.Now())
		return on && p.Reason != shield.Unreadable
	}
	// What was taken out of a prompt before it left, as counts: the
	// record that personal data stayed here, which names none of it.
	gw.OwnDomains = ownDomains(root)
	gw.OnMasked = func(consumer, route string, counts map[string]int) {
		noteMasked(root, consumer, route, counts)
	}
	gw.OnTrouble = func(kind, subject string) {
		name := "route-trouble"
		if kind == "spent" {
			name = "model-spend"
		}
		newShieldHost(root).engine.Observe(shield.Signal{Name: name, Subject: subject})
	}
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
	case "currency":
		if len(args) != 2 {
			return fmt.Errorf("usage: quilzo gateway currency USD")
		}
		code := strings.ToUpper(strings.TrimSpace(args[1]))
		return changeGateway(root, "currency", code, func(c *gateway.Config) error {
			c.Currency = code
			return c.Validate()
		})
	default:
		return fmt.Errorf("unknown gateway command %q; try status, route, budget or currency", args[0])
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
		privacy := "personal data masked"
		if h.Route.Personal {
			privacy = "may receive personal data"
		}
		w.Human("  %s  %s %s  %s%s; %s%s\n", h.Route.Name, h.Route.URL, h.Route.Model,
			dim, key, privacy, reset)
	}
	w.Human("%stoday%s\n", bold, reset)
	for _, s := range spend {
		limit := "no daily limit"
		if s.Budget > 0 {
			limit = fmt.Sprintf("of %d", s.Budget)
		}
		w.Human("  %s  %d characters %s, %d call(s), %d failed, %d refused\n",
			s.Consumer, s.Chars, limit, s.Calls, s.Failed, s.Refused)
		money := ""
		if cfg.Currency != "" {
			money = fmt.Sprintf(", %s %s today", s.Cost, cfg.Currency)
			if s.DayBudget > 0 {
				money += fmt.Sprintf(" of %s", s.DayBudget)
			}
			money += fmt.Sprintf(", %s this month", s.Month)
			if s.MonthBudget > 0 {
				money += fmt.Sprintf(" of %s", s.MonthBudget)
			}
		}
		w.Human("    %s%d tokens%s%s\n", dim, s.Tokens, money, reset)
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
		return fmt.Errorf("usage: quilzo gateway route add NAME --url U --model M [--key-env VAR] [--personal]\n" +
			"       quilzo gateway route remove NAME")
	}
	verb, name := args[0], args[1]
	fs := flag.NewFlagSet("route", flag.ContinueOnError)
	u := fs.String("url", "", "an OpenAI-compatible base URL")
	model := fs.String("model", "", "the model name at that endpoint")
	keyEnv := fs.String("key-env", "", "the environment variable holding the key (never the key)")
	priceIn := fs.String("price-in", "", "what a million input tokens cost here, like 0.15")
	priceOut := fs.String("price-out", "", "what a million output tokens cost here, like 0.60")
	first := fs.Bool("first", false, "try this route before the others")
	personal := fs.Bool("personal", false, "it may receive personal data: on this machine, or under an agreement to process it")
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
		r := gateway.Route{Name: name, URL: *u, Model: *model, KeyEnv: *keyEnv, PriceIn: *priceIn, PriceOut: *priceOut,
			Personal: *personal}
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
	tokens := fs.Int("tokens-per-day", 0, "tokens per day, as providers report them (0 is unlimited)")
	moneyDay := fs.String("money-per-day", "", "spending a day, in the gateway's currency, like 5.00")
	moneyMonth := fs.String("money-per-month", "", "spending a calendar month, in the gateway's currency")
	drop := fs.Bool("remove", false, "remove this caller's budget")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo gateway budget CALLER [--per-minute N] [--chars-per-day N]\n" +
			"         [--tokens-per-day N] [--money-per-day 5.00] [--money-per-month 100]\n" +
			"  CALLER is chatbot:NAME, assist, agent:NAME, person:NAME, or * for everybody else")
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
				CharsPerDay: *perDay, TokensPerDay: *tokens, MoneyPerDay: *moneyDay, MoneyPerMonth: *moneyMonth})
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

// directModel is the one model an install configures without the gateway
// (QUILZO_MODEL_URL), behind the gateway's privacy guard: personal data
// reaches it only when it is on this organisation's network.
func directModel(root string) (assist.Model, error) {
	m, err := assist.NewHTTPModel()
	if err != nil {
		return nil, err
	}
	host := ""
	if u, err := url.Parse(m.BaseURL); err == nil {
		host = u.Hostname()
	}
	return gateway.Guarded{Model: m, Personal: hostIsLocal(host), OwnDomains: ownDomains(root),
		OnMasked: func(counts map[string]int) { noteMasked(root, "direct", host, counts) }}, nil
}

// noteMasked records what was taken out of a prompt before it left, as
// counts: the record that personal data stayed here, which names none of
// it. A credential in a prompt is also the shield's: the model never saw
// it, but somebody pasted it, or an agent read it, somewhere it should not
// be.
func noteMasked(root, caller, route string, counts map[string]int) {
	d := map[string]string{"caller": caller, "route": route}
	for k, n := range counts {
		// The log refuses a key that names a secret, and with it the
		// whole record: a credential is counted under another name.
		if k == string(pii.Secret) {
			k = "credential"
		}
		d["masked_"+k] = strconv.Itoa(n)
	}
	record(root, audit.Record{Action: "model.masked", Resource: "/models", Outcome: audit.Success,
		Principal: "quilzo", Kind: audit.KindService, Verified: true, Detail: d})
	if counts[string(pii.Secret)] > 0 {
		newShieldHost(root).engine.Observe(shield.Signal{Name: "secret-in-prompt", Subject: caller})
	}
}
