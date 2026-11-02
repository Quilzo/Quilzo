// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/codescan"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/provider"
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
func usagePath(root string) string   { return filepath.Join(root, "usage", "models.jsonl") }

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
		m, err := routeModel(root, r)
		if err != nil {
			return nil, err
		}
		m.Draws = r.Draws
		// What this route's model is sent beside the conversation, and how
		// long a call through it may take: see gateway.RouteParams.
		var timeout time.Duration
		m.Params, timeout = r.Params.Model()
		if m.Params.MaxTokensField == "" {
			m.Params.MaxTokensField = providerMaxTokens(root, r)
		}
		if timeout > 0 {
			m.Client.Timeout = timeout
		}
		return m, nil
	}, ledger)
	// The shield: a route it cut is not used, and what the gateway sees
	// that a person must know (a spent budget, a provider refusing a route
	// for its cap or its key) reaches its playbooks.
	gw.HasSecret = func(name string) bool {
		_, err := readSecret(root, name)
		return err == nil
	}
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
		switch kind {
		case "ledger", "ledger-written":
			// The ledger's file is what budgets are counted from after a
			// restart. Its failing is a record in the audit log, where the
			// stream carries it to whoever watches, and it is not a route's
			// trouble: until it is written again, callers with budgets wait.
			action, outcome, detail := "gateway.ledger-failed", audit.Failure, map[string]string{"error": onOneLine(subject)}
			if kind == "ledger-written" {
				action, outcome, detail = "gateway.ledger-restored", audit.Success, map[string]string{"path": filepath.Base(subject)}
			}
			record(root, audit.Record{Action: action, Resource: "/gateway", Outcome: outcome,
				Principal: "gateway", Kind: audit.KindService, Verified: true, Detail: detail})
			return
		}
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
	case "providers", "provider":
		return gatewayProviders(root, args[1:])
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
		switch {
		case h.Route.KeySecret != "":
			key = "key sealed as " + h.Route.KeySecret
			if !h.KeySet {
				key += " (not kept: quilzo secret set " + h.Route.KeySecret + ")"
			}
		case h.Route.KeyEnv != "":
			key = "key in $" + h.Route.KeyEnv
			if !h.KeySet {
				key += " (not set)"
			}
		}
		if h.Route.Provider != "" {
			key = h.Route.Provider + ", " + key
		}
		if h.Route.Draws {
			key = "draws pictures; " + key
		}
		privacy := "personal data masked"
		if h.Route.Personal {
			privacy = "may receive personal data"
		}
		sends := ""
		if p := h.Route.Params.String(); p != "" {
			sends = "; sends " + p
		}
		w.Human("  %s  %s %s  %s%s; %s%s%s\n", h.Route.Name, h.Route.URL, h.Route.Model,
			dim, key, privacy, sends, reset)
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
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind, Model: caller.Model,
		Verified: caller.Verified, Detail: map[string]string{"name": name}})
	return nil
}

func gatewayRoute(root string, args []string) error {
	if len(args) < 2 || (args[0] != "add" && args[0] != "remove") {
		return fmt.Errorf("usage: quilzo gateway route add NAME --provider ID --model M [--param name=value] [--key-secret NAME]\n" +
			"       quilzo gateway route add NAME --url U --model M [--key-env VAR | --key-secret NAME] [--personal]\n" +
			"       quilzo gateway route add NAME ... --draws [--price-picture 0.04]   a route that draws pictures\n" +
			"         [--max-tokens-field max_completion_tokens] [--temperature T] [--top-p P] [--timeout 300s] [--auto-tool-choice]\n" +
			"         [--effort low|medium|high|xhigh|max] [--geo us|global] [--server-fallback]   Anthropic's Messages API only\n" +
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
	maxField := fs.String("max-tokens-field", "", "the output-limit field this model takes: max_tokens (the default) or max_completion_tokens")
	temperature := fs.String("temperature", "", "a temperature sent on every call; empty sends none, which current frontier models require")
	topP := fs.String("top-p", "", "a top_p sent on every call; empty sends none")
	timeout := fs.String("timeout", "", "how long one call may take, such as 300s for a model that reasons at length")
	autoTool := fs.Bool("auto-tool-choice", false, "send auto where a caller forces a tool, for a model that refuses a forced choice")
	effort := fs.String("effort", "", "Anthropic's Messages API: how hard the model thinks, low, medium, high, xhigh or max")
	geo := fs.String("geo", "", "Anthropic's Messages API: where the model may run, us or global (the provider's default)")
	serverFallback := fs.Bool("server-fallback", false, "Anthropic's Messages API: a request the model declines is answered by "+
		"another of Anthropic's models, for the models that take it")
	draws := fs.Bool("draws", false, "this route's model draws pictures (an images endpoint), and is used for nothing else")
	pricePicture := fs.String("price-picture", "", "what one picture costs here, like 0.04")
	prov := fs.String("provider", "", "a provider from quilzo gateway providers: the route reaches it and nothing else")
	keySecret := fs.String("key-secret", "", "the sealed credential holding the key (quilzo secret set NAME)")
	var provParams multiFlag
	fs.Var(&provParams, "param", "a provider's parameter, name=value (an Azure resource, an AWS region)")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	params, err := routeParams(*maxField, *temperature, *topP, *timeout, *autoTool)
	if err != nil {
		return err
	}
	params.Effort, params.Geo, params.Fallback = strings.TrimSpace(*effort), strings.TrimSpace(*geo), *serverFallback
	if err := params.Check(); err != nil {
		return err
	}
	wire := ""
	// A provider's route: its address from the profile, checked now, and
	// its key's credential named the way the profile suggests.
	var pp map[string]string
	if verb == "add" && *prov != "" {
		cat, cerr := loadProviders(root)
		if cerr != nil {
			return cerr
		}
		p, ok := cat.Get(*prov)
		if !ok {
			return fmt.Errorf("no provider called %q; quilzo gateway providers lists them", *prov)
		}
		pp = map[string]string{}
		for _, kv := range provParams {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return fmt.Errorf("--param is name=value, not %q", kv)
			}
			pp[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		base, _, eerr := p.Endpoint(pp)
		if eerr != nil {
			return eerr
		}
		wire = p.Wire
		if *u == "" {
			*u = base
		}
		if *keySecret == "" && *keyEnv == "" && p.Auth != "none" {
			*keySecret = p.Key
		}
		if len(pp) == 0 {
			pp = nil
		}
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
			Personal: *personal, Params: params, Provider: *prov, ProviderParams: pp, KeySecret: *keySecret,
			Draws: *draws, PricePicture: *pricePicture}
		if err := r.CheckWire(wire); err != nil {
			return err
		}
		if *first {
			c.Routes = append([]gateway.Route{r}, kept...)
		} else {
			c.Routes = append(kept, r)
		}
		return c.Validate()
	})
}

// routeParams reads a route's request fields as people type them.
func routeParams(maxField, temperature, topP, timeout string, autoTool bool) (gateway.RouteParams, error) {
	p := gateway.RouteParams{MaxTokens: maxField, Timeout: timeout, AutoToolChoice: autoTool}
	for _, f := range []struct {
		raw  string
		into **float64
		name string
	}{{temperature, &p.Temperature, "temperature"}, {topP, &p.TopP, "top_p"}} {
		if strings.TrimSpace(f.raw) == "" {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(f.raw), 64)
		if err != nil {
			return p, fmt.Errorf("%s is a number, not %q", f.name, f.raw)
		}
		*f.into = &v
	}
	return p, p.Check()
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
		Providers: func() []provider.Provider {
			cat, err := loadProviders(root)
			if err != nil {
				return nil
			}
			return cat.All()
		},
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

// assistModel is the model a person writes with: the gateway's routes, as
// the assistant and as them, each against its own budget and on the
// record, when the store has a gateway; the one configured model, guarded,
// when it has none. It went straight to the configured model either way,
// so the writing assistant was outside every budget and the ledger.
func assistModel(root, person string) (assist.Model, error) {
	gw, _, err := modelGateway(root)
	if err != nil {
		return nil, err
	}
	if gw != nil {
		var also []string
		if person != "" {
			also = append(also, "person:"+person)
		}
		return gw.For("assist", also...), nil
	}
	return directModel(root)
}

// paintPicture draws a picture: through the gateway's routes that draw,
// charged to "media" and to the person, on the record, when there are
// any; otherwise through the one configured image model, with the prompt's
// personal data and credentials taken out first (unless the model is on
// this network). It went straight to the configured model, unmasked and
// outside every budget.
func paintPicture(ctx context.Context, root, person, prompt, size string) (assist.Picture, error) {
	gw, _, err := modelGateway(root)
	if err != nil {
		return assist.Picture{}, err
	}
	if gw != nil && gw.Draws() {
		consumers := []string{"media"}
		if person != "" {
			consumers = append(consumers, "person:"+person)
		}
		pic, _, err := gw.Paint(ctx, consumers, prompt, size)
		return pic, err
	}
	m, err := assist.NewHTTPModel()
	if err != nil {
		return assist.Picture{}, err
	}
	host := ""
	if u, err := url.Parse(m.BaseURL); err == nil {
		host = u.Hostname()
	}
	mask := &pii.Masker{Allowed: ownDomains(root), Secrets: codescan.SecretSpans}
	prompt = mask.Mask(prompt, hostIsLocal(host))
	if counts := mask.Masked(); len(counts) > 0 {
		noteMasked(root, "media", host, counts)
	}
	return m.Paint(ctx, prompt, size)
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

// providersPath is the operator's own provider profiles, laid over the
// built-in ones (internal/provider).
func providersPath(root string) string { return filepath.Join(root, "providers.json") }

func loadProviders(root string) (*provider.Catalogue, error) {
	return provider.Load(providersPath(root))
}

// routeKey is a route's key: from its sealed credential, or from the
// environment variable it names.
func routeKey(root string, r gateway.Route) (string, error) {
	if r.KeySecret != "" {
		v, err := readSecret(root, r.KeySecret)
		if err != nil {
			return "", fmt.Errorf("route %s's key: %w", r.Name, err)
		}
		return strings.TrimSpace(v), nil
	}
	if r.KeyEnv != "" {
		key := os.Getenv(r.KeyEnv)
		if key == "" {
			return "", fmt.Errorf("%s is not set", r.KeyEnv)
		}
		return key, nil
	}
	return "", nil
}

// routeModel is the model a route reaches.
//
// A route that names a provider reaches that provider's host and nothing
// else, at public addresses for a hosted one and on this network for a
// local one, and sends its key the way the provider takes it. A route with
// only an address is as it was: any https address with a key, this network
// without one.
func routeModel(root string, r gateway.Route) (*assist.HTTPModel, error) {
	key, err := routeKey(root, r)
	if err != nil {
		return nil, err
	}
	if r.Provider == "" {
		if err := r.CheckWire(""); err != nil {
			return nil, err
		}
		return assist.NewHTTPModelAt(r.URL, key, r.Model)
	}
	cat, err := loadProviders(root)
	if err != nil {
		return nil, err
	}
	p, ok := cat.Get(r.Provider)
	if !ok {
		return nil, fmt.Errorf("route %s names %s, which is not a provider here (quilzo gateway providers)", r.Name, r.Provider)
	}
	base, host, err := p.Endpoint(r.ProviderParams)
	if err != nil {
		return nil, fmt.Errorf("route %s: %w", r.Name, err)
	}
	if err := r.CheckWire(p.Wire); err != nil {
		return nil, err
	}
	if r.URL != "" {
		u, perr := url.Parse(r.URL)
		if perr != nil || !strings.EqualFold(u.Host, host) || (u.Scheme != "https" && !p.Local) {
			return nil, fmt.Errorf("route %s is at %s and its provider, %s, is at %s: a route reaches its "+
				"provider and nothing else", r.Name, r.URL, p.Name, host)
		}
		base = strings.TrimSuffix(r.URL, "/")
	}
	if p.Auth != "none" && key == "" {
		return nil, fmt.Errorf("route %s needs its key for %s: quilzo secret set %s < keyfile, then "+
			"--key-secret %s", r.Name, p.Name, p.Key, p.Key)
	}
	reach := fetch.Public
	if p.Local {
		reach = fetch.OnThisNetwork
	}
	m := &assist.HTTPModel{BaseURL: base, APIKey: key, Model: r.Model,
		Client: fetch.Speaking("assistant", reach, assist.RequestTimeout),
		Auth:   p.Auth, Headers: p.Headers, Host: host, Wire: p.Wire}
	if p.Auth == "none" && key != "" {
		m.Auth = "bearer"
	}
	return m, nil
}

// providerMaxTokens is the output-limit field a route uses: its own, or
// its provider's.
func providerMaxTokens(root string, r gateway.Route) string {
	if r.Params.MaxTokens != "" || r.Provider == "" {
		return r.Params.MaxTokens
	}
	if cat, err := loadProviders(root); err == nil {
		if p, ok := cat.Get(r.Provider); ok {
			return p.MaxTokens
		}
	}
	return ""
}

// gatewayProviders lists the providers a route can name, or one of them.
func gatewayProviders(root string, args []string) error {
	cat, err := loadProviders(root)
	if err != nil {
		return err
	}
	if len(args) > 0 {
		p, ok := cat.Get(args[0])
		if !ok {
			return fmt.Errorf("no provider called %q; quilzo gateway providers lists them", args[0])
		}
		if w.JSON(p) {
			return nil
		}
		w.Human("%s%s%s  (%s)\n", bold, p.Name, reset, p.ID)
		w.Human("  %s, %s\n", provider.GroupName(p.Group), p.Where)
		w.Human("  address   %s\n", p.Base)
		if p.Wire == provider.WireAnthropic {
			w.Human("  speaks    Anthropic's Messages API: --effort, --geo and --server-fallback apply\n")
		}
		auth := "Authorization: Bearer"
		switch {
		case p.Auth == "none":
			auth = "no key"
		case strings.HasPrefix(p.Auth, "header:"):
			auth = strings.TrimPrefix(p.Auth, "header:") + " header"
		}
		w.Human("  key       %s\n", auth)
		w.Human("  trains on what it is sent: %s\n", p.Data.Trains)
		w.Human("  keeps it: %s", p.Data.Retention)
		if p.Data.ZeroRetention != "" {
			w.Human(" (zero retention: %s)", p.Data.ZeroRetention)
		}
		w.Human("\n  where it is processed: %s\n", p.Data.Residency)
		w.Human("  %saddress from %s; %s%s\n", dim, p.Verified, p.Docs, reset)
		add := "quilzo gateway route add NAME --provider " + p.ID + " --model MODEL"
		for _, prm := range p.Params {
			add += " --param " + prm.Name + "=..."
		}
		if p.Auth != "none" {
			w.Human("\n  quilzo secret set %s < keyfile\n", p.Key)
			add += " --key-secret " + p.Key
		} else {
			w.Human("\n")
		}
		w.Human("  %s\n", add)
		return nil
	}
	all := cat.All()
	if w.JSON(all) {
		return nil
	}
	group := ""
	for _, p := range all {
		if p.Group != group {
			group = p.Group
			w.Human("\n%s%s%s\n", bold, provider.GroupName(group), reset)
		}
		w.Human("  %-16s %-48s %s%s%s\n", p.ID, clip(p.Name, 48), dim, p.Where, reset)
	}
	w.Human("\n%squilzo gateway providers ID for one, with what it keeps and how to add it%s\n", dim, reset)
	return nil
}
