// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package gateway puts every model call behind one door: which endpoint,
// what happens when it fails, how much each caller may spend, and a record
// of what was spent.
//
// # What LiteLLM made obvious
//
// A team with one model key soon has five: a hosted model for quality, a
// local one for privacy, a cheaper one for volume. Each feature then grows its
// own client, its own retry, its own idea of a budget, and nobody can answer
// "what did the chatbot cost last week" or "what happens when the provider is
// down". LiteLLM's answer — one proxy with routes, fallbacks, virtual keys and
// budgets — is why it is everywhere. This is the same answer inside the
// program, with three differences.
//
// Keys are never stored. A route names the environment variable its key is
// in, so the configuration file can be committed, diffed and reviewed, and a
// leaked copy of it leaks nothing.
//
// Budgets are per caller, not per key. A public chatbot is a model endpoint
// anybody on the internet can reach; the public site limits each visitor, and
// a thousand visitors are still a thousand. A daily cap on the chatbot itself
// is what bounds the bill, and it fails closed: over budget, the chatbot
// answers without the model, from its pages, which is a worse answer and not
// an outage.
//
// The ledger records who asked, which route answered, how much and how long
// — never what was asked. Prompts hold what visitors typed and what the site
// says, and neither belongs in a log.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Route is one model endpoint.
type Route struct {
	Name string `json:"name"`
	// URL is an OpenAI-compatible base, like http://localhost:11434/v1.
	URL   string `json:"url"`
	Model string `json:"model"`
	// KeyEnv names the environment variable holding the key. Empty is a
	// keyless endpoint, which must be on this network.
	KeyEnv string `json:"key_env,omitempty"`
	// PriceIn and PriceOut are what a million input and output tokens cost
	// on this route, in the configuration's currency: "0.15", "0.60". Empty
	// is free, which a model on this machine is.
	PriceIn  string `json:"price_in,omitempty"`
	PriceOut string `json:"price_out,omitempty"`
}

// Budget bounds one caller.
type Budget struct {
	// Consumer is who is calling: "chatbot:help", "assist", "agent:triage",
	// or "*" for everybody without a budget of their own.
	Consumer string `json:"consumer"`
	// PerMinute is calls per minute. Zero is unlimited.
	PerMinute int `json:"per_minute,omitempty"`
	// CharsPerDay bounds prompt plus reply, in characters. Characters rather
	// than tokens because every provider counts tokens differently and a
	// budget has to mean the same thing whichever route answered; roughly
	// four characters to a token. Zero is unlimited.
	CharsPerDay int `json:"chars_per_day,omitempty"`
	// TokensPerDay bounds tokens, as the providers report them. Zero is
	// unlimited.
	TokensPerDay int `json:"tokens_per_day,omitempty"`
	// MoneyPerDay and MoneyPerMonth bound spending in the configuration's
	// currency, at the routes' prices: "5.00". Empty is unlimited.
	MoneyPerDay   string `json:"money_per_day,omitempty"`
	MoneyPerMonth string `json:"money_per_month,omitempty"`
}

// Config is the gateway's declaration.
type Config struct {
	// Routes in fallback order: the first that answers is used.
	Routes  []Route  `json:"routes"`
	Budgets []Budget `json:"budgets,omitempty"`
	// Currency is what the prices and money budgets are in: ISO 4217, like
	// USD or EUR. Required once anything has a price.
	Currency string `json:"currency,omitempty"`
}

var (
	reName   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	reEnv    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	reWho    = regexp.MustCompile(`^(\*|[a-z][a-z0-9-]*(:[a-z0-9][a-z0-9-]{0,62})?|person:[A-Za-z0-9._@+-]{1,254})$`)
	reModelN = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,120}$`)
)

// Validate refuses a declaration that could not work.
func (c Config) Validate() error {
	seen := map[string]bool{}
	for _, r := range c.Routes {
		if !reName.MatchString(r.Name) {
			return fmt.Errorf("%q is not a usable route name", r.Name)
		}
		if seen[r.Name] {
			return fmt.Errorf("the route %s is declared twice", r.Name)
		}
		seen[r.Name] = true
		u, err := url.Parse(r.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
			u.User != nil {
			return fmt.Errorf("route %s: %q is not an http(s) address", r.Name, r.URL)
		}
		if !reModelN.MatchString(r.Model) {
			return fmt.Errorf("route %s: %q is not a model name", r.Name, r.Model)
		}
		if r.KeyEnv != "" && !reEnv.MatchString(r.KeyEnv) {
			return fmt.Errorf("route %s: %q is not an environment variable name; "+
				"the key itself is never written here", r.Name, r.KeyEnv)
		}
		in, out, err := r.prices()
		if err != nil {
			return err
		}
		if (in > 0 || out > 0) && !reCurrency.MatchString(c.Currency) {
			return fmt.Errorf("route %s has prices and the configuration names no currency (USD, EUR, …)", r.Name)
		}
	}
	if c.Currency != "" && !reCurrency.MatchString(c.Currency) {
		return fmt.Errorf("%q is not a currency code like USD or EUR", c.Currency)
	}
	who := map[string]bool{}
	for _, b := range c.Budgets {
		if !reWho.MatchString(b.Consumer) {
			return fmt.Errorf("%q is not a caller; use chatbot:NAME, assist, "+
				"agent:NAME or *", b.Consumer)
		}
		if who[b.Consumer] {
			return fmt.Errorf("%s has two budgets", b.Consumer)
		}
		who[b.Consumer] = true
		if b.PerMinute < 0 || b.CharsPerDay < 0 || b.TokensPerDay < 0 {
			return fmt.Errorf("%s's budget is negative", b.Consumer)
		}
		day, month, err := b.caps()
		if err != nil {
			return err
		}
		if (day > 0 || month > 0) && !reCurrency.MatchString(c.Currency) {
			return fmt.Errorf("%s has a money budget and the configuration names no currency", b.Consumer)
		}
	}
	return nil
}

// BudgetFor is the budget that applies to a caller: its own, or "*".
func (c Config) BudgetFor(consumer string) (Budget, bool) {
	var star *Budget
	for i := range c.Budgets {
		if c.Budgets[i].Consumer == consumer {
			return c.Budgets[i], true
		}
		if c.Budgets[i].Consumer == "*" {
			star = &c.Budgets[i]
		}
	}
	if star != nil {
		return *star, true
	}
	return Budget{}, false
}

// Load reads a declaration; a missing file is (nil, nil), meaning no gateway
// is configured and callers use the single configured model as before.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s is not a gateway declaration: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Save writes a declaration.
func Save(path string, c *Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// Model is what callers use: the same two methods as internal/assist's.
type Model interface {
	Complete(ctx context.Context, system, user string) (string, error)
	Name() string
}

// ErrBudget is a call refused because its caller has spent its budget.
var ErrBudget = errors.New("over budget")

// ErrNoRoute is every route failing or none configured.
var ErrNoRoute = errors.New("no model route answered")

// Build turns a route into a model. Supplied by the caller, so tests drive
// the gateway with fakes and the program with internal/assist.
type Build func(Route) (Model, error)

// Failure handling: a route that fails this many times in a row is skipped
// for Cooldown, then tried again.
const (
	FailuresBeforeCooldown = 3
	Cooldown               = time.Minute
)

// Gateway is the running door.
type Gateway struct {
	cfg    Config
	build  Build
	ledger *Ledger
	now    func() time.Time

	// Cut reports a route the shield has cut, which is skipped as a route
	// resting after failures is (internal/shield). Nil cuts nothing.
	Cut func(route string) bool
	// OnTrouble is told what the shield should know: a caller that spent
	// its budget ("spent", with the consumer), and a route the provider
	// refused for its spend cap or its key ("route-spent", "route-auth",
	// with the route). Nil tells nobody.
	OnTrouble func(kind, subject string)

	mu      sync.Mutex
	models  map[string]Model
	fails   map[string]int
	downTil map[string]time.Time
	calls   map[string][]time.Time
}

// New starts a gateway.
func New(cfg Config, build Build, ledger *Ledger) *Gateway {
	return &Gateway{cfg: cfg, build: build, ledger: ledger, now: time.Now,
		models: map[string]Model{}, fails: map[string]int{},
		downTil: map[string]time.Time{}, calls: map[string][]time.Time{}}
}

// WithClock sets the clock, for tests.
func (g *Gateway) WithClock(now func() time.Time) *Gateway { g.now = now; return g }

// For is the model a caller uses. Also are others the call is charged to
// as well, each against its own budget: an agent's run is charged to the
// agent and to the person who started it, so neither can spend past its
// own limit through the other.
func (g *Gateway) For(consumer string, also ...string) Model {
	return &bound{g: g, consumers: append([]string{consumer}, also...)}
}

type bound struct {
	g         *Gateway
	consumers []string
}

func (b *bound) Name() string { return "gateway:" + b.consumers[0] }

func (b *bound) Complete(ctx context.Context, system, user string) (string, error) {
	out, _, _, err := b.g.complete(ctx, b.consumers, system, user)
	return out, err
}

// CompleteMetered is Complete with what the call used.
func (b *bound) CompleteMetered(ctx context.Context, system, user string) (string, assist.Usage, error) {
	out, u, _, err := b.g.complete(ctx, b.consumers, system, user)
	return out, u, err
}

// CompleteCosted is Complete with what the call used and what it cost, in
// millionths of the configuration's currency.
func (b *bound) CompleteCosted(ctx context.Context, system, user string) (string, assist.Usage, int64, error) {
	out, u, cost, err := b.g.complete(ctx, b.consumers, system, user)
	return out, u, int64(cost), err
}

// Currency is what costs are in.
func (g *Gateway) Currency() string { return g.cfg.Currency }

// admit checks a call against every budget it is charged to.
func (g *Gateway) admit(consumers []string, chars int) error {
	for _, c := range consumers {
		if err := g.admitOne(c, chars); err != nil {
			return err
		}
	}
	return nil
}

func (g *Gateway) admitOne(consumer string, chars int) error {
	b, ok := g.cfg.BudgetFor(consumer)
	if !ok {
		return nil
	}
	now := g.now()
	if g.ledger != nil {
		// Spending is known only after a call, so a cap stops the next call
		// once it is reached rather than the one that crosses it: the
		// overshoot is one call, and the ledger says exactly how much.
		if b.TokensPerDay > 0 {
			if used := g.ledger.TodayTokens(consumer, now); used >= b.TokensPerDay {
				return fmt.Errorf("%w: %s has used %d of %d tokens today", ErrBudget, consumer, used, b.TokensPerDay)
			}
		}
		day, month, _ := b.caps()
		if day > 0 {
			if spent := g.ledger.TodayCost(consumer, now); spent >= day {
				return fmt.Errorf("%w: %s has spent %s of %s %s today", ErrBudget, consumer, spent, day, g.cfg.Currency)
			}
		}
		if month > 0 {
			if spent := g.ledger.MonthCost(consumer, now); spent >= month {
				return fmt.Errorf("%w: %s has spent %s of %s %s this month", ErrBudget, consumer, spent, month, g.cfg.Currency)
			}
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if b.PerMinute > 0 {
		recent := g.calls[consumer][:0]
		for _, t := range g.calls[consumer] {
			if now.Sub(t) < time.Minute {
				recent = append(recent, t)
			}
		}
		g.calls[consumer] = recent
		if len(recent) >= b.PerMinute {
			return fmt.Errorf("%w: %s has made %d calls this minute, its limit",
				ErrBudget, consumer, len(recent))
		}
		g.calls[consumer] = append(g.calls[consumer], now)
	}
	if b.CharsPerDay > 0 && g.ledger != nil {
		if used := g.ledger.Today(consumer, now); used+chars > b.CharsPerDay {
			return fmt.Errorf("%w: %s has used %d of %d characters today",
				ErrBudget, consumer, used, b.CharsPerDay)
		}
	}
	return nil
}

func (g *Gateway) model(r Route) (Model, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if m, ok := g.models[r.Name]; ok {
		return m, nil
	}
	m, err := g.build(r)
	if err != nil {
		return nil, err
	}
	g.models[r.Name] = m
	return m, nil
}

func (g *Gateway) complete(ctx context.Context, consumers []string, system, user string) (string, assist.Usage, Money, error) {
	consumer, also := consumers[0], consumers[1:]
	in := len(system) + len(user)
	if err := g.admit(consumers, in); err != nil {
		g.ledger.record(Usage{At: g.now(), Consumer: consumer, Also: also, In: in, Outcome: "over-budget"})
		if g.OnTrouble != nil {
			g.OnTrouble("spent", consumer)
		}
		return "", assist.Usage{}, 0, err
	}
	if len(g.cfg.Routes) == 0 {
		return "", assist.Usage{}, 0, ErrNoRoute
	}
	var errs []string
	for _, r := range g.cfg.Routes {
		g.mu.Lock()
		down := g.now().Before(g.downTil[r.Name])
		g.mu.Unlock()
		if down {
			errs = append(errs, r.Name+": resting after repeated failures")
			continue
		}
		if g.Cut != nil && g.Cut(r.Name) {
			errs = append(errs, r.Name+": cut by the shield")
			continue
		}
		m, err := g.model(r)
		if err != nil {
			errs = append(errs, r.Name+": "+err.Error())
			continue
		}
		start := g.now()
		var out string
		var used assist.Usage
		if mm, ok := m.(assist.Metered); ok {
			out, used, err = mm.CompleteMetered(ctx, system, user)
		} else {
			out, err = m.Complete(ctx, system, user)
			used = assist.Estimate(system+user, out)
		}
		took := g.now().Sub(start)
		if err != nil {
			if kind := Trouble(err); kind != "" && g.OnTrouble != nil {
				g.OnTrouble(kind, r.Name)
			}
			g.failed(r.Name)
			g.ledger.record(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name,
				Model: r.Model, In: in, Millis: took.Milliseconds(), Outcome: "failed"})
			errs = append(errs, r.Name+": "+err.Error())
			if ctx.Err() != nil {
				break
			}
			continue
		}
		g.mu.Lock()
		g.fails[r.Name] = 0
		g.mu.Unlock()
		pin, pout, _ := r.prices()
		cost := costOf(pin, pout, used.In, used.Out)
		g.ledger.record(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name,
			Model: r.Model, In: in, Out: len(out), Millis: took.Milliseconds(),
			TokensIn: used.In, TokensOut: used.Out, Estimated: !used.Reported, Cost: cost,
			Outcome: "ok"})
		return out, used, cost, nil
	}
	return "", assist.Usage{}, 0, fmt.Errorf("%w: %s", ErrNoRoute, strings.Join(errs, "; "))
}

func (g *Gateway) failed(route string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fails[route]++
	if g.fails[route] >= FailuresBeforeCooldown {
		g.downTil[route] = g.now().Add(Cooldown)
		g.fails[route] = 0
	}
}

// Health is a route's state, for the screen.
type Health struct {
	Route    Route
	KeySet   bool
	Resting  bool
	Until    time.Time
	Failures int
}

// Health reports every route.
func (g *Gateway) Health() []Health {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Health
	for _, r := range g.cfg.Routes {
		h := Health{Route: r, Failures: g.fails[r.Name], Until: g.downTil[r.Name]}
		h.Resting = g.now().Before(h.Until)
		h.KeySet = r.KeyEnv == "" || os.Getenv(r.KeyEnv) != ""
		out = append(out, h)
	}
	return out
}

// -- the ledger ---------------------------------------------------------------

// Usage is one call, without its content.
type Usage struct {
	At       time.Time `json:"at"`
	Consumer string    `json:"consumer"`
	// Also are the others it was charged to: the person an agent ran for.
	Also   []string `json:"also,omitempty"`
	Route  string   `json:"route,omitempty"`
	Model  string   `json:"model,omitempty"`
	In     int      `json:"in"`
	Out    int      `json:"out,omitempty"`
	Millis int64    `json:"ms,omitempty"`
	// TokensIn and TokensOut are as the provider reported them, or
	// estimated from the text when it did not (Estimated).
	TokensIn  int  `json:"tokens_in,omitempty"`
	TokensOut int  `json:"tokens_out,omitempty"`
	Estimated bool `json:"estimated,omitempty"`
	// Cost is at the route's prices, in millionths of the currency.
	Cost    Money  `json:"cost,omitempty"`
	Outcome string `json:"outcome"`
}

func (u Usage) payers() []string { return append([]string{u.Consumer}, u.Also...) }

// Ledger records usage to a file and keeps today's and this month's
// totals in memory.
type Ledger struct {
	path      string
	mu        sync.Mutex
	day       string
	month     string
	used      map[string]int
	tokens    map[string]int
	cost      map[string]Money
	monthCost map[string]Money
	all       []Usage
}

// MaxKept is how many recent calls the ledger keeps in memory for display.
const MaxKept = 500

// OpenLedger opens a ledger, reading today's totals back so a restart does
// not refill every budget.
func OpenLedger(path string, now time.Time) (*Ledger, error) {
	l := &Ledger{path: path, day: now.UTC().Format("2006-01-02"), month: now.UTC().Format("2006-01"),
		used: map[string]int{}, tokens: map[string]int{}, cost: map[string]Money{}, monthCost: map[string]Money{}}
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		var u Usage
		if json.Unmarshal([]byte(line), &u) != nil {
			continue
		}
		l.keep(u)
	}
	return l, nil
}

func (l *Ledger) keep(u Usage) {
	if u.Outcome == "ok" || u.Outcome == "failed" {
		for _, who := range u.payers() {
			if u.At.UTC().Format("2006-01-02") == l.day {
				l.used[who] += u.In + u.Out
				l.tokens[who] += u.TokensIn + u.TokensOut
				l.cost[who] += u.Cost
			}
			if u.At.UTC().Format("2006-01") == l.month {
				l.monthCost[who] += u.Cost
			}
		}
	}
	l.all = append(l.all, u)
	if len(l.all) > MaxKept {
		l.all = l.all[len(l.all)-MaxKept:]
	}
}

func (l *Ledger) record(u Usage) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(u.At)
	l.keep(u)
	b, err := json.Marshal(u)
	if err != nil || l.path == "" {
		return
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
}

func (l *Ledger) roll(now time.Time) {
	if day := now.UTC().Format("2006-01-02"); day != l.day {
		l.day, l.used, l.tokens, l.cost = day, map[string]int{}, map[string]int{}, map[string]Money{}
	}
	if month := now.UTC().Format("2006-01"); month != l.month {
		l.month, l.monthCost = month, map[string]Money{}
	}
}

// TodayTokens is how many tokens a caller has used today.
func (l *Ledger) TodayTokens(consumer string, now time.Time) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(now)
	return l.tokens[consumer]
}

// TodayCost is what a caller has spent today.
func (l *Ledger) TodayCost(consumer string, now time.Time) Money {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(now)
	return l.cost[consumer]
}

// MonthCost is what a caller has spent this calendar month (UTC).
func (l *Ledger) MonthCost(consumer string, now time.Time) Money {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(now)
	return l.monthCost[consumer]
}

// Today is how many characters a caller has used today.
func (l *Ledger) Today(consumer string, now time.Time) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(now)
	return l.used[consumer]
}

// Spend is one caller's day, for the screen.
type Spend struct {
	Consumer string
	Chars    int
	Calls    int
	Failed   int
	Refused  int
	Budget   int
	// Tokens and Cost are today's; Month is this month's cost, and the
	// money budgets what applies.
	Tokens       int
	Cost         Money
	Month        Money
	DayBudget    Money
	MonthBudget  Money
	TokensBudget int
}

// Summary is today's spending by caller, largest first.
func (l *Ledger) Summary(cfg Config, now time.Time) []Spend {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(now)
	by := map[string]*Spend{}
	for _, u := range l.all {
		if u.At.UTC().Format("2006-01-02") != l.day {
			continue
		}
		for _, who := range u.payers() {
			s, ok := by[who]
			if !ok {
				s = &Spend{Consumer: who}
				if b, has := cfg.BudgetFor(who); has {
					s.Budget, s.TokensBudget = b.CharsPerDay, b.TokensPerDay
					s.DayBudget, s.MonthBudget, _ = b.caps()
				}
				by[who] = s
			}
			switch u.Outcome {
			case "ok":
				s.Calls++
			case "failed":
				s.Failed++
			case "over-budget":
				s.Refused++
			}
		}
	}
	var out []Spend
	for who, s := range by {
		s.Chars, s.Tokens, s.Cost, s.Month = l.used[who], l.tokens[who], l.cost[who], l.monthCost[who]
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Chars != out[j].Chars {
			return out[i].Chars > out[j].Chars
		}
		return out[i].Consumer < out[j].Consumer
	})
	return out
}

// Trouble says whether a provider's refusal is one a person must hear of:
// "route-auth" for a key that is wrong or revoked, "route-spent" for an
// account that has reached its spend cap or run out of credit. Anything
// else, an outage or a slow answer, is the ordinary failure the cooldown
// is for.
func Trouble(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "returned 401"), strings.Contains(msg, "returned 403"):
		return "route-auth"
	case strings.Contains(msg, "returned 429"), strings.Contains(msg, "returned 400"), strings.Contains(msg, "returned 402"):
		for _, w := range []string{"spend_limit", "spend limit", "usage limit", "usage_limit", "credit_balance", "credit balance",
			"insufficient_quota", "billing", "quota exceeded"} {
			if strings.Contains(msg, w) {
				return "route-spent"
			}
		}
	}
	return ""
}
