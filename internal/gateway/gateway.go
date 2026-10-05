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
}

// Config is the gateway's declaration.
type Config struct {
	// Routes in fallback order: the first that answers is used.
	Routes  []Route  `json:"routes"`
	Budgets []Budget `json:"budgets,omitempty"`
}

var (
	reName   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	reEnv    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	reWho    = regexp.MustCompile(`^(\*|[a-z][a-z0-9-]*(:[a-z0-9][a-z0-9-]{0,62})?)$`)
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
		if b.PerMinute < 0 || b.CharsPerDay < 0 {
			return fmt.Errorf("%s's budget is negative", b.Consumer)
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

// For is the model a caller uses.
func (g *Gateway) For(consumer string) Model { return &bound{g: g, consumer: consumer} }

type bound struct {
	g        *Gateway
	consumer string
}

func (b *bound) Name() string { return "gateway:" + b.consumer }

func (b *bound) Complete(ctx context.Context, system, user string) (string, error) {
	return b.g.complete(ctx, b.consumer, system, user)
}

// admit charges a call against its caller's budget, or refuses it.
func (g *Gateway) admit(consumer string, chars int) error {
	b, ok := g.cfg.BudgetFor(consumer)
	if !ok {
		return nil
	}
	now := g.now()
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

func (g *Gateway) complete(ctx context.Context, consumer, system, user string) (string, error) {
	in := len(system) + len(user)
	if err := g.admit(consumer, in); err != nil {
		g.ledger.record(Usage{At: g.now(), Consumer: consumer, In: in, Outcome: "over-budget"})
		if g.OnTrouble != nil {
			g.OnTrouble("spent", consumer)
		}
		return "", err
	}
	if len(g.cfg.Routes) == 0 {
		return "", ErrNoRoute
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
		out, err := m.Complete(ctx, system, user)
		took := g.now().Sub(start)
		if err != nil {
			if kind := Trouble(err); kind != "" && g.OnTrouble != nil {
				g.OnTrouble(kind, r.Name)
			}
			g.failed(r.Name)
			g.ledger.record(Usage{At: start, Consumer: consumer, Route: r.Name,
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
		g.ledger.record(Usage{At: start, Consumer: consumer, Route: r.Name,
			Model: r.Model, In: in, Out: len(out), Millis: took.Milliseconds(),
			Outcome: "ok"})
		return out, nil
	}
	return "", fmt.Errorf("%w: %s", ErrNoRoute, strings.Join(errs, "; "))
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
	Route    string    `json:"route,omitempty"`
	Model    string    `json:"model,omitempty"`
	In       int       `json:"in"`
	Out      int       `json:"out,omitempty"`
	Millis   int64     `json:"ms,omitempty"`
	Outcome  string    `json:"outcome"`
}

// Ledger records usage to a file and keeps today's totals in memory.
type Ledger struct {
	path string
	mu   sync.Mutex
	day  string
	used map[string]int
	all  []Usage
}

// MaxKept is how many recent calls the ledger keeps in memory for display.
const MaxKept = 500

// OpenLedger opens a ledger, reading today's totals back so a restart does
// not refill every budget.
func OpenLedger(path string, now time.Time) (*Ledger, error) {
	l := &Ledger{path: path, day: now.UTC().Format("2006-01-02"), used: map[string]int{}}
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
	if day := u.At.UTC().Format("2006-01-02"); day == l.day {
		if u.Outcome == "ok" || u.Outcome == "failed" {
			l.used[u.Consumer] += u.In + u.Out
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
		l.day, l.used = day, map[string]int{}
	}
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
		s, ok := by[u.Consumer]
		if !ok {
			s = &Spend{Consumer: u.Consumer}
			if b, has := cfg.BudgetFor(u.Consumer); has {
				s.Budget = b.CharsPerDay
			}
			by[u.Consumer] = s
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
	var out []Spend
	for who, s := range by {
		s.Chars = l.used[who]
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
