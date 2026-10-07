// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/fleet"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/oauthas"
	"github.com/quilzo/quilzo/internal/shield"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// The fleet: every agent this organisation runs or uses, who called what,
// and the AI use nobody registered. See internal/fleet.

func fleetPath(root string) string { return filepath.Join(root, "fleet.json") }

func loadFleet(root string) (*fleet.Registry, error) {
	r := &fleet.Registry{}
	if err := loadJSON(fleetPath(root), r); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return r, nil
}

// cardFetch reads an agent card: https only, outside this network (the
// fetch client's rules), no redirects, at most 64 kilobytes.
var cardFetch = func(ctx context.Context, cardURL string) ([]byte, error) {
	u, err := url.Parse(cardURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("an agent card is read over https, from an address with no credentials in it")
	}
	c := fetch.New()
	c.Purpose = "fleet"
	c.UserAgent = "quilzo/1 (+fleet)"
	c.Limits = fetch.Limits{MaxBytes: fleet.MaxCard + 1, Timeout: 10 * time.Second, MaxRedirects: -1}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := c.GetAccepting(ctx, cardURL, "application/json")
	if err != nil {
		return nil, err
	}
	if res.Status != 200 {
		return nil, fmt.Errorf("it answered %d", res.Status)
	}
	if res.Truncated {
		return nil, errors.New("the card is more than 64 kilobytes")
	}
	return res.Body, nil
}

// fleetRegister registers another vendor's agent by its card.
func fleetRegister(root, cardURL, name string, by *Caller, now time.Time) (fleet.External, error) {
	if err := authorise(root, by, auth.ActGrant, "/"); err != nil {
		return fleet.External{}, fmt.Errorf("registering another vendor's agent is an administrator's: %w", err)
	}
	body, err := cardFetch(context.Background(), cardURL)
	if err != nil {
		return fleet.External{}, fmt.Errorf("the card at %s could not be read: %w", cardURL, err)
	}
	e, err := fleet.ReadCard(body, cardURL)
	if err != nil {
		return fleet.External{}, err
	}
	if name != "" {
		e.Name = name
	}
	e.Sponsor, e.Added, e.Checked = by.Name, now.UTC(), now.UTC()
	reg, err := loadFleet(root)
	if err != nil {
		return e, err
	}
	if err := reg.Add(e); err != nil {
		return e, err
	}
	if err := saveJSON(fleetPath(root), reg); err != nil {
		return e, err
	}
	return e, recordE(root, by.auditRecord("fleet.registered", "/fleet", audit.Success,
		map[string]string{"agent": e.Name, "card": cardURL, "card_sha256": e.Digest}))
}

// fleetUnregister takes another vendor's agent off the fleet.
func fleetUnregister(root, name string, by *Caller) error {
	if err := authorise(root, by, auth.ActGrant, "/"); err != nil {
		return fmt.Errorf("removing another vendor's agent is an administrator's: %w", err)
	}
	reg, err := loadFleet(root)
	if err != nil {
		return err
	}
	if !reg.Remove(name) {
		return fmt.Errorf("no agent called %s is registered", name)
	}
	if err := saveJSON(fleetPath(root), reg); err != nil {
		return err
	}
	return recordE(root, by.auditRecord("fleet.removed", "/fleet", audit.Success, map[string]string{"agent": name}))
}

// fleetCheck reads every registered card again and marks the ones that
// say something else now.
func fleetCheck(root string, now time.Time) ([]string, error) {
	reg, err := loadFleet(root)
	if err != nil {
		return nil, err
	}
	var changed []string
	for i := range reg.Agents {
		e := &reg.Agents[i]
		body, err := cardFetch(context.Background(), e.CardURL)
		if err != nil {
			continue // unreachable today is not changed
		}
		now := now.UTC()
		e.Checked = now
		if got, err := fleet.ReadCard(body, e.CardURL); err == nil && got.Digest != e.Digest && !e.Changed {
			e.Changed = true
			changed = append(changed, e.Name)
			record(root, audit.Record{Action: "fleet.card-changed", Resource: "/fleet", Outcome: audit.Success,
				Principal: "quilzo", Kind: audit.KindService, Verified: true,
				Detail: map[string]string{"agent": e.Name, "card_sha256": got.Digest, "was": e.Digest}})
		}
	}
	return changed, saveJSON(fleetPath(root), reg)
}

// pseudonyms resolves the log's handles for people back to names, for an
// administrator's view: the people who have access here, their tokens and
// their app connections.
func pseudonyms(root string) func(string) string {
	l, err := openAudit(root)
	if err != nil {
		return func(s string) string { return s }
	}
	names := map[string]bool{}
	if pol, err := loadPolicy(root); err == nil && pol != nil {
		for _, n := range pol.Principals() {
			names[n] = true
		}
	}
	if toks, err := loadTokens(root); err == nil {
		for _, t := range toks.Snapshot() {
			names[t.Principal] = true
		}
	}
	if grants, err := (&oauthas.Store{Dir: oauthDir(root)}).Grants(); err == nil {
		for _, g := range grants {
			names[g.Principal] = true
		}
	}
	byHandle := map[string]string{}
	for n := range names {
		if l.Pseudonymous() {
			byHandle[audit.Pseudonym(l.Key(), n)] = n
		}
	}
	return func(s string) string {
		if n, ok := byHandle[s]; ok {
			return n
		}
		return s
	}
}

// buildFleet is the fleet, as of now, with the last days of calls.
func buildFleet(root string, days int, now time.Time) (fleet.View, error) {
	v := fleet.View{Days: days}
	since := now.Add(-time.Duration(days) * 24 * time.Hour)
	set, err := loadAgents(root)
	if err != nil {
		return v, err
	}
	gw, cfg, _ := modelGateway(root)
	names := make([]string, 0, len(set.Agents))
	for n := range set.Agents {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		m := set.Agents[name]
		n := fleet.Node{ID: "agent:" + name, Kind: fleet.KindAgent, Name: name, Detail: m.Purpose, Autonomy: string(m.Autonomy)}
		if id := set.identityOf(name); id != nil {
			n.Owner = id.Sponsor
			switch {
			case !hasStanding(root, id.Sponsor):
				n.Standing = "its sponsor can no longer act here"
			case now.After(id.Expires):
				n.Standing = "ended " + id.Expires.UTC().Format("2 Jan 2006")
			default:
				n.Standing = "until " + id.Expires.UTC().Format("2 Jan 2006")
			}
		} else {
			n.Standing = "nobody answers for it"
		}
		if p, on := shield.Find(root, shield.Agent, name, now); on {
			n.Flags = append(n.Flags, "paused by the shield until "+p.Until.UTC().Format("15:04 UTC")+": "+p.Reason)
		}
		if at, why := trustLost(root, name); !at.IsZero() && now.Sub(at) < 30*24*time.Hour {
			n.Flags = append(n.Flags, "trust lost "+at.UTC().Format("2 Jan")+": "+why)
		}
		if gw != nil {
			if s := gw.TodaySpend("agent:"+name, now); s > 0 {
				n.Spent = s.String() + " " + cfg.Currency + " today"
			}
		}
		v.Nodes = append(v.Nodes, n)
	}
	if grants, err := (&oauthas.Store{Dir: oauthDir(root)}).Grants(); err == nil {
		byClient := map[string]*fleet.Node{}
		for _, g := range grants {
			if !g.Live(now) {
				continue
			}
			n := byClient[g.Client]
			if n == nil {
				n = &fleet.Node{ID: "app:" + g.Client, Kind: fleet.KindApp, Name: nonEmpty(g.ClientName, g.Client)}
				byClient[g.Client] = n
			}
			n.Detail = strings.TrimPrefix(n.Detail+", "+g.Principal+" ("+strings.Join(g.Scopes, " ")+")", ", ")
			if g.LastUsed.After(n.Last) {
				n.Last = g.LastUsed
			}
		}
		clients := make([]string, 0, len(byClient))
		for c := range byClient {
			clients = append(clients, c)
		}
		sort.Strings(clients)
		for _, c := range clients {
			n := byClient[c]
			n.Detail = "connected for " + n.Detail
			v.Nodes = append(v.Nodes, *n)
		}
	}
	if ins, err := loadIntegrations(root); err == nil {
		for _, in := range ins.Declared {
			n := fleet.Node{ID: "tool:" + in.Name, Kind: fleet.KindTool, Name: in.Name, Detail: in.Purpose,
				Standing: map[bool]string{true: "enabled", false: "declared, off"}[in.Enabled]}
			if in.Endpoint != "" {
				n.Detail += " (" + in.Endpoint + ")"
			}
			if in.Gateway != nil {
				n.Flags = append(n.Flags, "offered through the gateway to "+in.Gateway.Role+"s")
			}
			unpinned := 0
			for _, u := range in.Uses {
				if in.Pins[u] == "" {
					unpinned++
				}
			}
			if unpinned > 0 {
				n.Flags = append(n.Flags, count(unpinned, "tool")+" nobody pinned")
			}
			v.Nodes = append(v.Nodes, n)
		}
	}
	if cfg != nil {
		for _, r := range cfg.Routes {
			n := fleet.Node{ID: "route:" + r.Name, Kind: fleet.KindRoute, Name: r.Name, Detail: r.Model}
			if u, err := url.Parse(r.URL); err == nil {
				n.Detail += " at " + u.Host
			}
			if r.Personal {
				n.Flags = append(n.Flags, "may receive personal data")
			}
			v.Nodes = append(v.Nodes, n)
		}
	}
	if reg, err := loadFleet(root); err == nil {
		for _, e := range reg.Agents {
			n := fleet.Node{ID: "external:" + e.Name, Kind: fleet.KindExternal, Name: e.Name, Detail: e.Description,
				Owner: e.Sponsor, Standing: e.Protocol, Last: e.Checked}
			if e.Provider != "" {
				n.Detail = e.Provider + ": " + n.Detail
			}
			if e.Changed {
				n.Flags = append(n.Flags, "its card has changed since it was registered")
			}
			v.Nodes = append(v.Nodes, n)
		}
	}

	// Who called what, from the log and the model ledger.
	who := pseudonyms(root)
	var edges fleet.Edges
	touch := func(id, kind, name string, at time.Time) {
		v.Touch(id, kind, name, at)
	}
	if events, err := audit.Read(auditPath(root)); err == nil {
		for _, e := range events {
			at, err := time.Parse(time.RFC3339, e.At)
			if err != nil || at.Before(since) {
				continue
			}
			person := who(e.Detail["on_behalf_of"])
			switch e.Action {
			case "agent.run":
				a := "agent:" + e.Detail["agent"]
				touch(a, fleet.KindAgent, e.Detail["agent"], at)
				if person != "" {
					touch("person:"+person, fleet.KindPerson, person, at)
					edges.Add("person:"+person, a, at)
				}
			case "agent.action":
				if tool := e.Detail["tool"]; tool != "" {
					a := "agent:" + e.Detail["agent"]
					to := toolServerOf(root, tool)
					touch(to, fleet.KindTool, strings.TrimPrefix(to, "tool:"), at)
					edges.Add(a, to, at)
				}
			case "agent.egress":
				to := "host:" + e.Detail["host"]
				touch(to, "host", e.Detail["host"], at)
				edges.Add("agent:"+e.Detail["agent"], to, at)
			case "mcp.call", "mcp.gateway":
				from := "app:" + e.Model
				if e.Model == "" {
					from = "person:" + person
				}
				to := "quilzo"
				if e.Action == "mcp.gateway" {
					to = "tool:" + e.Detail["integration"]
				}
				touch(from, fleet.KindApp, e.Model, at)
				touch(to, fleet.KindQuilzo, "Quilzo's interface", at)
				edges.Add(from, to, at)
				if person != "" && e.Model != "" {
					touch("person:"+person, fleet.KindPerson, person, at)
					edges.Add("person:"+person, from, at)
				}
			case "a2a.task":
				a := "agent:" + e.Detail["agent"]
				from := "person:" + person
				if e.Model != "" {
					from = "app:" + e.Model
				}
				edges.Add(from, a, at)
			}
		}
	}
	for _, u := range recentUsage(root, since) {
		from := u.Consumer
		switch {
		case strings.HasPrefix(from, "agent:"):
		case strings.HasPrefix(from, "chatbot:"):
			touch(from, "chatbot", strings.TrimPrefix(from, "chatbot:"), u.At)
		default:
			touch(from, "feature", from, u.At)
		}
		to := "route:" + nonEmpty(u.Route, "direct")
		touch(to, fleet.KindRoute, nonEmpty(u.Route, "the configured model"), u.At)
		edges.Add(from, to, u.At)
	}
	v.Edges = edges.List()
	v.Shadow = shadowAI(root, since, now)
	return v, nil
}

// toolServerOf is the integration that offers a tool, for an edge.
func toolServerOf(root, tool string) string {
	if ins, err := loadIntegrations(root); err == nil {
		for _, in := range ins.Declared {
			for _, u := range in.Uses {
				if u == tool {
					return "tool:" + in.Name
				}
			}
		}
	}
	return "tool:" + tool
}

// recentUsage is the model ledger since a time.
func recentUsage(root string, since time.Time) []gateway.Usage {
	f, err := os.Open(usagePath(root))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []gateway.Usage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var u gateway.Usage
		if json.Unmarshal(sc.Bytes(), &u) == nil && !u.At.Before(since) {
			out = append(out, u)
		}
	}
	return out
}

// shadowAI is direct use of AI services: in the security events collected
// from other systems, and in this install's own agents' connections.
func shadowAI(root string, since, now time.Time) []fleet.Sighting {
	var events []telemetry.Event
	if sp, err := openSpool(root, spool.Options{}); err == nil {
		_ = sp.Range(since, now, func(e telemetry.Event) error {
			events = append(events, e)
			return nil
		})
		_ = sp.Close() // a reader's close, as the other readers make it
	}
	// The log's own records of agents' programs reaching a host, as events.
	if recs, err := audit.Read(auditPath(root)); err == nil {
		for _, e := range recs {
			at, err := time.Parse(time.RFC3339, e.At)
			if e.Action == "agent.egress" && err == nil && !at.Before(since) {
				events = append(events, telemetry.Event{Time: at, Source: "agents/egress",
					Actor: telemetry.ID{Issuer: "agent", Value: e.Detail["agent"]},
					Raw:   map[string]string{"host": e.Detail["host"]}})
			}
		}
	}
	return fleet.Sightings(events, func(e telemetry.Event) bool {
		// Quilzo's own model calls go through the gateway; what it collects
		// about itself is not somebody else's AI use.
		return strings.HasPrefix(e.Source, "quilzo/")
	})
}

// cmdFleet is `quilzo fleet [--days N] | add CARD_URL [--name N] | remove NAME | check | shadow [--days N]`.
func cmdFleet(root string, args []string) error {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "add":
			fs := flag.NewFlagSet("fleet add", flag.ContinueOnError)
			name := fs.String("name", "", "what it is called here")
			pos, rest := leadingArgs(args[1:], 1)
			if err := fs.Parse(rest); err != nil {
				return err
			}
			if len(pos) != 1 {
				return errors.New("quilzo fleet add CARD_URL [--name NAME]")
			}
			e, err := fleetRegister(root, pos[0], *name, resolveCaller(root, flagToken), time.Now())
			if err != nil {
				return err
			}
			w.Human("registered %s (%s), %s; you answer for it here\n", e.Name, nonEmpty(e.Provider, "no provider named"), nonEmpty(e.Protocol, "no endpoint"))
			return nil
		case "remove":
			if len(args) != 2 {
				return errors.New("quilzo fleet remove NAME")
			}
			return fleetUnregister(root, args[1], resolveCaller(root, flagToken))
		case "check":
			changed, err := fleetCheck(root, time.Now())
			if err != nil {
				return err
			}
			if len(changed) == 0 {
				w.Human("no registered agent's card has changed\n")
			}
			for _, n := range changed {
				w.Human("%s%s's card has changed since it was registered%s\n", yellow, n, reset)
			}
			return nil
		case "shadow":
			fs := flag.NewFlagSet("fleet shadow", flag.ContinueOnError)
			days := fs.Int("days", 30, "how far back")
			if err := fs.Parse(args[1:]); err != nil {
				return err
			}
			now := time.Now()
			s := shadowAI(root, now.Add(-time.Duration(*days)*24*time.Hour), now)
			if w.JSON(s) {
				return nil
			}
			if len(s) == 0 {
				w.Human("no direct use of an AI service in the last %d days, in what this install collects\n", *days)
			}
			for _, x := range s {
				w.Human("%s%s%s  %s by %s, %s, last %s (%s)\n", bold, x.Service, reset, x.Where, nonEmpty(x.Who, "somebody"),
					count(x.Count, "time"), x.Last.UTC().Format("2006-01-02"), x.Source)
			}
			return nil
		default:
			return fmt.Errorf("unknown fleet command %q; try add, remove, check or shadow", args[0])
		}
	}
	fs := flag.NewFlagSet("fleet", flag.ContinueOnError)
	days := fs.Int("days", 30, "how far back calls are read")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, err := buildFleet(root, *days, time.Now())
	if err != nil {
		return err
	}
	if w.JSON(v) {
		return nil
	}
	kind := ""
	for _, n := range v.Nodes {
		if n.Kind == fleet.KindPerson || n.Kind == fleet.KindQuilzo || n.Kind == "feature" || n.Kind == "host" {
			continue
		}
		if n.Kind != kind {
			kind = n.Kind
			w.Human("\n%s%ss%s\n", bold, kind, reset)
		}
		w.Human("  %s  %s", n.Name, clip(n.Detail, 80))
		for _, x := range []string{n.Owner, n.Standing, n.Autonomy, n.Spent} {
			if x != "" {
				w.Human("  %s%s%s", dim, x, reset)
			}
		}
		w.Human("\n")
		for _, f := range n.Flags {
			w.Human("    %s%s%s\n", yellow, f, reset)
		}
	}
	if len(v.Edges) > 0 {
		w.Human("\n%swho called what, in the last %d days%s\n", bold, v.Days, reset)
		for _, e := range v.Edges {
			w.Human("  %s → %s  %s\n", e.From, e.To, count(e.Calls, "call"))
		}
	}
	if len(v.Shadow) > 0 {
		w.Human("\n%sAI used directly, not through Quilzo%s\n", bold, reset)
		for _, x := range v.Shadow {
			w.Human("  %s  %s by %s, %s\n", x.Service, x.Where, nonEmpty(x.Who, "somebody"), count(x.Count, "time"))
		}
	}
	return nil
}
