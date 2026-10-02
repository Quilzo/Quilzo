// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/automate"
	"github.com/quilzo/quilzo/internal/estate"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/geo"
	"github.com/quilzo/quilzo/internal/incident"
	"github.com/quilzo/quilzo/internal/travel"
)

// Automations: the rules (internal/automate), the actions they may take
// here, where sign-ins come from (internal/geo) and each person's recent
// ones (internal/travel).
//
// What acts here acts on this program: stepping a session up, ending a
// person's sessions, telling somebody, opening a case. What would change
// another system — suspending an Okta account — is never sent by a rule:
// the rule opens a case and asks for it there, where actions have always
// needed a second person to approve the exact call (see actioncmd.go).

func automatePath(root string) string { return filepath.Join(root, "automate.json") }
func signinsPath(root string) string  { return filepath.Join(root, "signins") }
func geoPath(root string) string      { return filepath.Join(root, "geo.json") }
func geoDBPath(root string) string    { return filepath.Join(root, "geo", "city.mmdb") }
func geoASNPath(root string) string   { return filepath.Join(root, "geo", "asn.mmdb") }
func geoTorPath(root string) string   { return filepath.Join(root, "geo", "tor-exits.txt") }

// automateBy is who the audit log says acted, for what rules do.
const automateBy = "automation"

type geoConfig struct {
	Networks []geo.Network `json:"networks"`
}

func loadGeo(root string) (*geo.Locator, string, error) {
	var c geoConfig
	if b, err := os.ReadFile(geoPath(root)); err == nil {
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, "", fmt.Errorf("geo.json: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	l := &geo.Locator{Networks: c.Networks}
	desc := fmt.Sprintf("Places come from %d network(s) you declared", len(c.Networks))
	if b, err := os.ReadFile(geoDBPath(root)); err == nil {
		db, oerr := geo.Open(b)
		if oerr != nil {
			return nil, "", fmt.Errorf("%s: %w", geoDBPath(root), oerr)
		}
		l.DB = db
		desc += " and " + db.Type + " (DB-IP, CC BY 4.0)"
	} else {
		desc += "; with no city database, other addresses are not placed (quilzo geo help)"
	}
	if b, err := os.ReadFile(geoASNPath(root)); err == nil {
		db, oerr := geo.Open(b)
		if oerr != nil {
			return nil, "", fmt.Errorf("%s: %w", geoASNPath(root), oerr)
		}
		l.ASNDB = db
		desc += "; networks named from " + db.Type
	}
	if b, err := os.ReadFile(geoTorPath(root)); err == nil {
		l.Tor = geo.ParseTorExits(b)
		desc += fmt.Sprintf("; %d Tor exits known", len(l.Tor))
	}
	return l, desc + ".", nil
}

// automationEngine is the rules over this store. The server runs actions in
// the background, so no request waits on a mail server; the command line
// does them before it returns, so a run is finished when it exits.
// geoCache keeps the locator and reloads it only when the networks file
// or the city database changes: the database is tens of megabytes, and a
// sign-in must not read it.
type geoCache struct {
	mu          sync.Mutex
	cfgAt, dbAt time.Time
	dbSize      int64
	loc         *geo.Locator
	desc        string
	err         error
	loaded      bool
}

var (
	geoCachesMu sync.Mutex
	geoCaches   = map[string]*geoCache{}
)

func cachedGeo(root string) (*geo.Locator, string, error) {
	geoCachesMu.Lock()
	c := geoCaches[root]
	if c == nil {
		c = &geoCache{}
		geoCaches[root] = c
	}
	geoCachesMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	var cfgAt, dbAt time.Time
	var dbSize int64
	if fi, err := os.Stat(geoPath(root)); err == nil {
		cfgAt = fi.ModTime()
	}
	// Any of the data files changing reloads them all.
	for _, p := range []string{geoDBPath(root), geoASNPath(root), geoTorPath(root)} {
		if fi, err := os.Stat(p); err == nil {
			if fi.ModTime().After(dbAt) {
				dbAt = fi.ModTime()
			}
			dbSize += fi.Size()
		}
	}
	if !c.loaded || !cfgAt.Equal(c.cfgAt) || !dbAt.Equal(c.dbAt) || dbSize != c.dbSize {
		c.loc, c.desc, c.err = loadGeo(root)
		c.cfgAt, c.dbAt, c.dbSize, c.loaded = cfgAt, dbAt, dbSize, true
	}
	return c.loc, c.desc, c.err
}

func automationEngine(root string) *automate.Engine {
	return &automate.Engine{Path: automatePath(root), Actions: automationActions(root)}
}

func automationEngineAsync(root string) *automate.Engine {
	e := automationEngine(root)
	e.Async = true
	return e
}

// securityAddress is the first mail address in security.contact.
func securityAddress(root string) string {
	cfg, err := loadConfig(root)
	if err != nil || cfg == nil {
		return ""
	}
	for _, c := range splitList(cfg.Raw("security.contact")) {
		if addr, ok := strings.CutPrefix(strings.TrimSpace(c), "mailto:"); ok {
			return addr
		}
	}
	return ""
}

func automationActions(root string) map[string]automate.Action {
	mail := func(to, subject, body string) error {
		m, err := loadMailConfig(root)
		if err != nil {
			return err
		}
		if m == nil {
			return errors.New("no mail is set up (quilzo notify mail), so nobody was told; it is in the history and the audit log")
		}
		return m.SendPlain(to, subject, body)
	}
	ownSessions := func(principal string, what func(ts tokenStoreLike) int) (int, error) {
		ts, err := loadTokens(root)
		if err != nil {
			return 0, err
		}
		n := what(ts)
		if n == 0 {
			return 0, nil
		}
		return n, saveJSON(tokensPath(root), ts)
	}
	acts := map[string]automate.Action{
		"step-up": {ID: "step-up", Name: "Make them prove it is them",
			Does:   "the sign-in gets no session until its person confirms it with a passkey or a code, or an administrator lets them in; for anything else, every session they have open does the same",
			Undo:   "Undone by the person confirming it is them.",
			Kinds:  []string{"signin", "finding", "person"},
			Inline: true,
			Access: true,
			Run: func(ev automate.Event, _ map[string]string) (string, error) {
				n, err := ownSessions(ev.Subject, func(ts tokenStoreLike) int {
					return ts.RequireStepUpFor(ev.Subject, ev.Summary, time.Now())
				})
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("%d open session(s) must now confirm it is them", n), nil
			}},
		"end-sessions": {ID: "end-sessions", Name: "Sign them out of Quilzo",
			Does:   "ends every session and token they hold here",
			Undo:   "Undone by signing in again; a token has to be issued afresh.",
			Kinds:  []string{"signin", "finding", "person"},
			Access: true,
			Run: func(ev automate.Event, _ map[string]string) (string, error) {
				n, err := ownSessions(ev.Subject, func(ts tokenStoreLike) int {
					ended := 0
					for _, t := range ts.Snapshot() {
						if strings.EqualFold(t.Principal, ev.Subject) && !t.Revoked {
							if _, err := ts.Revoke(t.ID); err == nil {
								ended++
							}
						}
					}
					return ended
				})
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("ended %d session(s) and token(s)", n), nil
			}},
		"notify": {ID: "notify", Name: "Tell somebody",
			Does:   "sends an email to the security team (security.contact) or to the person it is about",
			Undo:   "A message cannot be unsent.",
			Kinds:  []string{"signin", "finding", "device", "person"},
			Params: []automate.Param{{Name: "to", Choices: []string{"security", "person"}}},
			Run: func(ev automate.Event, with map[string]string) (string, error) {
				to := securityAddress(root)
				if with["to"] == "person" {
					to = ev.Fields["owner"]
					if to == "" && strings.Contains(ev.Subject, "@") {
						to = ev.Subject
					}
				}
				if to == "" {
					return "", errors.New("there is no address to send it to")
				}
				// One line: a name with a line break in it, from a tool,
				// must not cost the message (mail refuses broken headers).
				subject := "Quilzo: " + onOneLine(ev.Summary)
				if err := mail(to, subject, ev.Summary+"\n\nThis was sent by an automation in Quilzo."); err != nil {
					return "", err
				}
				return "told " + to, nil
			}},
		"open-case": {ID: "open-case", Name: "Open a case",
			Does:  "opens an incident with what happened, linked to the finding when there is one",
			Undo:  "A case is closed, not deleted.",
			Kinds: []string{"signin", "finding", "device", "person"},
			Run: func(ev automate.Event, _ map[string]string) (string, error) {
				grade := incident.Sev3
				if s := ev.Fields["severity"]; s == "critical" || s == "high" || ev.Fields["signal"] == "impossible-travel" {
					grade = incident.Sev2
				}
				var findings []string
				if id := ev.Fields["finding"]; id != "" {
					findings = append(findings, id)
				}
				title := ev.Summary
				if len(title) > 180 {
					title = title[:180]
				}
				caller := &Caller{Name: automateBy, Kind: audit.KindService, Verified: true}
				i, err := declareIncident(root, caller, title, grade, nil, findings, time.Now().UTC())
				if err != nil {
					return "", err
				}
				return "opened " + i.ID, nil
			}},
	}
	// What changes another system is asked for in a case, never sent here.
	for _, ext := range []struct{ id, name, does string }{
		{"okta-suspend-user", "Suspend them in Okta", "asks, in a case, for their Okta account to be suspended"},
		{"okta-clear-sessions", "End their Okta sessions", "asks, in a case, for every Okta session they have to be ended"},
	} {
		ext := ext
		acts[ext.id] = automate.Action{ID: ext.id, Name: ext.name, Does: ext.does,
			Undo:   "Nothing is sent until a second person approves it in the case, and it can be undone there.",
			Kinds:  []string{"finding"},
			Access: true,
			Run: func(ev automate.Event, _ map[string]string) (string, error) {
				return requestFromRule(root, ev, ext.id)
			}}
	}
	return acts
}

// tokenStoreLike is the token store the session actions change.
type tokenStoreLike = *auth.TokenStore

// requestFromRule opens a case for the finding and asks for the action in
// it, as a person would; approving it stays a person's job.
func requestFromRule(root string, ev automate.Event, name string) (string, error) {
	id := ev.Fields["finding"]
	if id == "" {
		return "", errors.New("this can only be asked for about a finding")
	}
	if _, err := findAction(root, name); err != nil {
		return "", fmt.Errorf("%s is not installed (quilzo action add %s): %w", name, name, err)
	}
	caller := &Caller{Name: automateBy, Kind: audit.KindService, Verified: true}
	now := time.Now().UTC()
	i, err := declareIncident(root, caller, ev.Summary, incident.Sev2, nil, []string{id}, now)
	if err != nil {
		return "", err
	}
	if err := requestAct(root, i.ID, caller, name, ev.Subject, "raised by an automation: "+ev.Summary, now); err != nil {
		return "", err
	}
	return "asked for in " + i.ID + "; nothing is sent until a second person approves it there", nil
}

// signInRisk is the admin's sign-in check: place the address, judge it
// against the person's own history, and put any signal to the rules.
func signInRisk(root string) func(admin.SignInFacts) admin.SignInVerdict {
	store := &travel.Store{Dir: signinsPath(root)}
	engine := automationEngineAsync(root)
	return func(f admin.SignInFacts) admin.SignInVerdict {
		// Whatever cannot be read is said in the audit log and the sign-in
		// goes on: an unreadable rules file must not lock out the people
		// who would fix it. (A step-up that was decided and cannot be
		// recorded is the admin's to refuse.)
		trouble := func(what string, err error) {
			record(root, audit.Record{Action: "signin.check-degraded", Resource: "/", Outcome: audit.Failure,
				Principal: automateBy, Kind: audit.KindService, Verified: true,
				Detail: map[string]string{"subject": f.Principal, "what": what, "error": err.Error()}})
		}
		loc, _, err := cachedGeo(root)
		if err != nil {
			trouble("geo", err)
			loc = &geo.Locator{}
		}
		place, _ := loc.Locate(f.Addr)
		net := loc.Net(f.Addr)
		in := travel.SignIn{At: time.Now().UTC(), IP: f.Addr, Place: place, Device: travel.DeviceClass(f.Agent),
			How: f.How, ASN: net.ASN, Network: net.Org, Anon: net.Anon}
		judged, err := store.Check(f.Principal, in)
		if err != nil {
			trouble("history", err)
		}
		if f.Verifying || len(judged.Signals) == 0 {
			return admin.SignInVerdict{}
		}
		return signInEvent(root, engine, f, in, judged, trouble)
	}
}

// signInEvent puts one judged sign-in to the rules, as one event carrying
// every signal it raised, and says whether a rule stepped it up.
func signInEvent(root string, engine *automate.Engine, f admin.SignInFacts, in travel.SignIn,
	judged travel.Judged, trouble func(string, error)) admin.SignInVerdict {
	kinds := make([]string, 0, len(judged.Signals))
	primary := judged.Signals[0]
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	for _, sg := range judged.Signals {
		kinds = append(kinds, sg.Kind)
		if rank[sg.Severity()] > rank[primary.Severity()] {
			primary = sg
		}
		record(root, audit.Record{Action: "signin.signal", Resource: "/", Outcome: audit.Success,
			Principal: automateBy, Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"subject": f.Principal, "signal": sg.Kind, "detail": sg.Detail}})
	}
	fields := map[string]string{"signal": strings.Join(kinds, ","), "risk": judged.Risk,
		"score": strconv.FormatFloat(judged.Score, 'f', 1, 64), "how": f.How, "role": string(f.Role),
		"country": in.Place.Country, "network": in.Place.Kind, "provider": in.Network,
		"anon": in.Anon, "device": in.Device, "source": "quilzo", "history": strconv.Itoa(primary.History)}
	if in.ASN != 0 {
		fields["asn"] = strconv.FormatUint(uint64(in.ASN), 10)
	}
	for _, sg := range judged.Signals {
		if sg.Kind == "impossible-travel" {
			fields["from"], fields["to"] = sg.From.String(), sg.To.String()
			fields["km"], fields["kmh"] = strconv.Itoa(int(sg.Km)), strconv.Itoa(int(sg.KmH))
		}
	}
	out, err := engine.Handle(automate.Event{Kind: "signin", Subject: f.Principal,
		Summary: f.Principal + ": " + primary.Detail, Fields: fields})
	if err != nil {
		trouble("rules", err)
		return admin.SignInVerdict{}
	}
	if !out.StepUp {
		return admin.SignInVerdict{}
	}
	return admin.SignInVerdict{StepUp: true, Reason: primary.Detail}
}

// automateFindings puts newly opened findings to the rules.
func automateFindings(root string, opened []finding.Finding) {
	if len(opened) == 0 {
		return
	}
	engine := automationEngine(root)
	for _, f := range opened {
		subject := f.Entity.Value
		if f.Entity.Issuer != "" {
			subject = f.Entity.Issuer + ":" + f.Entity.Value
		}
		_, _ = engine.Handle(automate.Event{Kind: "finding", Subject: subject, Summary: f.Title,
			Fields: map[string]string{"source": f.Source, "severity": severityWord(f.Severity),
				"kind": string(f.Kind), "title": f.Title, "issuer": f.Entity.Issuer, "finding": f.ID}})
	}
}

// automateDevices puts machines' violations to the rules, each only the
// first time it is seen, so a laptop that stays unencrypted is not
// reported every time the tools are read.
func automateDevices(root string, e *estate.Estate, now time.Time) {
	seenPath := filepath.Join(estateDir(root), "automate-seen.json")
	seen := map[string]bool{}
	if b, err := os.ReadFile(seenPath); err == nil {
		_ = json.Unmarshal(b, &seen)
	}
	engine := automationEngine(root)
	current := map[string]bool{}
	for _, m := range e.Machines {
		c := estate.Comply(m, now)
		owner := ""
		if m.Owner != nil && len(m.Owner.Emails) > 0 {
			owner = m.Owner.Emails[0]
		}
		for _, v := range c.Violations() {
			key := m.Key + "/" + v.Control.ID
			current[key] = true
			if seen[key] {
				continue
			}
			_, _ = engine.Handle(automate.Event{Kind: "device", Subject: m.Name(),
				Summary: fmt.Sprintf("%s: %s (%s)", m.Name(), v.Control.Name, v.Detail),
				Fields: map[string]string{"control": v.Control.ID, "severity": severityWord(v.Control.Severity),
					"os": strings.TrimSpace(c.OS + " " + c.Version), "support": string(c.Lifecycle.Currency), "owner": owner}})
		}
	}
	// What is fixed is forgotten, so it is reported again if it comes back.
	b, err := json.Marshal(current)
	if err == nil {
		_ = atomicfile.Write(seenPath, b, 0o600)
	}
}

func automateUsage() error {
	return fmt.Errorf("usage: quilzo automate list | runs | templates | add TEMPLATE | mode ID watch|ask|act | on ID | off ID | remove ID | approve RUN | decline RUN")
}

func cmdAutomate(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	e := automationEngine(root)
	caller := resolveCaller(root, "")
	note := func(action, detail string) error {
		return recordE(root, caller.auditRecord(action, "/", audit.Success, map[string]string{"rule": detail}))
	}
	// A rule that acts on somebody's access, or approving what one waits
	// for, is a whole-site administrator's decision: an analyst who could
	// write "when anybody signs in, sign out the administrators" could
	// lock out everybody above them.
	siteAdmin := func(what string) error {
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return fmt.Errorf("%s acts on people's access, which takes an administrator of the whole site: %w", what, err)
		}
		return nil
	}
	find := func(id string) (automate.Rule, error) {
		rules, err := e.Rules()
		if err != nil {
			return automate.Rule{}, err
		}
		for _, r := range rules {
			if r.ID == id || strings.EqualFold(r.Name, id) {
				return r, nil
			}
		}
		return automate.Rule{}, fmt.Errorf("no rule %q (quilzo automate list)", id)
	}
	switch args[0] {
	case "list":
		rules, err := e.Rules()
		if err != nil {
			return err
		}
		if w.JSON(rules) {
			return nil
		}
		if len(rules) == 0 {
			w.Human("  no rules; quilzo automate templates lists ones to start from\n")
		}
		for _, r := range rules {
			state := r.Mode
			if !r.Enabled {
				state = "off"
			}
			w.Human("  %s%s%s  %s  [%s]\n", bold, r.ID, reset, onOneLine(r.Name), state)
		}
		return nil
	case "templates":
		if w.JSON(automate.Templates) {
			return nil
		}
		for _, t := range automate.Templates {
			w.Human("  %s%s%s  %s  [%s]\n", bold, strings.TrimPrefix(t.ID, "tpl-"), reset, t.Name, t.Mode)
		}
		return nil
	case "add":
		if len(args) != 2 {
			return automateUsage()
		}
		for _, t := range automate.Templates {
			if t.ID == args[1] || t.ID == "tpl-"+args[1] {
				if t.Access(e.Actions) {
					if err := siteAdmin(t.Name); err != nil {
						return err
					}
				}
				t.ID, t.Enabled = "", true
				saved, err := e.Save(t, caller.Name)
				if err != nil {
					return err
				}
				w.Human("added %s as %s, in %s mode\n", saved.Name, saved.ID, saved.Mode)
				return note("automation.added", saved.Name)
			}
		}
		return fmt.Errorf("no template %q (quilzo automate templates)", args[1])
	case "mode", "on", "off":
		want := 2
		if args[0] == "mode" {
			want = 3
		}
		if len(args) != want {
			return automateUsage()
		}
		r, err := find(args[1])
		if err != nil {
			return err
		}
		switch args[0] {
		case "mode":
			r.Mode = args[2]
		case "on":
			r.Enabled = true
		case "off":
			r.Enabled = false
		}
		if r.Enabled && r.Access(e.Actions) {
			if err := siteAdmin(r.Name); err != nil {
				return err
			}
		}
		if _, err := e.Save(r, caller.Name); err != nil {
			return err
		}
		w.Human("%s: %s\n", r.Name, map[bool]string{true: r.Mode, false: "off"}[r.Enabled])
		return note("automation.changed", r.Name)
	case "remove":
		if len(args) != 2 {
			return automateUsage()
		}
		r, err := find(args[1])
		if err != nil {
			return err
		}
		if err := e.Remove(r.ID); err != nil {
			return err
		}
		return note("automation.removed", r.Name)
	case "runs":
		runs, err := e.Runs()
		if err != nil {
			return err
		}
		if w.JSON(runs) {
			return nil
		}
		for i, r := range runs {
			if i >= 30 {
				break
			}
			w.Human("  %s  %s%s%s  %s  [%s]\n", r.At.Format("2006-01-02 15:04"), bold, r.Name, reset, onOneLine(r.Event.Summary), r.State)
			for _, s := range r.Steps {
				w.Human("      %s: %s\n", s.Name, onOneLine(s.Said))
			}
		}
		return nil
	case "approve", "decline":
		if len(args) != 2 {
			return automateUsage()
		}
		if args[0] == "approve" {
			runs, err := e.Runs()
			if err != nil {
				return err
			}
			for _, r := range runs {
				if r.ID == args[1] && r.Access(e.Actions) {
					if err := siteAdmin("approving " + r.Name); err != nil {
						return err
					}
				}
			}
		}
		run, err := e.Decide(args[1], args[0] == "approve", caller.Name)
		if err != nil {
			return err
		}
		w.Human("%s: %s\n", run.Name, run.State)
		return note("automation.run-"+run.State, run.Name)
	}
	return automateUsage()
}

func geoUsage() error {
	return fmt.Errorf("usage: quilzo geo status | network add PREFIX NAME --kind office|vpn [--city C --country CC --lat N --lon N] | network remove PREFIX | help")
}

// cmdGeo says where sign-ins are placed from, and names networks.
func cmdGeo(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	var c geoConfig
	if b, err := os.ReadFile(geoPath(root)); err == nil {
		if err := json.Unmarshal(b, &c); err != nil {
			return fmt.Errorf("geo.json: %w", err)
		}
	}
	saveGeo := func(action, prefix string) error {
		sort.Slice(c.Networks, func(i, j int) bool { return c.Networks[i].Prefix < c.Networks[j].Prefix })
		b, err := json.MarshalIndent(c, "", " ")
		if err != nil {
			return err
		}
		if err := atomicfile.Write(geoPath(root), b, 0o600); err != nil {
			return err
		}
		// Naming a network an office or a VPN changes which sign-ins are
		// stepped up, so it is on the record.
		caller := resolveCaller(root, "")
		return recordE(root, caller.auditRecord(action, "/", audit.Success, map[string]string{"network": prefix}))
	}
	switch args[0] {
	case "status":
		_, desc, err := loadGeo(root)
		if err != nil {
			return err
		}
		w.Human("  %s\n", desc)
		for _, n := range c.Networks {
			w.Human("  %s  %s  %s\n", n.Prefix, n.Network, n.Place.String())
		}
		return nil
	case "help":
		w.Human("  Sign-ins are placed from networks you name first, then a city database.\n"+
			"  The database: download DB-IP's free IP to City Lite in MMDB form from\n"+
			"  https://db-ip.com/db/download/ip-to-city-lite (CC BY 4.0), unpack it, and put it at\n"+
			"  %s. It is never fetched by this program, and no lookup leaves the machine.\n\n"+
			"  Optional, beside it:\n"+
			"    %s  DB-IP's IP to ASN Lite (MMDB): names the network a sign-in came\n"+
			"      from, so a new provider and a hosting provider can be told apart from home\n"+
			"    %s  the Tor Project's bulk exit list, one address a line, from\n"+
			"      https://check.torproject.org/torbulkexitlist; refresh it daily\n", geoDBPath(root), geoASNPath(root), geoTorPath(root))
		return nil
	case "network":
		if len(args) < 3 {
			return geoUsage()
		}
		switch args[1] {
		case "remove":
			kept := c.Networks[:0]
			for _, n := range c.Networks {
				if n.Prefix != args[2] {
					kept = append(kept, n)
				}
			}
			c.Networks = kept
			return saveGeo("geo.network-removed", args[2])
		case "add":
			if len(args) < 4 {
				return geoUsage()
			}
			n := geo.Network{Prefix: args[2]}
			n.Network = args[3]
			for i := 4; i+1 < len(args); i += 2 {
				v := args[i+1]
				switch args[i] {
				case "--kind":
					if v != "office" && v != "vpn" {
						return fmt.Errorf("--kind is office or vpn")
					}
					n.Kind = v
				case "--city":
					n.City = v
				case "--country":
					n.Country = strings.ToUpper(v)
				case "--lat":
					f, err := strconv.ParseFloat(v, 64)
					if err != nil {
						return err
					}
					n.Lat = f
				case "--lon":
					f, err := strconv.ParseFloat(v, 64)
					if err != nil {
						return err
					}
					n.Lon = f
				default:
					return geoUsage()
				}
			}
			if _, err := netip.ParsePrefix(n.Prefix); err != nil {
				return fmt.Errorf("%q is not a network: %w", n.Prefix, err)
			}
			c.Networks = append(c.Networks, n)
			return saveGeo("geo.network-added", n.Prefix)
		}
	}
	return geoUsage()
}

// automateEvent is a finding-shaped event about somebody, for tests and the
// command line.
func automateEvent(subject string) automate.Event {
	return automate.Event{Kind: "finding", Subject: subject, Summary: "seen elsewhere: " + subject}
}

// sessionHooks are the admin's other ways into the rules: where a request
// is from, a session seen elsewhere, a person reporting a sign-in, and one
// more signal about a sign-in.
func sessionHooks(root string) (func(addr, agent string) admin.SessionContext,
	func(admin.SessionMove) admin.SignInVerdict, func(principal, session string),
	func(principal, kind, detail string)) {

	engine := automationEngineAsync(root)
	place := func(addr, agent string) admin.SessionContext {
		c := admin.SessionContext{Device: travel.DeviceClass(agent)}
		if loc, _, err := cachedGeo(root); err == nil {
			if p, ok := loc.Locate(addr); ok {
				c.Country = p.Country
			}
		}
		return c
	}
	moved := func(m admin.SessionMove) admin.SignInVerdict {
		detail := fmt.Sprintf("a session issued to %s in %s is now used from %s in %s",
			firstNonEmptyStr(m.From.Device, "a device"), firstNonEmptyStr(m.From.Country, "an unknown country"),
			firstNonEmptyStr(m.To.Device, "a device"), firstNonEmptyStr(m.To.Country, "an unknown country"))
		out, err := engine.Handle(automate.Event{Kind: "signin", Subject: m.Principal,
			Summary: m.Principal + ": " + detail,
			Fields: map[string]string{"signal": "session-moved", "risk": "high", "role": string(m.Role),
				"country": m.To.Country, "device": m.To.Device, "source": "quilzo"}})
		if err != nil || !out.StepUp {
			return admin.SignInVerdict{}
		}
		return admin.SignInVerdict{StepUp: true, Reason: detail}
	}
	reported := func(principal, session string) {
		_, _ = engine.Handle(automate.Event{Kind: "person", Subject: principal,
			Summary: principal + " said a sign-in was not them",
			Fields:  map[string]string{"reason": "reported"}})
	}
	signal := func(principal, kind, detail string) {
		_, _ = engine.Handle(automate.Event{Kind: "signin", Subject: principal, Summary: principal + ": " + detail,
			Fields: map[string]string{"signal": kind, "risk": travel.Severity(kind), "source": "quilzo"}})
	}
	return place, moved, reported, signal
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
