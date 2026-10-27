// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/shield"
)

// The governed browser over MCP: another vendor's agent — Claude Code,
// Codex, anything that speaks MCP — drives a browser through Quilzo at
// /mcp/browser/NAME, under a grant an administrator declared, with the
// same tokens and app connections as the rest of the machine interface.
//
// What makes this Quilzo's offer and not a proxy: the browser is Quilzo's,
// in a box of its own, and the client never holds its pipe. Each call is
// one step of a kept run — the session's gate, the breaker, the host rule
// on every request the page makes — and a press that commits to something
// waits for a person exactly as a gateway tool does: held as a call, gone
// through once if approved within the hour, never widened. Nothing the
// client sends is a selector or a script: it names an element by a
// reference from the outline it was given, as a model of Quilzo's own
// does.
//
// What a grant never holds: a credential. Signing in is an agent's
// capability, typed from a sealed vault by Quilzo; an outside client's
// browser is offered reading, acting and looking only.

// browserGrant is a declared offer of the governed browser to named
// outside callers.
type browserGrant struct {
	Name string `json:"name"`
	// Read and Write are the hosts, exactly as an agent declares them.
	Read  []string `json:"read,omitempty"`
	Write []string `json:"write,omitempty"`
	// Ops are the actions offered, from the browser's capabilities except
	// signing in. Empty means all of those.
	Ops []string `json:"ops,omitempty"`
	// Pictures allows browser_look, which carries a picture of whatever
	// the page shows.
	Pictures bool `json:"pictures,omitempty"`
	// Daily caps one caller's calls a day; zero is the gateway's default.
	Daily int `json:"daily,omitempty"`
}

// MaxBrowserGrantHosts matches an agent's declaration: a grant is a
// browser declaration with a token instead of a run.
const maxBrowserGrantHosts = 32

// grantOps are everything a grant may offer: the browser's capabilities
// without signing in, and without looking unless the grant allows
// pictures, which carry a picture of whatever the page shows.
func grantOps(g browserGrant) []string {
	all := []string{"browser_open", "browser_read", "browser_look", "browser_type", "browser_choose", "browser_click"}
	if len(g.Ops) == 0 {
		g.Ops = all
	}
	var out []string
	for _, op := range all {
		if op == "browser_look" && !g.Pictures {
			continue
		}
		for _, held := range g.Ops {
			if op == held {
				out = append(out, op)
				break
			}
		}
	}
	return out
}

// manifest is the grant as a manifest, so every rule that holds an agent's
// browser holds a grant's: the host shapes, https, write-only-by-writing.
// Validating a grant through the manifest's own checks is the only way the
// two cannot drift apart.
func (g browserGrant) manifest() (agent.Manifest, error) {
	ops := grantOps(g)
	m := agent.Manifest{Name: "browser-" + g.Name, Kind: agent.KindTask,
		Purpose:      "the governed browser over MCP, granted to " + g.Name,
		Capabilities: ops,
		Autonomy:     agent.AutonomyDraft,
		Browser:      &agent.Browser{Read: g.Read, Write: g.Write, Pictures: g.Pictures},
		Budget:       agent.Budget{Steps: 10000, Tools: 10000, Duration: agent.Duration(24 * time.Hour)},
	}
	if err := m.Validate(nil); err != nil {
		return m, fmt.Errorf("the grant %s: %w", g.Name, err)
	}
	return m, nil
}

func grantsPath(root string) string { return filepath.Join(root, "browser", "grants.json") }

type grantsFile struct {
	Grants []browserGrant `json:"grants"`
}

func loadBrowserGrants(root string) (map[string]browserGrant, error) {
	out := map[string]browserGrant{}
	b, err := os.ReadFile(grantsPath(root))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	var f grantsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s cannot be read: %w", grantsPath(root), err)
	}
	for _, g := range f.Grants {
		out[g.Name] = g
	}
	return out, nil
}

func saveBrowserGrant(root string, g browserGrant) error {
	if _, err := g.manifest(); err != nil {
		return err
	}
	set, err := loadBrowserGrants(root)
	if err != nil {
		return err
	}
	set[g.Name] = g
	var f grantsFile
	for _, gr := range set {
		f.Grants = append(f.Grants, gr)
	}
	sort.Slice(f.Grants, func(i, j int) bool { return f.Grants[i].Name < f.Grants[j].Name })
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(grantsPath(root)), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(grantsPath(root), b, 0o600)
}

// grantName is what a grant may be called, on the wire and on disk.
var grantName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// browserGrantOffered is the grant a name names, when it validates: an
// offer that no longer validates is not one, and saying nothing is the
// refusal the endpoint already gives.
func browserGrantOffered(root, name string) (browserGrant, agent.Manifest, bool) {
	set, err := loadBrowserGrants(root)
	if err != nil {
		return browserGrant{}, agent.Manifest{}, false
	}
	g, ok := set[name]
	if !ok || !grantName.MatchString(name) {
		return browserGrant{}, agent.Manifest{}, false
	}
	m, err := g.manifest()
	if err != nil {
		return browserGrant{}, agent.Manifest{}, false
	}
	return g, m, true
}

// grantSession is one caller's browser under one grant: a kept run whose
// steps are the calls, and the browser the run opens. It lives in this
// process, which is the process serving the interface, and closes after a
// quarter hour with nobody on it — a browser nobody is driving is a box
// held for nothing.
type grantSession struct {
	root   string
	grant  browserGrant
	m      agent.Manifest
	caller *Caller
	tok    auth.Token
	sess   *agent.Session
	rb     *runBrowser
	krun   *keptRun
	steps  int
	lastAt time.Time
	// actMu keeps one caller's calls in order on one browser: two clients
	// may arrive together, and a run whose steps interleave is a run whose
	// record lies about what happened on which page.
	actMu sync.Mutex
}

// grantIdle is how long a caller's browser waits for them before it
// closes.
const grantIdle = 15 * time.Minute

var grantSessions struct {
	sync.Mutex
	live map[string]*grantSession
}

func grantKey(name string, tok auth.Token) string {
	return name + "\x00" + tok.Principal + "\x00" + tok.Client + "\x00" + tok.Grant
}

func closeGrantSession(s *grantSession, why string, now time.Time) {
	if s.rb != nil {
		s.rb.end()
	}
	if s.krun != nil {
		s.krun.rec.State = ""
		s.krun.rec.Trace.Stopped = why
		s.krun.rec.Trace.Complete = true
		_ = writeAgentRun(s.root, s.krun.rec)
	}
}

// grantSessionFor is the caller's session under a grant, made on first
// use. The browser itself starts when the page is opened, as a run's does.
func grantSessionFor(root string, g browserGrant, m agent.Manifest, caller *Caller, tok auth.Token, now time.Time) (*grantSession, error) {
	grantSessions.Lock()
	defer grantSessions.Unlock()
	if grantSessions.live == nil {
		grantSessions.live = map[string]*grantSession{}
	}
	key := grantKey(g.Name, tok)
	if s, ok := grantSessions.live[key]; ok {
		s.lastAt = now
		return s, nil
	}
	id, err := newAgentRunID(now)
	if err != nil {
		return nil, err
	}
	s := &grantSession{root: root, grant: g, m: m, caller: caller, tok: tok,
		sess: agent.NewSession(m, nil), lastAt: now}
	who := tok.Principal
	if tok.Client != "" {
		who = "app:" + tok.Client
	}
	s.krun = &keptRun{root: root, rec: agent.Record{ID: id, Agent: m.Name, Kind: agent.KindTask,
		Goal: "the governed browser, for " + who, By: who, Model: "mcp",
		State: agent.Running, Started: now, Beat: now}}
	// A run with a browser is a live thing in this process: its pictures
	// are kept with it, and what it asks about waits with it.
	actor := programModel{name: "mcp"}
	rb, err := newRunBrowser(root, m, s.sess, caller, actor, id, g.Pictures)
	if err != nil {
		return nil, err
	}
	s.rb = rb
	if err := writeAgentRun(root, s.krun.rec); err != nil {
		rb.end()
		return nil, err
	}
	grantSessions.live[key] = s
	return s, nil
}

// grantSweep closes sessions nobody has called in a quarter of an hour.
// Called from each request and, when the server runs, from GrantSweeper's
// ticker — traffic alone is not a clock, and a browser nobody is driving
// holds one of the machine's few slots for nothing.
func grantSweep(now time.Time) {
	grantSessions.Lock()
	defer grantSessions.Unlock()
	for k, s := range grantSessions.live {
		if now.Sub(s.lastAt) < grantIdle {
			continue
		}
		closeGrantSession(s, "closed after "+grantIdle.String()+" with nobody on it", now)
		delete(grantSessions.live, k)
	}
}

// GrantSweeper closes idle grant browsers while the server runs, and
// adopts the runs a restarted process left claiming to be live: their
// browsers are gone with the process that held them, and a record that
// says running forever says nothing.
func GrantSweeper(ctx context.Context, root string) {
	adoptGrantRuns(root, time.Now())
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			grantSweep(time.Now())
			return
		case <-t.C:
			grantSweep(time.Now())
		}
	}
}

// adoptGrantRuns ends the kept runs of grant browsers whose serving
// process has gone: state running, the machine interface as their model,
// and a beat gone stale.
func adoptGrantRuns(root string, now time.Time) {
	entries, err := os.ReadDir(agentRunsDir(root))
	if err != nil {
		return
	}
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".json")
		if !agent.ValidRecordID(id) {
			continue
		}
		rec, err := loadAgentRun(root, id)
		if err != nil || rec.State != agent.Running || rec.Model != "mcp" {
			continue
		}
		if now.Sub(rec.Beat) <= agent.StaleAfter {
			continue
		}
		rec.State = ""
		rec.Trace.Stopped = "the serving process it lived in ended, so its browser is gone; the caller starts again"
		rec.Trace.Complete = true
		_ = writeAgentRun(root, rec)
	}
}

// closeGrantSessionsOf ends every live session under one grant, for the
// administrator withdrawing it: a grant taken back must not leave a
// browser running on the strength of it.
func closeGrantSessionsOf(name, why string, now time.Time) {
	grantSessions.Lock()
	defer grantSessions.Unlock()
	for k, s := range grantSessions.live {
		if s.grant.Name != name {
			continue
		}
		closeGrantSession(s, why, now)
		delete(grantSessions.live, k)
	}
}

// browserMCPServer is what one caller is offered under one grant.
func browserMCPServer(r *http.Request, root, name string, tok auth.Token) (*mcp.Server, error) {
	g, m, ok := browserGrantOffered(root, name)
	if !ok {
		return nil, fmt.Errorf("%s is not a browser grant offered here", name)
	}
	caller := remoteCaller(tok)
	if err := remoteRefusal(root, caller, auth.RoleReader); err != nil {
		return nil, err
	}
	if p, off := shield.Find(root, shield.Feature, "mcp", time.Now()); off && p.Level == shield.Off {
		return nil, fmt.Errorf("the machine interface is turned off until about %s: %s",
			p.Until.UTC().Format("15:04 UTC"), p.Reason)
	}
	srv := mcp.NewServer("quilzo-browser-"+name, version)
	srv.Authorise = func(op mcp.Operation) error {
		if op.Writes {
			// Acting on a page is not reading it: an author's token, as a
			// gateway tool that changes anything asks an author.
			return remoteRefusal(root, caller, auth.RoleAuthor)
		}
		return nil
	}
	for _, op := range grantOperations(g) {
		srv.Register(op, func(args map[string]any) (any, error) {
			ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
			defer cancel()
			return browserGrantCall(ctx, root, g, m, name, op.Name, args, caller, tok, time.Now())
		})
	}
	return srv, nil
}

// grantOperations are the offered actions as MCP operations: reading the
// page and looking at it are reads; acting on it — typing, choosing,
// pressing — is a write.
func grantOperations(g browserGrant) []mcp.Operation {
	var out []mcp.Operation
	for _, op := range grantOps(g) {
		o := mcp.Operation{Name: op,
			Summary: map[string]string{
				"browser_open":   "opens an address on a host the grant reads, and answers with the page's outline",
				"browser_read":   "reads the page's outline again, as it is now",
				"browser_look":   "sends a picture of the page, when the grant allows pictures",
				"browser_type":   "types text into a field of the page, by its reference from the outline",
				"browser_choose": "chooses an option in a list, by its reference and the option's label",
				"browser_click":  "presses a button or link by its reference; what commits to something waits for a person",
			}[op],
			NeedsRole: "reader",
		}
		switch op {
		case "browser_type", "browser_choose", "browser_click":
			o.Writes = true
		}
		switch op {
		case "browser_open":
			o.Args = map[string]string{"url": "the https address to open"}
		case "browser_type":
			o.Args = map[string]string{"ref": "the field's reference from the outline", "text": "the text to type"}
		case "browser_choose":
			o.Args = map[string]string{"ref": "the list's reference from the outline", "option": "the option's label"}
		case "browser_click":
			o.Args = map[string]string{"ref": "the element's reference from the outline"}
		}
		out = append(out, o)
	}
	return out
}

// browserGrantCall performs one offered action for one caller under the
// grant's rules, and records it whatever happens.
func browserGrantCall(ctx context.Context, root string, g browserGrant, m agent.Manifest, grant, op string,
	args map[string]any, caller *Caller, tok auth.Token, now time.Time) (out string, err error) {

	grantSweep(now)
	digest := argsDigest("browser/"+grant, op, args)
	held, decidedBy := "", ""
	runID, stepN := "", 0
	defer func() {
		d := map[string]string{"grant": grant, "tool": op, "run": runID,
			"on_behalf_of": tok.Principal, "args_digest": digest}
		if tok.Grant != "" {
			d["connection"] = tok.Grant
		}
		if decidedBy != "" {
			d["decided_by"] = decidedBy
		}
		if held != "" {
			d["held"] = held
		}
		if stepN > 0 {
			d["step"] = fmt.Sprintf("%d", stepN)
		}
		outcome := audit.Success
		if err != nil {
			outcome, d["error"] = audit.Denied, clip(err.Error(), 300)
			var ref *mcp.Refusal
			var se *mcp.ScopeError
			if !errors.As(err, &ref) && !errors.As(err, &se) {
				outcome = audit.Failure
			}
		}
		who, kind, model := tok.Principal, audit.KindHuman, ""
		if tok.Client != "" {
			who, kind, model = "app:"+tok.Client, audit.KindAI, tok.Client
		}
		record(root, audit.Record{Action: "mcp.browser", Resource: "/mcp/browser/" + grant, Outcome: outcome,
			Principal: who, Kind: kind, Model: model, Verified: true, Detail: d})
	}()

	if err := authorise(root, caller, auth.ActView, "/mcp/browser/"+grant); err != nil {
		// A denial, not a failure: this caller may not, and a failure rate
		// that counts refusals is an alarm that cries wolf.
		return "", &mcp.Refusal{Reason: err.Error()}
	}
	for _, o := range grantOperations(g) {
		if o.Name == op && o.Writes {
			if err := authorise(root, caller, auth.ActEditDraft, "/mcp/browser/"+grant); err != nil {
				return "", &mcp.Refusal{Reason: err.Error()}
			}
			// What a press or a typed word does is an agent's, and is
			// refused while its record could not be written.
			if err := auditReady(root); err != nil {
				return "", &mcp.Refusal{Reason: err.Error()}
			}
		}
	}
	s, serr := grantSessionFor(root, g, m, caller, tok, now)
	if serr != nil {
		return "", serr
	}
	runID = s.krun.rec.ID

	// The gate, then the breaker: the same order a run's loop applies
	// them in, and before anything is counted or held — a call the session
	// refuses is not a call the grant made.
	if err := s.sess.Check(op); err != nil {
		return "", &mcp.Refusal{Reason: err.Error()}
	}
	if err := s.sess.Authorize(op); err != nil {
		return "", &mcp.Refusal{Reason: err.Error()}
	}
	action := agent.Action{Op: op, Input: args}
	if b, breaks := s.sess.Breaks(action); breaks {
		return "", &mcp.Refusal{Reason: "the page has read somebody else's words and this would carry them to " +
			"another host: " + b}
	}

	// What a person must see first, weighed from the page before anything
	// global is locked: weighing asks the page, and a page that is slow
	// must not hold up every other call this machine serves.
	why := s.rb.driver.Weighs(action)

	// The daily count and any hold live in the gateway's own state, under
	// the grant's name: one place a person looks at what waits for them.
	gatewayMu.Lock()
	st, lerr := loadGatewayState(root)
	if lerr != nil {
		gatewayMu.Unlock()
		return "", lerr
	}
	day := now.UTC().Format("2006-01-02")
	if st.Days[day] == nil {
		st.Days[day] = map[string]int{}
	}
	key := gatewayCallerKey(tok) + "|browser/" + grant
	daily := g.Daily
	if daily <= 0 {
		daily = agent.DefaultGatewayDaily
	}
	if st.Days[day][key] >= daily {
		gatewayMu.Unlock()
		return "", &mcp.Refusal{Reason: fmt.Sprintf(
			"this caller has made %d calls to the browser of %s today, which is as many as a caller may",
			st.Days[day][key], grant)}
	}

	// The hold is the gateway's — same state, same once-within-the-hour
	// rule, same approval screen — because a call that waits for a person
	// over MCP waits the way every other one does.
	if why != "" {
		id, ok, wwhy, by := decideHeld(st, "browser/"+grant, op, digest, tok,
			map[string]any{"args": args, "why": why}, now)
		held, decidedBy = id, by
		if !ok {
			if serr := saveGatewayState(root, st, now); serr != nil {
				gatewayMu.Unlock()
				return "", serr
			}
			gatewayMu.Unlock()
			if wwhy == heldNew {
				tellHeld(root, "browser/"+grant, op, id, tok)
				return "", &mcp.Refusal{Reason: "a person approves each press that commits to something on " +
					grant + "'s browser. This one is held as " + id + " (" + why +
					"): call again with the same arguments once they have decided"}
			}
			return "", &mcp.Refusal{Reason: wwhy}
		}
	}
	st.Days[day][key]++
	if serr := saveGatewayState(root, st, now); serr != nil {
		gatewayMu.Unlock()
		return "", serr
	}
	gatewayMu.Unlock()

	s.actMu.Lock()
	defer s.actMu.Unlock()
	out, perr := s.rb.driver.Perform(func(context.Context, agent.Action) (string, error) {
		return "", errors.New("not the browser's")
	})(ctx, action)

	// One step of the run, kept with it, whatever came of it.
	s.steps++
	stepN = s.steps
	st2 := agent.Step{N: s.steps, Action: action, Allowed: true, At: now.UTC()}
	if perr != nil {
		st2.Err = perr.Error()
	} else {
		st2.Result = clip(out, 4000)
	}
	s.krun.rec.Trace.Steps = append(s.krun.rec.Trace.Steps, st2)
	s.krun.rec.Beat = now
	_ = writeAgentRun(root, s.krun.rec)
	if perr != nil {
		return "", perr
	}
	return out, nil
}

// grantNames lists the grants that validate, for the CLI and the coverage
// of what is offered.
func grantNames(root string) []string {
	set, err := loadBrowserGrants(root)
	if err != nil {
		return nil
	}
	var out []string
	for name := range set {
		if _, _, ok := browserGrantOffered(root, name); ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
