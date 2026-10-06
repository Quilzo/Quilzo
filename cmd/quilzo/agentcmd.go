// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/agentexec"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentmodel"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/otlp"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/store"
)

// Declaring agents from the command line.
//
// The noun is deliberately singular. `quilzo agents` (plural) reports what
// models have been doing — it reads the audit log and answers "did anything
// misbehave". This one declares what an agent is allowed to do before it does
// anything. Watching and permitting are different questions and they kept
// being confused when they shared a word.

func agentsPath(root string) string { return filepath.Join(root, "agents.json") }

// agentSet is what is stored: manifests by name.
type agentSet struct {
	Agents map[string]agent.Manifest `json:"agents"`
	// Identities are who answers for each agent, and until when it may run.
	// See internal/agent/identity.go.
	Identities map[string]agent.Identity `json:"identities,omitempty"`
}

func loadAgents(root string) (*agentSet, error) {
	set := &agentSet{Agents: map[string]agent.Manifest{}}
	if err := loadJSON(agentsPath(root), set); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if set.Agents == nil {
		set.Agents = map[string]agent.Manifest{}
	}
	if set.Identities == nil {
		set.Identities = map[string]agent.Identity{}
	}
	return set, nil
}

// identityOf is an agent's identity, or nil for one declared before
// identities existed.
func (set *agentSet) identityOf(name string) *agent.Identity {
	if id, ok := set.Identities[name]; ok {
		return &id
	}
	return nil
}

// knownCapabilities is the operation set a manifest is validated against.
//
// Built from the machine interface's own registry rather than from a list kept
// here, so an operation that is renamed there stops validating here rather than
// silently becoming a capability nothing offers.
func knownCapabilities(root string) map[string]bool {
	s, err := open(root)
	if err != nil {
		return nil
	}
	caller := resolveCaller(root, "")
	srv := buildMCP(root, s, caller, "templates")
	known := map[string]bool{}
	for _, op := range srv.Operations() {
		known[op.Name] = true
	}
	return known
}

func cmdAgent(root string, args []string) error {
	if len(args) == 0 {
		return agentUsage()
	}
	switch args[0] {
	case "templates":
		return agentTemplates()
	case "list":
		return agentList(root)
	case "show":
		return agentShow(root, args[1:])
	case "new":
		return agentNew(root, args[1:])
	case "probe":
		return agentProbe(args[1:])
	case "check":
		return agentCheck(root)
	case "run":
		return agentCheckRun(root, args[1:])
	case "runs":
		return agentRuns(root, args[1:])
	case "trace":
		return agentTrace(root, args[1:])
	case "approve", "decline":
		return agentAnswer(root, args[0] == "approve", args[1:])
	case "resume":
		return agentResumeCmd(root, args[1:])
	case "replay":
		return agentReplay(root, args[1:])
	case "sponsor", "renew":
		return agentIdentityCmd(root, args[0], args[1:])
	case "receipt":
		return agentReceipt(root, args[1:])
	case "verify-receipt":
		return agentVerifyReceipt(root, args[1:])
	default:
		return agentUsage()
	}
}

func agentUsage() error {
	return fmt.Errorf(`usage: quilzo agent <command>

  templates              the archetypes, and when to reach for each
  new NAME --kind KIND   declare one from a template
  sponsor NAME PERSON    who answers for it; it stops when they can no longer act here
  renew NAME [--for D]   another stretch before it has to be renewed (90 days unless said)
  receipt RUN [-o FILE]  what a run did, from the log, with proofs anybody can check
  verify-receipt FILE    check a receipt against the public keys you were given
  list                   what is declared here
  show NAME              one manifest in full
  check                  re-validate every manifest against this build
  run NAME ["goal"]      exercise one against its manifest, and record it
  runs [NAME]            the runs that are kept, newest first
  trace RUN              one run, step by step
  approve RUN STEP       agree to the action a run is waiting on
  decline RUN STEP       refuse it, and let the run carry on without
  resume RUN             continue a run that was interrupted
  replay RUN STEP        run it again from after that step, as a new run

kinds: %s`, strings.Join(agent.KindNames(), ", "))
}

func agentTemplates() error {
	for _, t := range agent.Catalogue() {
		m := t.Manifest
		fmt.Printf("  %s%-12s%s %s\n", bold, m.Kind, reset, t.Summary)
		fmt.Printf("      %s%s%s\n", dim, indented(t.When, 66, "      "), reset)
		fmt.Printf("      %scapabilities%s %s\n", dim, reset,
			strings.Join(m.Capabilities, ", "))
		fmt.Printf("      %sautonomy%s %s   %sbudget%s %d steps, %d tools, %s\n",
			dim, reset, m.Autonomy, dim, reset,
			m.Budget.Steps, m.Budget.Tools, m.Budget.Duration)
		if m.Memory.Any() {
			fmt.Printf("      %smemory%s %s for %s\n", dim, reset,
				memoryTiers(m.Memory), m.Memory.Retain)
		} else {
			fmt.Printf("      %smemory%s none\n", dim, reset)
		}
		fmt.Println()
	}
	fmt.Printf("  %severy template validates as written, and is the narrow "+
		"answer — widen what you need%s\n", dim, reset)
	return nil
}

func memoryTiers(m agent.Memory) string {
	var on []string
	if m.Episodic {
		on = append(on, "episodic")
	}
	if m.Semantic {
		on = append(on, "semantic")
	}
	if m.Procedural {
		on = append(on, "procedural")
	}
	return strings.Join(on, "+")
}

// indented re-indents a wrapped block, so continuation lines line up under
// the first. wrap() lives in posture.go and breaks lines without indenting;
// this is the one extra thing a nested list needs.
func indented(s string, width int, indent string) string {
	return strings.ReplaceAll(wrap(s, width), "\n", "\n"+indent)
}

func agentNew(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: quilzo agent new NAME --kind KIND")
	}
	name := args[0]
	kind := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--kind" && i+1 < len(args) {
			kind = args[i+1]
			i++
			continue
		}
		if v, ok := strings.CutPrefix(args[i], "--kind="); ok {
			kind = v
		}
	}
	if kind == "" {
		return fmt.Errorf("which kind? one of %s\n  quilzo agent templates — "+
			"what each one is for", strings.Join(agent.KindNames(), ", "))
	}

	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	if _, exists := set.Agents[name]; exists {
		return fmt.Errorf("an agent called %q is already declared here; "+
			"`quilzo agent show %s` to see it", name, name)
	}

	m, err := agent.New(agent.Kind(kind), name, knownCapabilities(root))
	if err != nil {
		return err
	}
	set.Agents[name] = m
	if err := saveJSON(agentsPath(root), set); err != nil {
		return err
	}

	// A declaration of what a model may do is exactly the sort of change a log
	// exists to preserve: it is the moment somebody decided the blast radius.
	caller := resolveCaller(root, "")
	record(root, caller.auditRecord("agent.declare", "/", audit.Success,
		map[string]string{
			"agent": name, "kind": kind,
			"autonomy":     string(m.Autonomy),
			"capabilities": strings.Join(m.Capabilities, " "),
		}))

	fmt.Printf("declared %s%s%s (%s)\n", bold, name, reset, m.Kind)
	fmt.Printf("  %s%s%s\n", dim, m.Purpose, reset)
	fmt.Printf("  capabilities  %s\n", strings.Join(m.Capabilities, ", "))
	fmt.Printf("  autonomy      %s\n", m.Autonomy)
	if m.HumanApproval {
		fmt.Printf("  %sa person approves before anything it did becomes public%s\n",
			dim, reset)
	}
	fmt.Printf("  %sedit %s to widen it; `quilzo agent check` re-validates%s\n",
		dim, agentsPath(root), reset)
	return nil
}

func agentList(root string) error {
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	if len(set.Agents) == 0 {
		fmt.Println("no agents are declared here")
		fmt.Printf("  %squilzo agent templates — the archetypes%s\n", dim, reset)
		return nil
	}
	names := make([]string, 0, len(set.Agents))
	for n := range set.Agents {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		m := set.Agents[n]
		approval := ""
		if m.HumanApproval {
			approval = dim + " · a person approves" + reset
		}
		fmt.Printf("  %-16s %-11s %-8s %d cap%s\n",
			n, m.Kind, m.Autonomy, len(m.Capabilities), approval)
	}
	return nil
}

func agentShow(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: quilzo agent show NAME")
	}
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	m, ok := set.Agents[args[0]]
	if !ok {
		return fmt.Errorf("no agent called %q", args[0])
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// agentCheck re-validates every manifest against this build.
//
// The capability set is not fixed: an operation removed from the machine
// interface leaves every manifest that named it describing a permission nothing
// grants. That reads as working configuration right up until it is needed, so
// it is worth a command that says so.
func agentCheck(root string) error {
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	known := knownCapabilities(root)
	names := make([]string, 0, len(set.Agents))
	for n := range set.Agents {
		names = append(names, n)
	}
	sort.Strings(names)

	bad := 0
	for _, n := range names {
		m := set.Agents[n]
		if verr := m.Validate(known); verr != nil {
			bad++
			fmt.Printf("  %s%s%s %v\n", red, n, reset, verr)
			continue
		}
		fmt.Printf("  %s%s%s %s, %s\n", green, n, reset, m.Kind, m.Autonomy)
	}
	if bad > 0 {
		return errBlocked{fmt.Errorf("%d agent(s) do not validate against this build", bad)}
	}
	fmt.Printf("  %s%d agent(s) valid%s\n", dim, len(names), reset)
	return nil
}

// agentCheckRun exercises an agent against its own manifest, without a model.
//
// # Why a run with no model is worth having
//
// Everything that decides what an agent may do is in the manifest and the
// session: the capability list, the autonomy, the budgets, the retrieval scope.
// None of that involves a model, so all of it can be exercised without one —
// and the answer to "is this agent configured the way I meant" is available
// before anybody spends a token on finding out.
//
// It is also the wiring. A receipt that nothing writes to the audit log is a
// data structure; this is the first caller that produces one, and it produces
// it on the path every later caller will use.
//
// # Two ways to decide, and the default is the one that needs no model
//
// `agent check` walks the manifest: every capability tried once, in a fixed
// order, to find out which of them this store actually answers. The plan is
// the manifest, so nothing a model says can change it, and it needs no
// endpoint and costs nothing.
//
// `agent run` asks a model to choose, through internal/agentmodel. That is the
// larger and riskier mode, and it is opt-in for that reason: the action space
// is still the manifest's and the session still refuses, but a model is now
// choosing which word out of that vocabulary — which is where an injected page
// gets its only opportunity.
func agentCheckRun(root string, args []string) error {
	// The name may come before the flags, as the help shows it. Parsed
	// alone, `agent run NAME --model "goal"` stopped at NAME, so --model was
	// taken for the goal and the run walked the manifest with no model.
	pos, rest := leadingArgs(args, 1)
	fs := flag.NewFlagSet("agent run", flag.ContinueOnError)
	withModel := fs.Bool("model", false,
		"let a model choose the actions, instead of walking the manifest")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	args = append(pos, fs.Args()...)
	if len(args) == 0 {
		return fmt.Errorf("usage: quilzo agent run NAME [--model] [\"what it should do\"]")
	}
	if len(args) > 2 {
		return fmt.Errorf("the goal is one argument, so quote it, and flags " +
			"go before it: quilzo agent run NAME --model \"what it should do\"")
	}
	name := args[0]
	goal := "check that this agent's manifest is enforceable"
	if len(args) > 1 {
		goal = args[1]
	}

	id, out, runErr := runAgentKept(context.Background(), root, name, goal,
		*withModel, resolveCaller(root, ""))
	if out.Manifest.Name == "" {
		return runErr
	}
	m, trace, rc := out.Manifest, out.Trace, out.Receipt
	if out.Model != "" {
		fmt.Printf("  %sdeciding with %s; the manifest is still the only "+
			"vocabulary%s\n", dim, out.Model, reset)
	}
	if out.TraceError != "" {
		fmt.Printf("  %straces not sent: %s%s\n", dim, out.TraceError, reset)
	}
	if id == "" {
		fmt.Printf("  %sthe run was not kept%s\n", dim, reset)
	}

	fmt.Printf("%s%s%s  %s\n", bold, name, reset, m.Kind)
	// What this run actually was, because the two modes answer different
	// questions and a summary that describes the wrong one is worse than
	// none. Left saying "no model" while a model was deciding, which is a
	// line somebody would quote in a report.
	if *withModel {
		fmt.Printf("  %sa model chose each action from the manifest's "+
			"capabilities — what it achieved, not what this store can "+
			"answer%s\n", dim, reset)
	} else {
		fmt.Printf("  %severy capability tried once, with no arguments and no "+
			"model — this reports what this store answers, not what the agent "+
			"would achieve%s\n", dim, reset)
	}
	fmt.Printf("  did %d, refused %d, failed %d\n", rc.Did, rc.Refused, rc.Failed)
	// Failures are shown, not only counted. A capability the manifest permits
	// and this store cannot answer is the most useful thing this command
	// finds, and a bare count sends the operator looking through a log for it.
	for _, step := range trace.Steps {
		if step.Allowed && step.Err != "" {
			what := step.Action.Op
			if what == "" {
				what = step.Action.Tool
			}
			fmt.Printf("  %s%-22s%s %s\n", dim, what, reset, step.Err)
		}
	}
	for _, step := range trace.Refused() {
		what := step.Action.Op
		if what == "" {
			what = step.Action.Tool
		}
		fmt.Printf("  %s%-22s%s %s\n", dim, what, reset, step.Why)
	}
	if rc.Tainted {
		fmt.Printf("  %sread stored content, so anything it produced needs a "+
			"person%s\n", dim, reset)
		// And what it read, because that is the review. Being told a run is
		// tainted and not what tainted it leaves the only honest check as
		// re-reading the site, which nobody does — so the approval becomes a
		// formality, which is the one outcome this rule cannot afford.
		if p := agent.Provenance(rc.Sources, rc.Omitted); p != "" {
			fmt.Printf("  %sit read: %s%s\n", dim, p, reset)
		}
	}
	fmt.Printf("  %srecorded as agent.run %s%s\n", dim, rc.Fingerprint()[:12], reset)
	if id != "" {
		fmt.Printf("  %skept as %s%s\n", dim, id, reset)
	}
	if w := trace.Waiting; w != nil {
		printPending(id, w)
	}
	return runErr
}

// pageGate is the type gate, as an agent executor takes it.
//
// Loaded per call rather than captured once: a run can outlive an operator
// binding a type, and a gate that decided at startup would let the rest of the
// run write content against a binding that no longer holds.
//
// Fails closed on an unreadable type store. The alternative — treating a
// broken types.json as "no types configured" — makes corrupting one file the
// way to switch validation off for every page, which is the shape of the
// fail-open bug this project has already been bitten by once.
func pageGate(root string) func(string, map[string]any) error {
	return func(page string, body map[string]any) error {
		st, err := schema.Load(root)
		if err != nil {
			return fmt.Errorf(
				"the type store could not be read, so this write cannot be "+
					"checked against the type bound to %s: %w", page, err)
		}
		problems := st.Check(page, body)
		if len(problems) == 0 {
			return nil
		}
		msgs := make([]string, len(problems))
		for i, p := range problems {
			msgs[i] = p.String()
		}
		return fmt.Errorf("%s does not satisfy the type bound to it: %s",
			page, strings.Join(msgs, "; "))
	}
}

// proposeCommit puts an agent's change into the review queue people already
// use, rather than giving agents a queue of their own.
//
// One queue is the point. A separate "AI approvals" screen is how a reviewer
// ends up with two inboxes and treats one of them as less real; and the rules
// that matter here — an author may not approve their own change, and a
// machine-written one needs a human — are already written against this queue.
func proposeCommit(root string, s *store.Store) func(string, string) error {
	return func(commit, message string) error {
		prop, file, err := currentProposal(root, s)
		if err != nil {
			return err
		}
		if prop.Content != commit {
			// The draft moved between the write and the publish. Refused
			// rather than proposing whatever is current: an approval names a
			// content hash, and proposing a commit the agent did not produce
			// would put somebody else's bytes behind the agent's name.
			return fmt.Errorf(
				"the draft is now %s and this agent proposed %s; something "+
					"else wrote in between", shortCommit(prop.Content),
				shortCommit(commit))
		}
		if message != "" && prop.Message == "" {
			prop.Message = message
		}
		return saveJSON(proposalsPath(root), file)
	}
}

func shortCommit(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// tracerFor builds an OTLP exporter from configuration, or nil.
//
// Nil rather than an exporter that does nothing: a run with no collector
// configured should not pay for encoding spans nobody receives, and the caller
// checking for nil is clearer than an exporter with a silent no-op mode.
func tracerFor(root string) *otlp.Exporter {
	cfg, err := loadConfig(root)
	if err != nil {
		return nil
	}
	endpoint := cfg.Raw("telemetry.otlp_endpoint")
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	e := &otlp.Exporter{
		Endpoint:    endpoint,
		AllowRemote: cfg.Bool("telemetry.allow_remote"),
		Service:     nonBlank(cfg.Raw("site.name"), "quilzo"),
		Version:     version,
		Timeout:     cfg.Dur("telemetry.timeout"),
	}
	// A credential for a collector that wants one, from the environment rather
	// than from configuration — the store is content-addressed and an object
	// in it cannot be deleted, so a token written there is permanent.
	if h := os.Getenv("QUILZO_OTLP_HEADER"); h != "" {
		if k, v, ok := strings.Cut(h, ":"); ok {
			e.Headers = map[string]string{
				strings.TrimSpace(k): strings.TrimSpace(v)}
		}
	}
	return e
}

func nonBlank(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// agentOutcome is one run of an agent, as whoever asked for it needs it.
type agentOutcome struct {
	Manifest agent.Manifest
	Trace    agent.Trace
	Receipt  agent.Receipt
	Started  time.Time
	// Model is what chose the actions, empty when the manifest was walked.
	Model string
	// TraceError is why the run's trace did not reach a collector.
	TraceError string
}

// agentRunModel is the model an agent's run asks: through the gateway when
// one is declared, so the run is budgeted and recorded like every other
// caller, and the one configured endpoint otherwise.
func agentRunModel(root, name string) (assist.Model, string) {
	gw, _, err := modelGateway(root)
	if err != nil {
		return nil, "the model gateway could not be read: " + err.Error()
	}
	if gw != nil {
		return gw.For("agent:" + name), ""
	}
	m, err := assist.NewHTTPModel()
	if err != nil {
		return nil, err.Error()
	}
	return m, ""
}

// executeAgent runs one declared agent once: from the command line and
// from the screen alike, so there is one place the manifest is narrowed by
// the caller, the executors are wired, and the outcome is recorded.
func executeAgent(ctx context.Context, root, name, goal string,
	withModel bool, caller *Caller) (agentOutcome, error) {

	return executeAgentFrom(ctx, root, name, goal, withModel, caller, nil)
}

// agentResume is what a run is continued from, and how it is kept as it
// goes. See internal/agent/durable.go.
type agentResume struct {
	// Prior is the run so far, nil for a run starting now.
	Prior *agent.Record
	// Verdict answers the action Prior is waiting on.
	Verdict *agent.Verdict
	// Checkpoint is handed the trace after every step.
	Checkpoint func(agent.Trace)
	// RunID names the kept run, for the record each action leaves.
	RunID string
	// Eval makes the run an evaluation's: see evalcmd.go.
	Eval *evalMode
}

func executeAgentFrom(ctx context.Context, root, name, goal string,
	withModel bool, caller *Caller, from *agentResume) (agentOutcome, error) {

	var out agentOutcome
	if from == nil {
		from = &agentResume{}
	}
	set, err := loadAgents(root)
	if err != nil {
		return out, err
	}
	m, ok := set.Agents[name]
	if !ok {
		return out, fmt.Errorf("no agent called %q; `quilzo agent list`", name)
	}
	// Paused by the shield: an evaluation or a playbook found something
	// steering it, and it does not run until a person lifts that. An
	// evaluation still runs it, because it writes nothing, calls no tool and
	// starts no other agent, and re-testing is how somebody knows the pause
	// can be lifted.
	if from.Eval == nil {
		if err := refuseIfPaused(root, name); err != nil {
			return out, err
		}
		// Somebody answers for it, and that person can still act here.
		// Evaluations run regardless: they change nothing, and are how a
		// new sponsor finds out what they are taking on.
		if id := set.identityOf(name); id != nil {
			if err := id.MayRun(sponsorActive(root, id.Sponsor), time.Now()); err != nil {
				return out, fmt.Errorf("%s does not run: %w", name, err)
			}
		}
	}
	// Re-validated against this build before it runs. A manifest that was
	// written when an operation existed and no longer does describes a
	// permission nothing grants, and running it would report a clean result
	// for an agent that cannot work.
	if err := m.Validate(knownCapabilities(root)); err != nil {
		return out, err
	}

	s, err := open(root)
	if err != nil {
		return out, err
	}

	// Bounded by whoever started it, before the session is built.
	//
	// Not a check inside the run: a manifest narrowed here is narrower in
	// every later decision, including the ones nobody thought to guard. The
	// alternative — asking "may this caller do that?" at each step — is the
	// arrangement that put the content-type gate in the CLI and not in the
	// API. See agentnarrow.go.
	m = narrowedBy(m, caller)
	// And by its own standing, when the access policy gives it one: an
	// agent granted reader on /docs reads /docs, whoever starts it.
	if own, err := agentGrants(root, name); err != nil {
		return out, err
	} else if own != nil {
		m = narrowedBy(m, own)
	}
	if len(m.Capabilities) == 0 {
		return out, fmt.Errorf(
			"%s holds nothing once bounded by this token: the manifest and "+
				"the token you are using have no capability in common", name)
	}
	sess := agent.NewSession(m, nil)
	if from.Prior != nil {
		sess.Recall(from.Prior.Receipt.Sources, from.Prior.Receipt.Omitted)
	}

	// Every capability the manifest holds, tried once, in a fixed order.
	//
	// The point is to find out which of them this store actually answers, so
	// the plan is the manifest rather than anything chosen at run time — and
	// a capability that is refused here is refused for a reason the operator
	// can read rather than one a model stumbled into.
	plan := make([]agent.Action, 0, len(m.Capabilities)+len(m.Tools)+1)
	for _, c := range m.Capabilities {
		plan = append(plan, agent.Action{Op: c})
	}
	// And the tools, which the walk ignored.
	//
	// "Everything that decides what an agent may do is in the manifest" —
	// and the tool list is half of it. A manifest declaring a tool was
	// checked for its capabilities and never for whether the tool resolves:
	// whether this install has an integration offering it, whether that
	// integration is enabled, and whether it points where the manifest says.
	//
	// All three are answerable without a model and without reaching the far
	// side, which is what this mode is for. An operator who has just declared
	// a tool wants to know it is wired before an agent tries to use it in
	// front of somebody.
	for _, t := range m.Tools {
		plan = append(plan, agent.Action{Tool: t.Name})
	}
	// And the delegates, for the same reason.
	//
	// Whether each named agent exists in this install, validates against this
	// build, and is narrower than its supervisor are all answerable without a
	// model — and all three are ways a pipeline is broken before anybody runs
	// it. A supervisor that walks its own manifest and never tries to hand
	// anything on has checked the half of itself that does not matter.
	for _, name := range m.Delegates {
		plan = append(plan, agent.Action{
			Delegate: name,
			Say:      "checking that this stage is wired",
		})
	}
	plan = append(plan, agent.Action{Say: "checked"})

	var delegateModel assist.Model

	i := 0
	if p := from.Prior; p != nil {
		// A walk being continued carries on down the plan: one entry was
		// used for each step taken, and one for the action it stopped at.
		i = len(p.Trace.Steps)
		if p.Trace.Waiting != nil {
			i++
		}
	}
	// The scripted walk: the plan is the manifest, so nothing a model says can
	// change it. This is the default, and the only mode that costs nothing.
	decide := func(context.Context, string, []agent.Observation) (agent.Action, error) {
		if i >= len(plan) {
			return agent.Action{Say: "checked"}, nil
		}
		a := plan[i]
		i++
		return a, nil
	}
	if withModel {
		model, why := agentRunModel(root, name)
		if model == nil {
			return out, fmt.Errorf(
				"letting a model choose needs a model configured: %s\n"+
					"  without one, the run walks the manifest and needs "+
					"nothing", why)
		}
		out.Model = model.Name()
		// Handed to delegates as well. A supervisor deciding with a model
		// and children walking their manifests would be a pipeline where the
		// stages that do the work cannot choose anything.
		delegateModel = model
		decide = agentmodel.Decider{
			Model:   model,
			Session: sess,
			// Reported by the provider, not measured here. Fed to the session
			// so the budget counts what the run actually cost.
			Tokens: sess.Tokens,
		}.Decide()
	}

	runner := agent.Runner{
		Decide: decide,
		// Reads and writes both, routed by the same classification the
		// session gate uses. Wiring only the reader would have made every
		// granted write report "not implemented", which reads as the agent
		// behaving correctly rather than as a surface nobody connected.
		Perform: agentexec.Dispatch(
			agentexec.Reader{
				Store: s,
				// Without these the manifest's type and locale scope is
				// decoration: Reader treats a nil resolver as "nothing is
				// typed" and Session.Retrieve reads that as unrestricted.
				// See agentnarrow.go.
				Types:  pageTypeOf(root),
				Locale: pageLocaleOf(s, refOf(m)),
			},
			agentexec.Writer{
				Store: s,
				// Attributed to the agent. A commit signed with whoever
				// happened to start the run is a history that lies about who
				// wrote it, and the review queue reads the author.
				Author:  "agent/" + m.Name,
				Gate:    pageGate(root),
				Propose: proposeCommit(root, s),
				Written: func(page string) {
					markAgentWrite(root, s, page, m.Name, out.Model, goal,
						caller, approvedWrite(from, page))
				},
			},
			// The tool surface, which had no executor at all.
			//
			// Every part of it existed — the manifest's host allow-list,
			// Session.MayCallTool, Integrations.Resolve, and a client that
			// refuses a tool the far side newly advertises — and Dispatch had
			// no branch to reach them, so an authorised tool call came back
			// "not implemented here".
			//
			// The same client `quilzo integrations call` uses, so the two
			// surfaces cannot drift into different ideas of what may be
			// reached or which credential is presented.
			agentexec.Tools{
				Installed: func() (agent.Integrations, error) {
					set, err := loadIntegrations(root)
					if err != nil || set == nil {
						return agent.Integrations{}, err
					}
					return *set, nil
				},
				Call: newMCPClient(root),
			},
			// The delegate surface, which had no executor either.
			//
			// Manifest.Delegates was validated, refused on anything that is
			// not a supervisor, copied out of the supervisor archetype and
			// published on the agent card as this program's answer to the
			// governance gap the research calls delegation with
			// accountability. Nothing read it, so a supervisor's whole
			// reason for existing did not happen and the card said it did.
			agentexec.Delegates{
				Manifest: manifestLoader(root),
				Run: delegation{
					root: root, store: s, model: delegateModel,
					parent: m.Name,
				},
			},
			sess,
		),
		Record: func(rc agent.Receipt) {
			// The outcome, into the log that can prove it was not edited.
			// Written whatever happened: a run that was refused everything is
			// exactly the record somebody comes asking about.
			// The agent is the actor when a model chose the actions. The
			// watchdog that exists to notice one misbehaving reads the log
			// filtered to model actors, and every run here was recorded as a
			// human — so it could not see a single one. See agentactor.go.
			detail := rc.Detail()
			if from.RunID != "" {
				detail["run"] = from.RunID
			}
			record(root, actorRecord(caller, "agent.run", outcomeOf(rc), m,
				delegateModel, detail))
		},
	}

	// A run here can be held for a person and continued: every run made
	// through this function is kept, which is what makes that possible.
	runner.Pause, runner.Checkpoint = true, from.Checkpoint
	// Every action into the log as it happens, allowed or refused: one
	// record each, which an auditor can be handed with its proof (quilzo
	// agent receipt). As each step ends rather than when the run does, so a
	// run cut off half way still left a record of what it did; and once
	// more when it ends, for the step no checkpoint follows.
	recorded := 0
	if from.Prior != nil {
		recorded = len(from.Prior.Trace.Steps)
	}
	recordSteps := func(t agent.Trace) {
		for ; recorded < len(t.Steps); recorded++ {
			record(root, actionRecord(caller, m, delegateModel, from.RunID, t.Steps[recorded]))
		}
	}
	if from.Eval != nil {
		runner.Perform, runner.Record = from.Eval.perform(runner.Perform), func(agent.Receipt) {}
		recordSteps = func(agent.Trace) {}
	} else {
		keep := runner.Checkpoint
		runner.Checkpoint = func(t agent.Trace) {
			recordSteps(t)
			if keep != nil {
				keep(t)
			}
		}
	}

	started := time.Now()
	var trace agent.Trace
	var runErr error
	if from.Prior != nil {
		trace, runErr = runner.Continue(ctx, sess, from.Prior.Trace,
			from.Verdict, started)
		if runErr != nil && len(trace.Steps) == len(from.Prior.Trace.Steps) &&
			trace.Waiting == from.Prior.Trace.Waiting {
			// Refused before anything happened: not a run, and the record
			// of the one it was asked about stays as it is.
			return agentOutcome{}, runErr
		}
	} else {
		trace, runErr = runner.Run(ctx, sess, goal)
	}
	recordSteps(trace)
	rc := trace.Receipt(sess)
	out.Manifest, out.Trace, out.Receipt, out.Started = m, trace, rc, started

	// Traces, when a collector is configured.
	//
	// After Run rather than inside the Record hook, because the hook fires
	// before the trace exists — and Run returns the trace on every path it can
	// take, including the ones that ended badly, which are the runs worth
	// tracing most.
	//
	// Fail-soft and loud. A collector that is down must not fail a run that
	// otherwise worked, and a trace that silently vanished is worse than one
	// that says it could not be sent.
	if exp := tracerFor(root); exp != nil && from.Eval == nil {
		spans, terr := otlp.FromTrace(trace, rc, m, started)
		if terr == nil {
			terr = exp.Export(context.Background(), spans)
		}
		if terr != nil {
			out.TraceError = terr.Error()
		}
	}
	return out, runErr
}

// printPending says what a run stopped at and how to answer it.
func printPending(id string, w *agent.Pending) {
	what := w.Action.Op
	if what == "" {
		what = w.Action.Tool
	}
	fmt.Printf("\n  %swaiting for a person%s  step %d wants %s\n", bold, reset,
		w.N, what)
	if len(w.Action.Input) > 0 {
		if b, err := json.Marshal(w.Action.Input); err == nil {
			fmt.Printf("    with %s\n", truncate(string(b), 600))
		}
	}
	fmt.Printf("    quilzo agent approve %s %d\n", id, w.N)
	fmt.Printf("    quilzo agent decline %s %d\n", id, w.N)
}
