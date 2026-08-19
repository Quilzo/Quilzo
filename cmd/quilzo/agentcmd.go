package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/quilzo/quilzo/internal/agentexec"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
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
}

func loadAgents(root string) (*agentSet, error) {
	set := &agentSet{Agents: map[string]agent.Manifest{}}
	if err := loadJSON(agentsPath(root), set); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if set.Agents == nil {
		set.Agents = map[string]agent.Manifest{}
	}
	return set, nil
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
	case "check":
		return agentCheck(root)
	case "run":
		return agentCheckRun(root, args[1:])
	default:
		return agentUsage()
	}
}

func agentUsage() error {
	return fmt.Errorf(`usage: quilzo agent <command>

  templates              the archetypes, and when to reach for each
  new NAME --kind KIND   declare one from a template
  list                   what is declared here
  show NAME              one manifest in full
  check                  re-validate every manifest against this build
  run NAME ["goal"]      exercise one against its manifest, and record it

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
// The plan is fixed rather than proposed. A model that chooses the actions is
// the next change and a larger one, because parsing model output into actions
// is where malformed responses and injected instructions arrive — that deserves
// its own review rather than riding along with the plumbing.
func agentCheckRun(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: quilzo agent run NAME [\"what it should do\"]")
	}
	name := args[0]
	goal := "check that this agent's manifest is enforceable"
	if len(args) > 1 {
		goal = args[1]
	}

	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	m, ok := set.Agents[name]
	if !ok {
		return fmt.Errorf("no agent called %q; `quilzo agent list`", name)
	}
	// Re-validated against this build before it runs. A manifest that was
	// written when an operation existed and no longer does describes a
	// permission nothing grants, and running it would report a clean result
	// for an agent that cannot work.
	if err := m.Validate(knownCapabilities(root)); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	sess := agent.NewSession(m, nil)
	caller := resolveCaller(root, "")

	// Every capability the manifest holds, tried once, in a fixed order.
	//
	// The point is to find out which of them this store actually answers, so
	// the plan is the manifest rather than anything chosen at run time — and
	// a capability that is refused here is refused for a reason the operator
	// can read rather than one a model stumbled into.
	plan := make([]agent.Action, 0, len(m.Capabilities)+1)
	for _, c := range m.Capabilities {
		plan = append(plan, agent.Action{Op: c})
	}
	plan = append(plan, agent.Action{Say: "checked"})

	i := 0
	runner := agent.Runner{
		Decide: func(context.Context, string, []agent.Observation) (agent.Action, error) {
			if i >= len(plan) {
				return agent.Action{Say: "checked"}, nil
			}
			a := plan[i]
			i++
			return a, nil
		},
		Perform: agentexec.Reader{Store: s}.Perform(sess),
		Record: func(rc agent.Receipt) {
			// The outcome, into the log that can prove it was not edited.
			// Written whatever happened: a run that was refused everything is
			// exactly the record somebody comes asking about.
			outcome := audit.Success
			if ok, _ := rc.Billable(); !ok {
				outcome = audit.Denied
			}
			record(root, caller.auditRecord("agent.run", "/", outcome,
				rc.Detail()))
		},
	}

	trace, runErr := runner.Run(context.Background(), sess, goal)
	rc := trace.Receipt(sess)

	fmt.Printf("%s%s%s  %s\n", bold, name, reset, m.Kind)
	fmt.Printf("  %severy capability tried once, with no arguments and no "+
		"model — this reports what this store answers, not what the agent "+
		"would achieve%s\n", dim, reset)
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
	}
	fmt.Printf("  %srecorded as agent.run %s%s\n", dim, rc.Fingerprint()[:12], reset)
	return runErr
}
