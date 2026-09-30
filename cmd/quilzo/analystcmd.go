// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/analyst"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/decide"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// The analyst: a model's first pass over the queue, as suggestions.
//
// `analyst triage` takes the open findings nobody has looked at, carries
// out the fixed plan in internal/analyst for each, and writes what it
// concluded as a proposal — the same record an outside agent writes through
// propose_finding_decision, shown on the finding's page for a person to
// agree with or not. It has no other way to write: this file calls the
// audit log for a proposal and nothing that records a decision.
//
// `analyst eval` measures the model that is configured, on this
// organisation's own history: the findings people have ruled on, each run
// several times, and again with instructions planted in the log text.
//
// What agents do is also put in front of the detections. Every action a
// model takes is already in the audit log; `storeAgentEvents` copies those
// into the event store as events, and raises a finding the first time an
// agent does something it has not done before.

// triageAgent is the name the analyst acts under.
const triageAgent = "analyst:triage"

// abstainAction records that the analyst looked and had no suggestion, so
// the same finding is not put to the model again until it changes.
const abstainAction = "analyst.abstained"

func agentsDir(root string) string { return filepath.Join(root, "agents") }

// analystModel is the model a triage asks, through the gateway when one is
// declared so that it is budgeted and recorded like every other caller.
func analystModel(root string) (decide.Model, string) {
	gw, _, err := modelGateway(root)
	if err != nil {
		return nil, "the model gateway could not be read: " + err.Error()
	}
	if gw != nil {
		return gw.For(triageAgent), ""
	}
	m, err := assist.NewHTTPModel()
	if err != nil {
		return nil, "no model is configured. quilzo gateway route add, " +
			"and the analyst has something to ask"
	}
	return m, ""
}

// analystSeam lets a test stand in for the model.
var analystSeam func(root string) (decide.Model, string)

func modelForAnalyst(root string) (decide.Model, string) {
	if analystSeam != nil {
		return analystSeam(root)
	}
	return analystModel(root)
}

func cmdAnalyst(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"plan"}
	}
	switch args[0] {
	case "plan":
		return analystPlan()
	case "triage":
		return analystTriage(root, args[1:])
	case "eval":
		return analystEval(root, args[1:])
	default:
		return fmt.Errorf("unknown analyst command %q; try plan, triage "+
			"or eval", args[0])
	}
}

func analystPlan() error {
	if w.JSON(map[string]any{"plan": analyst.TriagePlan,
		"decider": analyst.Decider()}) {
		return nil
	}
	w.Human("%sWhat a triage reads, in order%s\n\n", bold, reset)
	for n, s := range analyst.TriagePlan {
		mark := ""
		if s.Untrusted {
			mark = "  " + yellow + "text somebody else wrote" + reset
		}
		w.Human("%s%d.%s %s%s%s: %s%s\n", dim, n+1, reset, bold, s.Name,
			reset, s.Reads, mark)
	}
	w.Human("\n  %sthe list is fixed before anything is read, and what "+
		"comes out is a suggestion a person agrees with or not%s\n", dim,
		reset)
	return nil
}

// alreadyLooked is the findings the analyst has been through, and how
// many times each had been seen when it was.
func alreadyLooked(events []audit.Event) map[string]string {
	out := map[string]string{}
	for _, e := range events {
		if e.Detail["agent"] != "triage" {
			continue
		}
		if e.Action == finding.ProposalAction || e.Action == abstainAction {
			out[e.Detail["finding"]] = e.Detail["seen"]
		}
	}
	return out
}

// incidentFindings is every finding an incident gathers.
func incidentFindings(root string) (map[string]bool, error) {
	all, err := listIncidents(root)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, i := range all {
		for _, f := range i.Findings {
			out[f] = true
		}
	}
	return out, nil
}

// triageOutcome is what happened to one finding.
type triageOutcome struct {
	Finding string `json:"finding"`
	analyst.Suggestion
}

// runTriage is the analyst's pass. on is who asked for it.
func runTriage(ctx context.Context, root string, caller *Caller, limit int,
	dry bool, now time.Time) ([]triageOutcome, int, error) {

	if caller.Kind == audit.KindAI {
		return nil, 0, fmt.Errorf("the analyst is started by a person. A " +
			"model starting a model is a loop with nobody in it")
	}
	m, why := modelForAnalyst(root)
	if m == nil {
		return nil, 0, fmt.Errorf("%s", why)
	}
	q, err := loadQueue(root, now)
	if err != nil {
		return nil, 0, err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, 0, err
	}
	looked := alreadyLooked(events)
	gathered, err := incidentFindings(root)
	if err != nil {
		return nil, 0, err
	}
	var out []triageOutcome
	waiting := 0
	for _, f := range q {
		if f.State != finding.Open {
			continue
		}
		seen := fmt.Sprint(f.Seen)
		if looked[f.ID] == seen {
			// Looked at, and nothing about it has changed since.
			continue
		}
		if len(out) >= limit {
			waiting++
			continue
		}
		s, terr := analyst.Triage(ctx, m, f, q, gathered[f.ID], now)
		if terr != nil {
			return out, waiting, fmt.Errorf("%s: %w", f.ID, terr)
		}
		out = append(out, triageOutcome{f.ID, s})
		if dry {
			continue
		}
		rec := audit.Record{Action: abstainAction, Resource: "/" + f.ID,
			Outcome:   audit.Success,
			Principal: triageAgent, Kind: audit.KindAI, Model: m.Name(),
			Verified: false,
			Detail: map[string]string{"finding": f.ID, "agent": "triage",
				"seen": seen, "on_behalf_of": caller.Name,
				"confidence": fmt.Sprintf("%.2f", s.Confidence)}}
		if s.To != "" {
			rec.Action = finding.ProposalAction
			rec.Detail["to"] = string(s.To)
			rec.Detail["because"] = s.Reason
		} else {
			// A closed set of reasons, not the model's words.
			rec.Detail["why"] = abstainWord(s.Abstained)
		}
		if err := recordE(root, rec); err != nil {
			return out, waiting, err
		}
	}
	return out, waiting, nil
}

// abstainWord reduces why the analyst had no suggestion to one of a few
// words, so nothing a model produced is copied into the log.
func abstainWord(why string) string {
	switch {
	case strings.Contains(why, "threshold"):
		return "not confident enough"
	case strings.Contains(why, "no model"), strings.Contains(why, "could not be used"):
		return "the model could not be used"
	}
	return "no usable answer"
}

func analystTriage(root string, args []string) error {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "how many findings to look at")
	dry := fs.Bool("dry-run", false, "look, and record nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *limit < 1 || *limit > 500 {
		return fmt.Errorf("--limit is between 1 and 500")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	out, waiting, err := runTriage(ctx, root, caller, *limit, *dry,
		time.Now().UTC())
	if err != nil {
		return err
	}
	suggested := 0
	for _, o := range out {
		if o.To != "" {
			suggested++
		}
	}
	if w.JSON(map[string]any{"looked": len(out), "suggested": suggested,
		"waiting": waiting, "dry_run": *dry, "findings": out}) {
		return nil
	}
	if len(out) == 0 {
		w.Human("Nothing open that the analyst has not already looked at.\n")
		return nil
	}
	for _, o := range out {
		if o.To == "" {
			w.Human("  %s%s%s  no suggestion: %s\n", dim, o.Finding, reset,
				abstainWord(o.Abstained))
			continue
		}
		w.Human("  %s%s%s  suggests %s%s%s at %.2f\n", dim, o.Finding, reset,
			bold, o.To, reset, o.Confidence)
	}
	w.Human("\n%s%d looked at, %d suggestion(s)%s", bold, len(out), suggested,
		reset)
	if waiting > 0 {
		w.Human(", %d more waiting", waiting)
	}
	w.Human("\n")
	if *dry {
		w.Human("  %sa dry run: nothing was recorded%s\n", dim, reset)
	} else {
		w.Human("  %snothing has changed state. Each suggestion is on its "+
			"finding's page for a person to agree with or not%s\n", dim, reset)
	}
	return nil
}

// verdictCases turns what people have ruled into cases: each finding as
// the analyst would have seen it, with its own verdict left out.
func verdictCases(q []finding.Finding, gathered map[string]bool,
	now time.Time, limit int) []analyst.Case {

	var out []analyst.Case
	for _, f := range q {
		want := ""
		switch f.State {
		case finding.Triaged, finding.Fixed, finding.Accepted:
			want = analyst.Real
		case finding.FalsePositive:
			want = analyst.FalsePositive
		case finding.Benign:
			want = analyst.Benign
		default:
			continue
		}
		st, _ := analyst.Gather(f, q, gathered[f.ID], now)
		out = append(out, analyst.Case{Name: f.ID, State: st, Expect: want})
		if len(out) == limit {
			break
		}
	}
	return out
}

func analystEval(root string, args []string) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	k := fs.Int("k", 3, "how many times each case is run")
	limit := fs.Int("limit", 50, "how many ruled findings to use")
	file := fs.String("cases", "", "cases from a file, one JSON object "+
		"per line, instead of the findings people have ruled on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	m, why := modelForAnalyst(root)
	if m == nil {
		return fmt.Errorf("%s", why)
	}
	now := time.Now().UTC()
	var cases []analyst.Case
	if *file != "" {
		err := loadJSONL(*file, func(b []byte) error {
			var c analyst.Case
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			cases = append(cases, c)
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		q, err := loadQueue(root, now)
		if err != nil {
			return err
		}
		gathered, err := incidentFindings(root)
		if err != nil {
			return err
		}
		cases = verdictCases(q, gathered, now, *limit)
		if len(cases) == 0 {
			return fmt.Errorf("nobody has ruled on a finding yet, so there " +
				"is nothing to measure the analyst against. Rule on some, " +
				"or give --cases FILE")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	rep, err := analyst.Evaluate(ctx, m, cases, *k)
	if err != nil {
		return err
	}
	record(root, audit.Record{Action: "analyst.evaluated", Resource: "/agents",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified, Detail: map[string]string{
			"cases": fmt.Sprint(rep.Cases), "k": fmt.Sprint(rep.K),
			"reliable": fmt.Sprint(rep.Reliable), "wrong": fmt.Sprint(rep.Wrong),
			"hijacked": fmt.Sprint(rep.Hijacked), "model": m.Name()}})
	if w.JSON(rep) {
		return nil
	}
	w.Human("%s%d case(s), each run %d time(s)%s, on %s\n\n", bold, rep.Cases,
		rep.K, reset, m.Name())
	w.Human("  %s%d reliable%s: right on every run (pass^%d = %.0f%%)\n",
		green, rep.Reliable, reset, rep.K, rep.PassK*100)
	w.Human("  %s%d abstained%s: never wrong, and left some to a person\n",
		dim, rep.Abstained, reset)
	colour := dim
	if rep.Wrong > 0 {
		colour = red
	}
	w.Human("  %s%d wrong%s: confidently suggested something a person ruled "+
		"otherwise\n", colour, rep.Wrong, reset)
	for _, n := range rep.WrongCases {
		w.Human("      %s%s%s\n", dim, n, reset)
	}
	colour = dim
	if rep.Hijacked > 0 {
		colour = red
	}
	w.Human("\n  %s%d of %d hijacked%s: text planted where a log's text goes "+
		"moved the suggestion to what it asked for\n", colour, rep.Hijacked,
		rep.Planted, reset)
	for _, n := range rep.HijackedCases {
		w.Human("      %s%s%s\n", dim, n, reset)
	}
	w.Human("\n  %seven hijacked, the analyst can only suggest: a person "+
		"records every verdict%s\n", dim, reset)
	return nil
}

// ---- agents as a log source -------------------------------------------------

// agentsSeen is what has been observed of the agents so far.
type agentsSeen struct {
	// Seq is the last audit entry read.
	Seq int64 `json:"seq"`
	// Did is each agent's actions, and First when it was first seen.
	Did   map[string][]string  `json:"did"`
	First map[string]time.Time `json:"first"`
}

func agentsSeenPath(root string) string {
	return filepath.Join(agentsDir(root), "observed.json")
}

func loadAgentsSeen(root string) (agentsSeen, error) {
	s := agentsSeen{Did: map[string][]string{}, First: map[string]time.Time{}}
	b, err := os.ReadFile(agentsSeenPath(root))
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("observed.json: %w", err)
	}
	if s.Did == nil {
		s.Did = map[string][]string{}
	}
	if s.First == nil {
		s.First = map[string]time.Time{}
	}
	return s, nil
}

// AgentSettling is how long an agent is watched before something new from
// it is remarkable. On its first day everything it does is new.
const AgentSettling = 24 * time.Hour

// AgentSource is the source agents' actions are stored under.
const AgentSource = "quilzo/agents"

// storeAgentEvents copies what models have done, from the audit log, into the
// event store, and raises a finding when a settled agent does something it
// has not done before. It returns how many events it stored and how many
// findings it opened.
//
// The event carries the action, the outcome and the resource: what the
// audit log already holds. Nothing a model wrote is copied.
func storeAgentEvents(root string, sp *spool.Spool, reg *finding.Register,
	now time.Time) (stored, opened int, err error) {

	events, err := audit.Read(auditPath(root))
	if err != nil {
		return 0, 0, err
	}
	seen, err := loadAgentsSeen(root)
	if err != nil {
		return 0, 0, err
	}
	last := seen.Seq
	for _, e := range events {
		if e.Seq <= seen.Seq || e.Kind != audit.KindAI {
			if e.Seq > last {
				last = e.Seq
			}
			continue
		}
		last = e.Seq
		at, perr := time.Parse(time.RFC3339Nano, e.At)
		if perr != nil {
			at = now
		}
		who := telemetry.ID{Issuer: "agent", Value: e.Principal}
		disposition := telemetry.DispositionAllowed
		if e.Outcome != audit.Success {
			disposition = telemetry.DispositionFailed
		}
		ev := telemetry.Event{Time: at, Received: now,
			Class: telemetry.ClassAPIActivity, Disposition: disposition,
			Source: AgentSource, Actor: who,
			Message: e.Action + " " + string(e.Outcome),
			Raw: map[string]string{"action": e.Action,
				"outcome": string(e.Outcome), "resource": e.Resource}}
		if _, aerr := sp.Append(ev); aerr != nil {
			return stored, opened, aerr
		}
		stored++

		known := false
		for _, a := range seen.Did[e.Principal] {
			known = known || a == e.Action
		}
		first, met := seen.First[e.Principal]
		if !met {
			seen.First[e.Principal] = at
			first = at
		}
		if !known {
			if len(seen.Did[e.Principal]) < 500 {
				seen.Did[e.Principal] = append(seen.Did[e.Principal], e.Action)
				sort.Strings(seen.Did[e.Principal])
			}
			if at.Sub(first) > AgentSettling {
				if _, isNew := reg.Record(finding.Finding{
					Kind:   finding.FromDetection,
					Title:  "An agent did something it has not done before: " + e.Action,
					Source: "agent/new-action/" + e.Action, Entity: who,
					Severity: telemetry.SeverityMedium, State: finding.Open,
					Evidence: []finding.Evidence{{At: at, Source: AgentSource,
						What: e.Action + " on " + e.Resource + ", " +
							string(e.Outcome), Ref: e.Hash}},
				}, at); isNew {
					opened++
				}
			}
		}
	}
	seen.Seq = last
	b, merr := json.MarshalIndent(seen, "", "  ")
	if merr != nil {
		return stored, opened, merr
	}
	if err := os.MkdirAll(agentsDir(root), 0o700); err != nil {
		return stored, opened, err
	}
	return stored, opened, atomicfile.Write(agentsSeenPath(root), b, 0o600)
}
