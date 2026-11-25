// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/programme"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// `quilzo control`: what the organisation does, and what shows it working.
// Controls and their mappings to requirements; control tests, drafted as a
// typed query by a person or a model and approved by somebody else; their
// runs, each explained by code and replayed from the commit it read.

func init() {
	registerCLI(cliModule{
		module:  "control",
		command: "control",
		heading: "security programme: controls and control tests (typed queries a person approves, run on a schedule)",
		help: "  quilzo control list                      the controls, each with how it stood at its newest run\n" +
			"  quilzo control add REF --title T --domain D [--owner NAME]  add a control\n" +
			"  quilzo control map REF FRAMEWORK REQ --relation R --why TEXT  map a control to a requirement (NIST IR 8477)\n" +
			"  quilzo control schema                    the JSON schema a test's draft fills in\n" +
			"  quilzo control draft FILE                propose a test from a draft (FILE, or - for standard input)\n" +
			"  quilzo control approve ID --surface HASH  approve a test that waits for you, and its query, typing back\n" +
			"                                            the hash `quilzo approval show ID` gives\n" +
			"  quilzo control tests                     the approved tests, each with its newest run\n" +
			"  quilzo control run TEST | --due          run one approved test, or every one that is due\n" +
			"  quilzo control explain RUN               why a run came out as it did, in code's words\n" +
			"  quilzo control replay RUN                do a run again from the commit it read, and compare\n",
		run: cmdControl,
		needs: map[string]need{
			"control":         {action: auth.ActApprove},
			"control list":    {action: auth.ActView},
			"control tests":   {action: auth.ActView},
			"control schema":  {action: auth.ActView},
			"control explain": {action: auth.ActView},
			"control replay":  {action: auth.ActView},
			"control add":     {action: auth.ActEditDraft},
			"control map":     {action: auth.ActEditDraft},
			"control draft":   {action: auth.ActEditDraft},
			"control approve": {action: auth.ActApprove},
			"control run":     {action: auth.ActEditDraft},
		},
		area:   register.Area,
		reads:  [][]string{{"control", "list"}, {"control", "tests"}, {"control", "schema"}},
		absent: []string{"control", "explain", "00000000000000000000000000000000"},
		ops:    controlOps,
		notForRuns: "the controls and their evidence are the compliance area's record, which a run reads under the data " +
			"classes its model route accepts, and those are not yet declared",
	})
}

func cmdControl(root string, args []string) error {
	if len(args) == 0 {
		args = []string{bareRuns["control"]}
	}
	one := func(usage string) (string, error) {
		pos, err := positionals(args[1:], 1)
		if err != nil {
			return "", err
		}
		if len(pos) != 1 {
			return "", errMisused{fmt.Errorf("usage: %s", usage)}
		}
		return pos[0], nil
	}
	switch args[0] {
	case "list":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return controlList(root)
	case "tests":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return controlTests(root)
	case "schema":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		schema := programme.DraftSchema()
		if w.JSON(schema) {
			return nil
		}
		b, _ := json.MarshalIndent(schema, "", "  ")
		fmt.Println(string(b))
		return nil
	case "add":
		fs := flag.NewFlagSet("control add", flag.ContinueOnError)
		title := fs.String("title", "", "what the control is, in a line")
		domain := fs.String("domain", "", "the part of the organisation it is about")
		owner := fs.String("owner", "", "who answers for it; yourself when not given")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 1); err != nil {
			return err
		}
		if len(pos) != 1 || *title == "" || *domain == "" {
			return errMisused{fmt.Errorf("usage: quilzo control add REF --title T --domain D [--owner NAME]; the domains are %s",
				strings.Join(register.Domain("").Values(), ", "))}
		}
		caller := resolveCaller(root, flagToken)
		p, by, err := programmeWriter(root, caller)
		if err != nil {
			return err
		}
		who := by.Subject
		if *owner != "" {
			if who, err = p.Reg.SubjectFor(*owner, "person"); err != nil {
				return err
			}
		}
		if !who.Valid() {
			return errMisused{fmt.Errorf("say who answers for the control with --owner NAME")}
		}
		id, rc, err := p.AddControl(by, register.Control{Ref: pos[0], Title: *title, Domain: register.Domain(*domain), Owner: who})
		if err != nil {
			return programmeError(err)
		}
		return sayWritten(map[string]any{"control": id, "receipt": rc}, "the control "+pos[0], rc)
	case "map":
		fs := flag.NewFlagSet("control map", flag.ContinueOnError)
		relation := fs.String("relation", "", "how the control relates to the requirement: "+strings.Join(register.Relation("").Values(), ", "))
		why := fs.String("why", "", "why, in a sentence or two")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 3); err != nil {
			return err
		}
		if len(pos) != 3 || *relation == "" || strings.TrimSpace(*why) == "" {
			return errMisused{fmt.Errorf("usage: quilzo control map REF FRAMEWORK REQ --relation R --why TEXT; the relations are %s",
				strings.Join(register.Relation("").Values(), ", "))}
		}
		p, by, err := programmeWriter(root, resolveCaller(root, flagToken))
		if err != nil {
			return err
		}
		id, rc, err := p.MapControl(by, pos[0], pos[1], pos[2], register.Relation(*relation), *why)
		if err != nil {
			return programmeError(err)
		}
		return sayWritten(map[string]any{"mapping": id, "receipt": rc}, "the mapping", rc)
	case "draft":
		file, err := one("quilzo control draft FILE (or - for standard input); `quilzo control schema` is what it holds")
		if err != nil {
			return err
		}
		var b []byte
		if file == "-" {
			b, err = io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		} else {
			b, err = os.ReadFile(file)
		}
		if err != nil {
			return err
		}
		d, err := programme.ParseDraft(b)
		if err != nil {
			return errMisused{err}
		}
		p, by, err := programmeWriter(root, resolveCaller(root, flagToken))
		if err != nil {
			return err
		}
		got, err := p.ProposeDraft(by, d)
		if err != nil {
			return programmeError(err)
		}
		if w.JSON(got) {
			return nil
		}
		fmt.Printf("  the test %s%s%s waits for somebody who did not draft it: on Sign-off in the admin, or at the console, "+
			"where `quilzo approval show %s` shows it and the hash they type back to\n    quilzo control approve %s --surface HASH\n",
			bold, d.Name, reset, got.TestID, got.TestID)
		fmt.Printf("  %snothing runs it until then, and its query is filed under %s%s\n", dim, got.Query.Digest, reset)
		return nil
	case "approve":
		return approveDecision(root, args[1:], "control", register.KindControlTest)
	case "run":
		fs := flag.NewFlagSet("control run", flag.ContinueOnError)
		due := fs.Bool("due", false, "run every approved test that is due")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 1); err != nil {
			return err
		}
		if *due == (len(pos) == 1) {
			return errMisused{fmt.Errorf("usage: quilzo control run TEST | --due")}
		}
		var test register.ID
		if !*due {
			var err error
			if test, err = identifierWord(pos[0], "a test", "control tests"); err != nil {
				return err
			}
		}
		p, by, err := programmeWriter(root, resolveCaller(root, flagToken))
		if err != nil {
			return err
		}
		if *due {
			n, err := p.RunDue(by)
			if w.JSON(map[string]any{"ran": n}) {
				return registerError(err)
			}
			fmt.Printf("  ran %s\n", count(n, "test"))
			return registerError(err)
		}
		run, rc, err := p.RunTest(by, test)
		if err != nil {
			return registerError(err)
		}
		if w.JSON(map[string]any{"run": run, "receipt": rc, "explanation": programme.Explain(run)}) {
			return nil
		}
		for _, line := range programme.Explain(run) {
			fmt.Printf("  %s\n", line)
		}
		if rc.Commit != "" {
			fmt.Printf("  %sthe register stands at %s%s\n", dim, rc.Commit, reset)
		}
		return nil
	case "explain":
		id, err := one("quilzo control explain RUN")
		if err != nil {
			return err
		}
		if _, err := identifierWord(id, "a run", "control tests"); err != nil {
			return err
		}
		return controlExplain(root, id)
	case "replay":
		id, err := one("quilzo control replay RUN")
		if err != nil {
			return err
		}
		if _, err := identifierWord(id, "a run", "control tests"); err != nil {
			return err
		}
		p, err := openProgramme(root)
		if err != nil {
			return err
		}
		r, err := p.Replay(register.ID(id))
		if err != nil {
			return registerError(err)
		}
		if w.JSON(r) {
			return nil
		}
		if r.Same {
			fmt.Printf("  %sthe same%s: read again at %s, the run gives what was recorded\n", bold, reset, r.Recorded.Commit)
			return nil
		}
		fmt.Printf("  %snot the same%s: read again at %s,\n", bold, reset, r.Recorded.Commit)
		for _, d := range r.Differences {
			fmt.Printf("    %s\n", d)
		}
		return fmt.Errorf("the replay of %s does not give the recorded run", id)
	default:
		return errMisused{fmt.Errorf("unknown control command %q; try list, add, map, schema, draft, approve, tests, run, explain or replay", args[0])}
	}
}

// sayWritten says a write landed.
func sayWritten(v any, what string, rc register.Receipt) error {
	if w.JSON(v) {
		return nil
	}
	if rc.Commit == "" {
		fmt.Printf("  %s is in the register already, unchanged\n", what)
		return nil
	}
	fmt.Printf("  wrote %s; the register stands at %s\n", what, rc.Commit)
	return nil
}

// controlRow is a control with how it stands.
type controlRow struct {
	register.Entry
	Standing programme.Standing `json:"standing"`
}

func controlRows(p *programme.Programme) ([]controlRow, string, error) {
	v, err := headView(p)
	if err != nil {
		return nil, "", err
	}
	standing, err := programme.Standings(v)
	if err != nil {
		return nil, "", err
	}
	out := []controlRow{}
	err = v.Each(register.KindControl, func(e register.Entry, _ map[string]any) error {
		out = append(out, controlRow{Entry: e, Standing: standing[e.ID]})
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		return out[i].Record.(register.Control).Ref < out[j].Record.(register.Control).Ref
	})
	return out, v.Commit(), err
}

func controlList(root string) error {
	p, err := openProgramme(root)
	if err != nil {
		return err
	}
	rows, head, err := controlRows(p)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"controls": rows, "head": head}) {
		return nil
	}
	if len(rows) == 0 {
		fmt.Println("  no control yet; `quilzo control add REF --title T --domain D` adds one")
		return nil
	}
	for _, r := range rows {
		c := r.Record.(register.Control)
		fmt.Printf("  %s%-10s%s %-44s %s%s%s\n", bold, c.Ref, reset, truncate(printable(c.Title), 44), dim, standingLine(r.Standing), reset)
	}
	return nil
}

// testRow is an approved test with its newest run.
type testRow struct {
	register.Entry
	Last   *register.TestRun `json:"last,omitempty"`
	LastID register.ID       `json:"last_id,omitempty"`
}

func testRows(p *programme.Programme) ([]testRow, string, error) {
	v, err := headView(p)
	if err != nil {
		return nil, "", err
	}
	last := map[register.ID]register.Entry{}
	if err := v.Each(register.KindTestRun, func(e register.Entry, _ map[string]any) error {
		r := e.Record.(register.TestRun)
		if had, ok := last[r.Test]; !ok || r.Ran > had.Record.(register.TestRun).Ran {
			last[r.Test] = e
		}
		return nil
	}); err != nil {
		return nil, "", err
	}
	out := []testRow{}
	err = v.Each(register.KindControlTest, func(e register.Entry, _ map[string]any) error {
		row := testRow{Entry: e}
		if l, ok := last[e.ID]; ok {
			r := l.Record.(register.TestRun)
			row.Last, row.LastID = &r, l.ID
		}
		out = append(out, row)
		return nil
	})
	return out, v.Commit(), err
}

func controlTests(root string) error {
	p, err := openProgramme(root)
	if err != nil {
		return err
	}
	rows, head, err := testRows(p)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"tests": rows, "head": head}) {
		return nil
	}
	if len(rows) == 0 {
		fmt.Println("  no approved test yet; `quilzo control draft FILE` proposes one")
		return nil
	}
	for _, r := range rows {
		t := r.Record.(register.ControlTest)
		last := "never run"
		if r.Last != nil {
			last = fmt.Sprintf("%s at %s (run %s)", r.Last.Outcome, r.Last.Ran.At().Format("2 Jan 2006 15:04 UTC"), r.LastID)
		}
		fmt.Printf("  %s  %s%-20s%s %s%s%s\n", r.ID, bold, t.Name, reset, dim, last, reset)
	}
	return nil
}

// explained is a run and its explanation, read back.
func explained(p *programme.Programme, id string) (map[string]any, error) {
	if !register.ID(id).Valid() {
		return nil, fmt.Errorf("%w: %q is not a run's identifier", register.ErrNotFound, clip(id, 40))
	}
	e, err := p.Reg.Get(register.ID(id))
	if err != nil {
		return nil, err
	}
	rec, ok := e.Record.(register.TestRun)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a run of a control test", register.ErrNotFound, id)
	}
	if rec.Commit == "" {
		return map[string]any{"run": rec, "explanation": []string{"The run does not name the commit it read."}}, nil
	}
	v, err := p.Reg.At(rec.Commit)
	if err != nil {
		return nil, err
	}
	run, err := programme.Evaluate(v, rec.Test, rec.Ran.At())
	if err != nil {
		return nil, err
	}
	// The explanation is of the run as it was recorded: its members and its
	// failures, with the test and population as they stood when it ran.
	run.Record = rec
	return map[string]any{"run": rec, "id": id, "explanation": programme.Explain(run)}, nil
}

func controlExplain(root, id string) error {
	p, err := openProgramme(root)
	if err != nil {
		return err
	}
	out, err := explained(p, id)
	if err != nil {
		return registerError(err)
	}
	if w.JSON(out) {
		return nil
	}
	for _, line := range out["explanation"].([]string) {
		fmt.Printf("  %s\n", line)
	}
	return nil
}

// controlTestsJob runs the approved tests that are due, on the admin
// server's timer, as the scheduler.
func controlTestsJob(root string) upkeep.Job {
	return upkeep.Job{Name: "control tests", Do: func(now time.Time) (int, error) {
		s, err := open(root)
		if err != nil {
			return 0, err
		}
		r := register.Open(s)
		r.Audit = func(rec audit.Record) error { return recordE(root, rec) }
		r.Ready = func() error { return auditReady(root) }
		p := &programme.Programme{Reg: r, Now: func() time.Time { return now }}
		return p.RunDue(programme.Scheduler())
	}}
}

// controlOps is the controls on the agent interface: the controls, the
// tests, a run's explanation and its replay, read; and a test's draft,
// which an agent fills in as the draft's schema says and which waits for a
// person, as every draft does.
func controlOps(srv *mcp.Server, root string, caller *Caller) {
	may := programmeMay(root, caller)
	srv.Register(mcp.Operation{
		Name: "control_list", NeedsRole: "reader", Area: register.Area,
		Summary:  "the controls of the security programme, each with how it stood at its newest run",
		Keywords: []string{"programme", "controls", "status", "evidence", "tests"},
	}, func(map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		p, err := openProgramme(root)
		if err != nil {
			return nil, err
		}
		rows, head, err := controlRows(p)
		return map[string]any{"controls": rows, "head": head}, err
	})
	srv.Register(mcp.Operation{
		Name: "control_tests", NeedsRole: "reader", Area: register.Area,
		Summary:  "the approved control tests, each with its newest run",
		Keywords: []string{"programme", "control tests", "runs", "schedule"},
	}, func(map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		p, err := openProgramme(root)
		if err != nil {
			return nil, err
		}
		rows, head, err := testRows(p)
		return map[string]any{"tests": rows, "head": head}, err
	})
	srv.Register(mcp.Operation{
		Name: "control_explain", NeedsRole: "reader", Area: register.Area,
		Summary:  "why a run of a control test came out as it did, in lines code writes from the assertion, the query and the failing members",
		Args:     map[string]string{"run": "the run's identifier: 32 hexadecimal characters"},
		Keywords: []string{"programme", "control test", "failure", "explanation", "run"},
	}, func(a map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		id, _ := a["run"].(string)
		p, err := openProgramme(root)
		if err != nil {
			return nil, err
		}
		out, err := explained(p, id)
		return out, opError(err)
	})
	srv.Register(mcp.Operation{
		Name: "control_replay", NeedsRole: "reader", Area: register.Area,
		Summary:  "a run of a control test done again from the register commit it read, and whether it gives the recorded run",
		Args:     map[string]string{"run": "the run's identifier: 32 hexadecimal characters"},
		Keywords: []string{"programme", "control test", "replay", "reproduce", "audit"},
	}, func(a map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		id, _ := a["run"].(string)
		if !register.ID(id).Valid() {
			return nil, &mcp.ArgumentError{Reason: "control_replay needs arguments.run, a run's identifier of 32 hexadecimal characters"}
		}
		p, err := openProgramme(root)
		if err != nil {
			return nil, err
		}
		r, err := p.Replay(register.ID(id))
		return r, opError(err)
	})
	srv.Register(mcp.Operation{
		Name: "control_draft", NeedsRole: "author", Area: register.Area, Writes: true,
		Summary: "propose a control test: a typed query over the register and an assertion over a population, which waits for a person",
		Detail: "The arguments are the draft's schema (quilzo control schema) and nothing else: a field it does not " +
			"have is refused, as is a query field the kind does not have, a value of the wrong type, or a value " +
			"with a space in it. The draft waits on the register's proposals ref; nothing runs it until a person " +
			"who did not draft it approves it.",
		Args: map[string]string{"control": "the control's reference", "name": "the test's machine name",
			"population": "the population's machine name", "assertion": "all or none",
			"every": "optional, seconds between runs, at least 3600", "query": "the typed query: of, member and terms"},
		Types:    map[string]string{"every": "number", "query": "object"},
		Keywords: []string{"programme", "control test", "draft", "query", "propose"},
	}, func(a map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActEditDraft, register.Area); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		b, err := json.Marshal(a)
		if err != nil {
			return nil, &mcp.ArgumentError{Reason: err.Error()}
		}
		d, err := programme.ParseDraft(b)
		if err != nil {
			return nil, &mcp.ArgumentError{Reason: err.Error()}
		}
		p, by, err := programmeWriter(root, caller)
		if err != nil {
			return nil, err
		}
		got, err := p.ProposeDraft(by, d)
		return got, opError(err)
	})
}
