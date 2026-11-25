// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/programme"
	"github.com/quilzo/quilzo/internal/register"
)

// `quilzo soa`: the statement of applicability. What the programme covers
// (a scope, a decision), whether each requirement of the frameworks it
// answers to applies within it and why (a line, a decision), and the
// statement itself, with each line's controls as evidence towards the
// requirement, as text, JSON or CSV.

func init() {
	registerCLI(cliModule{
		module:  "soa",
		command: "soa",
		heading: "security programme: the statement of applicability (each line a decision, with its approval)",
		help: "  quilzo soa scopes                        the scopes the programme is decided for\n" +
			"  quilzo soa scope NAME --title T --domains D,D [--frameworks F,F]  decide what the programme covers\n" +
			"  quilzo soa decide SCOPE FRAMEWORK REF --applies|--excluded --why TEXT  decide one line, and why\n" +
			"  quilzo soa approve ID --surface HASH     approve a scope or a line that waits for you, typing back the\n" +
			"                                            hash `quilzo approval show ID` gives\n" +
			"  quilzo soa show SCOPE [--csv]            the statement: every requirement, decided or not, and its evidence\n",
		run: cmdSoa,
		needs: map[string]need{
			"soa":         {action: auth.ActApprove},
			"soa scopes":  {action: auth.ActView},
			"soa show":    {action: auth.ActView},
			"soa scope":   {action: auth.ActEditDraft},
			"soa decide":  {action: auth.ActEditDraft},
			"soa approve": {action: auth.ActApprove},
		},
		area:   register.Area,
		reads:  [][]string{{"soa", "scopes"}},
		absent: []string{"soa", "show", "nowhere"},
		ops:    soaOps,
		notForRuns: "the statement of applicability is the compliance area's record, which a run reads under the data " +
			"classes its model route accepts, and those are not yet declared",
	})
}

func cmdSoa(root string, args []string) error {
	if len(args) == 0 {
		args = []string{bareRuns["soa"]}
	}
	switch args[0] {
	case "scopes":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return soaScopes(root)
	case "scope":
		fs := flag.NewFlagSet("soa scope", flag.ContinueOnError)
		title := fs.String("title", "", "what people call the scope")
		domains := fs.String("domains", "", "the domains it covers, separated by commas")
		frameworks := fs.String("frameworks", "", "the frameworks it answers to, separated by commas; none is every installed one")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 1); err != nil {
			return err
		}
		if len(pos) != 1 || *title == "" || *domains == "" {
			return errMisused{fmt.Errorf("usage: quilzo soa scope NAME --title T --domains D,D [--frameworks F,F]; the domains are %s",
				strings.Join(register.Domain("").Values(), ", "))}
		}
		s := register.Scope{Name: pos[0], Title: *title, Frameworks: splitList(*frameworks)}
		for _, d := range splitList(*domains) {
			s.Domains = append(s.Domains, register.Domain(d))
		}
		caller := resolveCaller(root, flagToken)
		p, by, err := programmeWriter(root, caller)
		if err != nil {
			return err
		}
		d, err := p.DecideScope(by, s)
		if err != nil {
			return programmeError(err)
		}
		return sayDecided(d, "soa")
	case "decide":
		fs := flag.NewFlagSet("soa decide", flag.ContinueOnError)
		applies := fs.Bool("applies", false, "the requirement applies within the scope")
		excluded := fs.Bool("excluded", false, "the requirement does not apply within the scope")
		why := fs.String("why", "", "why, in a sentence or two")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 3); err != nil {
			return err
		}
		if len(pos) != 3 || *applies == *excluded || strings.TrimSpace(*why) == "" {
			return errMisused{fmt.Errorf("usage: quilzo soa decide SCOPE FRAMEWORK REF --applies|--excluded --why TEXT; " +
				"say one of --applies and --excluded, and why")}
		}
		caller := resolveCaller(root, flagToken)
		p, by, err := programmeWriter(root, caller)
		if err != nil {
			return err
		}
		d, err := p.DecideLine(by, pos[0], pos[1], pos[2], *applies, *why)
		if err != nil {
			return programmeError(err)
		}
		return sayDecided(d, "soa")
	case "approve":
		return approveDecision(root, args[1:], "soa", register.KindScope, register.KindApplicability)
	case "show":
		fs := flag.NewFlagSet("soa show", flag.ContinueOnError)
		asCSV := fs.Bool("csv", false, "write the statement as CSV")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 1); err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo soa show SCOPE [--csv]; `quilzo soa scopes` names them")}
		}
		return soaShow(root, pos[0], *asCSV)
	default:
		return errMisused{fmt.Errorf("unknown soa command %q; try scopes, scope, decide, approve or show", args[0])}
	}
}

// scopeRows is every scope in the register.
func scopeRows(p *programme.Programme) ([]register.Entry, string, error) {
	v, err := headView(p)
	if err != nil {
		return nil, "", err
	}
	out := []register.Entry{}
	err = v.Each(register.KindScope, func(e register.Entry, _ map[string]any) error {
		out = append(out, e)
		return nil
	})
	return out, v.Commit(), err
}

func soaScopes(root string) error {
	p, err := openProgramme(root)
	if err != nil {
		return err
	}
	rows, head, err := scopeRows(p)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"scopes": rows, "head": head}) {
		return nil
	}
	if len(rows) == 0 {
		fmt.Println("  no scope is decided yet; `quilzo soa scope NAME --title T --domains D` decides one")
		return nil
	}
	for _, e := range rows {
		s := e.Record.(register.Scope)
		alone := ""
		if s.Approval != nil && s.Approval.Alone {
			alone = ", approved alone"
		}
		fmt.Printf("  %s%-16s%s %s%s%s%s\n", bold, s.Name, reset, printable(s.Title), dim, alone, reset)
	}
	return nil
}

func soaShow(root, scope string, asCSV bool) error {
	p, err := openProgramme(root)
	if err != nil {
		return err
	}
	v, err := headView(p)
	if err != nil {
		return err
	}
	st, err := programme.StatementAt(v, p.Words, scope)
	if errors.Is(err, register.ErrNotFound) {
		return errNotFound{fmt.Errorf("there is no scope %q; `quilzo soa scopes` names them", clip(scope, 40))}
	}
	if err != nil {
		return err
	}
	// Under --json stdout carries one document, so the statement is that
	// document whether or not it was asked for as CSV too, as `quilzo
	// register export` answers --json with its table: `quilzo --json soa
	// show SCOPE --csv` wrote the CSV, which nothing reading the document
	// parses.
	if w.JSON(st) {
		return nil
	}
	if asCSV {
		return st.WriteCSV(os.Stdout)
	}
	fmt.Printf("  %s%s%s, at %s\n", bold, printable(st.Scope.Title), reset, st.Commit)
	fmt.Printf("  %d apply, %d do not, %d undecided, across %s\n\n", st.Applying, st.NotApplying, st.Undecided,
		strings.Join(st.Frameworks, ", "))
	for _, l := range st.Lines {
		fmt.Printf("  %-10s %-14s %s%-15s%s %s\n", l.Framework, l.Ref, bold, l.State, reset, printable(l.Title))
		for _, c := range l.Controls {
			fmt.Printf("               %sevidence towards it: %s (%s), %s%s\n", dim, c.Ref, c.Relation,
				standingLine(c.Standing), reset)
		}
	}
	fmt.Printf("\n  %sevidence towards a requirement is not the requirement met; each control's relation says how much of it%s\n", dim, reset)
	return nil
}

// standingLine is how a control stood at its newest run, in words.
func standingLine(s programme.Standing) string {
	switch s.Outcome {
	case register.Pass:
		return "passing at its newest run, " + s.At.At().Format("2 Jan 2006 15:04 UTC")
	case register.Fail:
		return "failing at its newest run, " + s.At.At().Format("2 Jan 2006 15:04 UTC")
	}
	return "no evidence from a run"
}

// soaOps is the statement on the agent interface, read.
func soaOps(srv *mcp.Server, root string, caller *Caller) {
	may := programmeMay(root, caller)
	srv.Register(mcp.Operation{
		Name: "soa_scopes", NeedsRole: "reader", Area: register.Area,
		Summary:  "the scopes the security programme is decided for, each with its approval",
		Keywords: []string{"programme", "scope", "statement of applicability", "soa"},
	}, func(map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		p, err := openProgramme(root)
		if err != nil {
			return nil, err
		}
		rows, head, err := scopeRows(p)
		return map[string]any{"scopes": rows, "head": head}, err
	})
	srv.Register(mcp.Operation{
		Name: "soa_show", NeedsRole: "reader", Area: register.Area,
		Summary: "the statement of applicability for a scope: every requirement, whether it applies and why, and the controls mapped to it",
		Detail: "A requirement nobody decided is undecided, never counted as applying. Each mapped control is evidence " +
			"towards its requirement with its NIST IR 8477 relation, never the requirement met.",
		Args:     map[string]string{"scope": "the scope's machine name, as soa_scopes names it"},
		Keywords: []string{"programme", "statement of applicability", "soa", "requirements", "evidence"},
	}, func(a map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		scope, _ := a["scope"].(string)
		if scope == "" {
			return nil, &mcp.ArgumentError{Reason: "soa_show needs arguments.scope, as soa_scopes names it"}
		}
		p, err := openProgramme(root)
		if err != nil {
			return nil, err
		}
		v, err := headView(p)
		if err != nil {
			return nil, err
		}
		st, err := programme.StatementAt(v, p.Words, scope)
		return st, opError(err)
	})
}
