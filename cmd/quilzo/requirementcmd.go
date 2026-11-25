// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"sort"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/programme"
	"github.com/quilzo/quilzo/internal/register"
)

// `quilzo requirement`: what the organisation has to do. The frameworks
// this program carries starters for, taken into the programme or out of it
// as one decision each, and the requirements they brought, each by the
// framework's own identifier with a line in Quilzo's own words.

func init() {
	registerCLI(cliModule{
		module:  "requirement",
		command: "requirement",
		heading: "security programme: requirements (frameworks' starters, in Quilzo's own words, mapped by identifier)",
		help: "  quilzo requirement starters              the frameworks there are starters for, and which are installed\n" +
			"  quilzo requirement install | uninstall FRAMEWORK  take a starter into the programme, or out, as one decision\n" +
			"  quilzo requirement approve ID            approve a starter's installation that waits for you\n" +
			"  quilzo requirement list [--framework F]  the requirements of the installed starters\n" +
			"  quilzo requirement show FRAMEWORK REF    one requirement, with what it is mapped to\n",
		run: cmdRequirement,
		needs: map[string]need{
			"requirement":           {action: auth.ActApprove},
			"requirement starters":  {action: auth.ActView},
			"requirement list":      {action: auth.ActView},
			"requirement show":      {action: auth.ActView},
			"requirement install":   {action: auth.ActEditDraft},
			"requirement uninstall": {action: auth.ActEditDraft},
			"requirement approve":   {action: auth.ActApprove},
		},
		area:   register.Area,
		reads:  [][]string{{"requirement", "starters"}, {"requirement", "list"}},
		absent: []string{"requirement", "show", "iso-27001", "A.0.0"},
		ops:    requirementOps,
		notForRuns: "the programme is the compliance area's record, which a run reads under the data classes its " +
			"model route accepts, and those are not yet declared",
	})
}

func cmdRequirement(root string, args []string) error {
	if len(args) == 0 {
		args = []string{bareRuns["requirement"]}
	}
	switch args[0] {
	case "starters":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return requirementStarters(root)
	case "install", "uninstall":
		pos, err := positionals(args[1:], 1)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo requirement %s FRAMEWORK; `quilzo requirement starters` names them", args[0])}
		}
		caller := resolveCaller(root, flagToken)
		p, by, err := programmeWriter(root, caller)
		if err != nil {
			return err
		}
		d := deciderFor(root, caller, by, register.KindStarter)
		var got programme.Decided
		if args[0] == "install" {
			got, err = p.Install(d, pos[0])
		} else {
			got, err = p.Uninstall(d, pos[0])
		}
		if err != nil {
			return programmeError(err)
		}
		return sayDecided(got, "requirement")
	case "approve":
		pos, err := positionals(args[1:], 1)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo requirement approve ID")}
		}
		return approveDecision(root, pos[0], "requirement", register.KindStarter)
	case "list":
		fs := flag.NewFlagSet("requirement list", flag.ContinueOnError)
		framework := fs.String("framework", "", "only this framework's requirements")
		if err := parseFlags(fs, args[1:], nil, 0); err != nil {
			return err
		}
		return requirementList(root, *framework)
	case "show":
		pos, err := positionals(args[1:], 2)
		if err != nil {
			return err
		}
		if len(pos) != 2 {
			return errMisused{fmt.Errorf("usage: quilzo requirement show FRAMEWORK REF")}
		}
		return requirementShow(root, pos[0], pos[1])
	default:
		return errMisused{fmt.Errorf("unknown requirement command %q; try starters, install, uninstall, approve, list or show", args[0])}
	}
}

// starterRow is a starter as the command line and the agent interface list
// it.
type starterRow struct {
	Framework    string `json:"framework"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	About        string `json:"about"`
	Level        string `json:"level"`
	Requirements int    `json:"requirements"`
	Mappings     int    `json:"mappings"`
	Installed    bool   `json:"installed"`
	// Alone says the decision that installed it was made alone.
	Alone bool `json:"alone,omitempty"`
}

func starterRows(p *programme.Programme) ([]starterRow, string, error) {
	v, err := headView(p)
	if err != nil {
		return nil, "", err
	}
	installed, err := programme.Installed(v)
	if err != nil {
		return nil, "", err
	}
	var out []starterRow
	for _, s := range programme.Starters() {
		d, in := installed[s.Framework]
		out = append(out, starterRow{Framework: s.Framework, Name: s.Name, Version: s.Version, About: s.About, Level: s.Level,
			Requirements: len(s.Clauses), Mappings: len(s.Crosswalk), Installed: in,
			Alone: in && d.Approval != nil && d.Approval.Alone})
	}
	return out, v.Commit(), nil
}

func requirementStarters(root string) error {
	p, err := openProgramme(root)
	if err != nil {
		return err
	}
	rows, head, err := starterRows(p)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"starters": rows, "head": head}) {
		return nil
	}
	for _, s := range rows {
		state := "not installed"
		if s.Installed {
			state = "installed"
			if s.Alone {
				state = "installed, approved alone"
			}
		}
		fmt.Printf("  %s%-10s%s %-32s %3d %-22s %s%s%s\n", bold, s.Framework, reset, s.Name+" "+s.Version, s.Requirements,
			s.Level, dim, state, reset)
	}
	fmt.Printf("\n  %seach line is in Quilzo's own words; the frameworks' texts are their publishers', read by identifier%s\n", dim, reset)
	return nil
}

// requirementRows is the requirements of the installed starters, in each
// framework's own order.
func requirementRows(p *programme.Programme, framework string) ([]register.Entry, string, error) {
	v, err := headView(p)
	if err != nil {
		return nil, "", err
	}
	installed, err := programme.Installed(v)
	if err != nil {
		return nil, "", err
	}
	order := map[string]int{}
	for _, s := range programme.Starters() {
		for i, c := range s.Clauses {
			order[s.Framework+" "+c.Ref] = i
		}
	}
	var out []register.Entry
	err = v.Each(register.KindRequirement, func(e register.Entry, _ map[string]any) error {
		q := e.Record.(register.Requirement)
		if _, in := installed[q.Framework]; in && (framework == "" || framework == q.Framework) {
			out = append(out, e)
		}
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Record.(register.Requirement), out[j].Record.(register.Requirement)
		if a.Framework != b.Framework {
			return a.Framework < b.Framework
		}
		return order[a.Framework+" "+a.Ref] < order[b.Framework+" "+b.Ref]
	})
	if out == nil {
		out = []register.Entry{}
	}
	return out, v.Commit(), err
}

func requirementList(root, framework string) error {
	p, err := openProgramme(root)
	if err != nil {
		return err
	}
	rows, head, err := requirementRows(p, framework)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"requirements": rows, "head": head}) {
		return nil
	}
	if len(rows) == 0 {
		fmt.Println("  no starter is installed; `quilzo requirement starters` lists them, and `install` takes one in")
		return nil
	}
	for _, e := range rows {
		q := e.Record.(register.Requirement)
		fmt.Printf("  %-10s %s%-14s%s %s\n", q.Framework, bold, q.Ref, reset, printable(q.Title))
	}
	return nil
}

func requirementShow(root, framework, ref string) error {
	p, err := openProgramme(root)
	if err != nil {
		return err
	}
	id, err := programme.RequirementID(framework, ref)
	if err != nil {
		return errMisused{err}
	}
	e, err := p.Reg.Get(id)
	if err != nil {
		return registerError(fmt.Errorf("%w: the programme holds no requirement %s of %s", register.ErrNotFound, clip(ref, 40), clip(framework, 40)))
	}
	v, err := headView(p)
	if err != nil {
		return err
	}
	var maps []register.Entry
	if err := v.Each(register.KindMapping, func(m register.Entry, _ map[string]any) error {
		mp := m.Record.(register.Mapping)
		if mp.From == id || mp.To == id {
			maps = append(maps, m)
		}
		return nil
	}); err != nil {
		return err
	}
	if maps == nil {
		maps = []register.Entry{}
	}
	if w.JSON(map[string]any{"requirement": e, "mappings": maps}) {
		return nil
	}
	q := e.Record.(register.Requirement)
	fmt.Printf("  %s%s %s%s\n  %s\n", bold, q.Framework, q.Ref, reset, printable(q.Title))
	for _, m := range maps {
		mp := m.Record.(register.Mapping)
		other := mp.To
		if other == id {
			other = mp.From
		}
		label := string(other)
		if o, err := v.Get(other); err == nil {
			label = register.Label(o.Record)
			if r, ok := o.Record.(register.Requirement); ok {
				label = r.Framework + " " + r.Ref
			}
		}
		words, _ := p.Keep.Words(mp.Rationale)
		fmt.Printf("    %s%s%s %s\n      %s%s%s\n", bold, mp.Relation, reset, printable(label), dim, printable(words), reset)
	}
	return nil
}

// requirementOps is the requirements on the agent interface: the starters
// and the requirements, read. Taking a starter in or out is a person's
// decision, made on the command line or by approving what waits.
func requirementOps(srv *mcp.Server, root string, caller *Caller) {
	may := programmeMay(root, caller)
	srv.Register(mcp.Operation{
		Name: "requirement_starters", NeedsRole: "reader", Area: register.Area,
		Summary: "the frameworks the security programme has starters for, and which are installed",
		Detail: "Each starter is a framework's requirements by the framework's own identifiers, each with a line in " +
			"Quilzo's own words; no standard's text is copied. Installing one is a person's decision.",
		Keywords: []string{"programme", "framework", "starter", "iso 27001", "nis2", "soc 2", "dora", "nist csf", "iso 42001"},
	}, func(map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		p, err := openProgramme(root)
		if err != nil {
			return nil, err
		}
		rows, head, err := starterRows(p)
		return map[string]any{"starters": rows, "head": head}, err
	})
	srv.Register(mcp.Operation{
		Name: "requirement_list", NeedsRole: "reader", Area: register.Area,
		Summary:  "the requirements of the installed starters, in each framework's own order",
		Args:     map[string]string{"framework": "optional, one framework's requirements, as requirement_starters names it"},
		Keywords: []string{"programme", "requirements", "framework", "clauses", "controls"},
	}, func(a map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		p, err := openProgramme(root)
		if err != nil {
			return nil, err
		}
		f, _ := a["framework"].(string)
		rows, head, err := requirementRows(p, f)
		return map[string]any{"requirements": rows, "head": head}, err
	})
}
