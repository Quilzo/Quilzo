// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/programme"
	"github.com/quilzo/quilzo/internal/register"
)

// `quilzo population`: the N of every "n of N". A population says which
// source its members are read from and the typed query that selects them,
// is compared with a second source where there is one, and keeps the
// disagreement as a number of its own. Links join two sources' records on
// an identifier both report exactly.

func init() {
	registerCLI(cliModule{
		module:  "population",
		command: "population",
		heading: "security programme: populations and links (every denominator with its source and a cross-check)",
		help: "  quilzo population list                   the populations, each with its count, its cross-check and its labels\n" +
			"  quilzo population define NAME --source S --query FILE  define one: its source and the query that selects it\n" +
			"                                           [--fresh 24h] [--independent] [--title T] [--cross-check S --cross-query FILE]\n" +
			"  quilzo population count NAME             count a population now, and its cross-check, and record both\n" +
			"  quilzo population show NAME              one population as last counted, with what disagrees\n" +
			"  quilzo population link --on ON --a SOURCE[:FACT] --b SOURCE[:FACT]  link two sources on an exact identifier\n",
		run: cmdPopulation,
		needs: map[string]need{
			"population":        {action: auth.ActView},
			"population define": {action: auth.ActEditDraft},
			"population count":  {action: auth.ActEditDraft},
			"population link":   {action: auth.ActEditDraft},
		},
		area:   register.Area,
		reads:  [][]string{{"population", "list"}},
		absent: []string{"population", "show", "nobody"},
		ops:    populationOps,
		notForRuns: "the populations count the compliance area's records, which a run reads under the data classes its " +
			"model route accepts, and those are not yet declared",
	})
}

func cmdPopulation(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return populationList(root)
	case "define":
		fs := flag.NewFlagSet("population define", flag.ContinueOnError)
		src := fs.String("source", "", "the source its members are read from, by its machine name")
		query := fs.String("query", "", "a file holding the typed query that selects its members")
		fresh := flagDuration(fs, "fresh", 24*time.Hour, "how old a count may be before it is stale")
		independent := fs.Bool("independent", false, "the source is not the tool the population is used to measure")
		title := fs.String("title", "", "what people call it")
		cross := fs.String("cross-check", "", "a second source the count is compared with")
		crossQuery := fs.String("cross-query", "", "a file holding the typed query that selects what the second source knows of")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 1); err != nil {
			return err
		}
		if len(pos) != 1 || *src == "" || *query == "" || (*cross == "") != (*crossQuery == "") {
			return errMisused{fmt.Errorf("usage: quilzo population define NAME --source S --query FILE [--fresh 24h] " +
				"[--independent] [--title T] [--cross-check S --cross-query FILE]; a cross-check names its query too")}
		}
		q, err := readQuery(*query)
		if err != nil {
			return err
		}
		d := programme.Definition{Name: pos[0], Title: *title, Source: *src, Query: q, Fresh: *fresh,
			Independent: *independent, CrossCheck: *cross}
		if *cross != "" {
			cq, err := readQuery(*crossQuery)
			if err != nil {
				return err
			}
			d.CrossQuery = &cq
		}
		p, by, err := programmeWriter(root, resolveCaller(root, flagToken))
		if err != nil {
			return err
		}
		id, rc, err := p.Define(by, d)
		if err != nil {
			return programmeError(err)
		}
		return sayWritten(map[string]any{"population": id, "receipt": rc}, "the population "+pos[0], rc)
	case "count":
		pos, err := positionals(args[1:], 1)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo population count NAME")}
		}
		id, err := register.DeriveID(register.KindPopulation, register.Local, pos[0])
		if err != nil {
			return errMisused{err}
		}
		p, by, err := programmeWriter(root, resolveCaller(root, flagToken))
		if err != nil {
			return err
		}
		c, rc, err := p.Recount(by, id)
		if err != nil {
			return programmeError(err)
		}
		if w.JSON(map[string]any{"count": c, "unexplained": c.Unexplained(), "receipt": rc}) {
			return nil
		}
		sayCount(c)
		return nil
	case "show":
		pos, err := positionals(args[1:], 1)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo population show NAME")}
		}
		p, err := openProgramme(root)
		if err != nil {
			return err
		}
		c, err := populationCount(p, pos[0])
		if err != nil {
			return registerError(err)
		}
		if w.JSON(map[string]any{"count": c, "unexplained": c.Unexplained()}) {
			return nil
		}
		sayCount(c)
		return nil
	case "link":
		fs := flag.NewFlagSet("population link", flag.ContinueOnError)
		on := fs.String("on", "", "the identifier: "+strings.Join(register.LinkOn("").Values(), ", "))
		a := fs.String("a", "", "one side: a source's machine name, and :FACT for an observation's value rather than an asset's reference")
		b := fs.String("b", "", "the other side, the same way")
		if err := parseFlags(fs, args[1:], nil, 0); err != nil {
			return err
		}
		if *on == "" || *a == "" || *b == "" {
			return errMisused{fmt.Errorf("usage: quilzo population link --on ON --a SOURCE[:FACT] --b SOURCE[:FACT]; ON is one of %s",
				strings.Join(register.LinkOn("").Values(), ", "))}
		}
		left, err := sideOf(*a)
		if err != nil {
			return err
		}
		right, err := sideOf(*b)
		if err != nil {
			return err
		}
		p, by, err := programmeWriter(root, resolveCaller(root, flagToken))
		if err != nil {
			return err
		}
		c, rc, err := p.Link(by, register.LinkOn(*on), left, right)
		if err != nil {
			return programmeError(err)
		}
		if w.JSON(map[string]any{"links": len(c.Links), "ambiguous": c.Ambiguous, "receipt": rc}) {
			return nil
		}
		fmt.Printf("  %s on %s, each an exact match; %s shared by two records of one source linked nothing\n",
			count(len(c.Links), "link"), *on, count(c.Ambiguous, "identifier"))
		return nil
	default:
		return errMisused{fmt.Errorf("unknown population command %q; try list, define, count, show or link", args[0])}
	}
}

// readQuery reads a typed query from a file, refusing a field a query does
// not have.
func readQuery(path string) (register.Query, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return register.Query{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var q programme.DraftQuery
	if err := dec.Decode(&q); err != nil {
		return register.Query{}, errMisused{fmt.Errorf("%s is not a typed query: %v", path, err)}
	}
	return register.Query{Of: q.Of, Member: q.Member, Terms: q.Terms}, nil
}

// sideOf is a side of a link as the command line names it: SOURCE, or
// SOURCE:FACT.
func sideOf(s string) (programme.Side, error) {
	name, fact, _ := strings.Cut(s, ":")
	id, err := register.DeriveID(register.KindSource, register.Local, name)
	if err != nil || name == "" {
		return programme.Side{}, errMisused{fmt.Errorf("%q does not name a source", clip(s, 40))}
	}
	return programme.Side{Source: id, Fact: fact}, nil
}

// populationCount is a population as it was last counted, labelled as of
// now, without counting it again.
func populationCount(p *programme.Programme, name string) (programme.Count, error) {
	v, err := headView(p)
	if err != nil {
		return programme.Count{}, err
	}
	id, err := register.DeriveID(register.KindPopulation, register.Local, name)
	if err != nil {
		return programme.Count{}, fmt.Errorf("%w: name the population", register.ErrNotFound)
	}
	c, err := programme.CountAt(v, id, time.Now())
	if err != nil {
		return programme.Count{}, err
	}
	return c, nil
}

func sayCount(c programme.Count) {
	fmt.Printf("  %s%s%s: %s\n", bold, c.Population.Name, reset, programme.Disagreement(c))
	for _, l := range c.Labels {
		fmt.Printf("    %s%s%s\n", dim, l, reset)
	}
}

// populationRows is every population as last recorded, with its labels.
type populationRow struct {
	register.Entry
	Labels []programme.Label `json:"labels"`
}

func populationRows(p *programme.Programme) ([]populationRow, string, error) {
	v, err := headView(p)
	if err != nil {
		return nil, "", err
	}
	out := []populationRow{}
	now := time.Now()
	err = v.Each(register.KindPopulation, func(e register.Entry, _ map[string]any) error {
		out = append(out, populationRow{Entry: e, Labels: programme.Labels(e.Record.(register.Population), now)})
		return nil
	})
	return out, v.Commit(), err
}

func populationList(root string) error {
	p, err := openProgramme(root)
	if err != nil {
		return err
	}
	rows, head, err := populationRows(p)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"populations": rows, "head": head}) {
		return nil
	}
	if len(rows) == 0 {
		fmt.Println("  no population yet; `quilzo population define NAME --source S --query FILE` defines one")
		return nil
	}
	for _, r := range rows {
		pop := r.Record.(register.Population)
		counted := "never counted"
		if pop.Counted != 0 {
			counted = fmt.Sprintf("%d, counted %s", pop.Size, pop.Counted.At().Format("2 Jan 2006 15:04 UTC"))
			if pop.CrossCheck != "" {
				counted += fmt.Sprintf("; cross-check %d, %d unexplained", pop.CrossSize, pop.Unexplained)
			}
		}
		fmt.Printf("  %s%-20s%s %s\n", bold, pop.Name, reset, counted)
		for _, l := range r.Labels {
			fmt.Printf("    %s%s%s\n", dim, l, reset)
		}
	}
	return nil
}

// populationOps is the populations on the agent interface, read.
func populationOps(srv *mcp.Server, root string, caller *Caller) {
	may := programmeMay(root, caller)
	srv.Register(mcp.Operation{
		Name: "population_list", NeedsRole: "reader", Area: register.Area,
		Summary:  "the populations every coverage figure is counted against, each with its source, its cross-check and its labels",
		Keywords: []string{"programme", "population", "denominator", "coverage", "cross-check"},
	}, func(map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		p, err := openProgramme(root)
		if err != nil {
			return nil, err
		}
		rows, head, err := populationRows(p)
		return map[string]any{"populations": rows, "head": head}, err
	})
	srv.Register(mcp.Operation{
		Name: "population_show", NeedsRole: "reader", Area: register.Area,
		Summary:  "one population counted at the register's head: its members, the cross-check's, and the disagreement as its own number",
		Args:     map[string]string{"name": "the population's machine name, as population_list names it"},
		Keywords: []string{"programme", "population", "disagreement", "unexplained", "cross-check"},
	}, func(a map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		name, _ := a["name"].(string)
		if name == "" {
			return nil, &mcp.ArgumentError{Reason: "population_show needs arguments.name, as population_list names it"}
		}
		p, err := openProgramme(root)
		if err != nil {
			return nil, err
		}
		c, err := populationCount(p, name)
		if err != nil {
			return nil, opError(err)
		}
		return map[string]any{"count": c, "unexplained": c.Unexplained(), "said": programme.Disagreement(c)}, nil
	})
}
