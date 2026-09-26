// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/entity"
)

// A group of companies, and the report a group-level dashboard cannot show.
//
// The structure is a file: one company per line, with its parent. Evidence
// carries the company it speaks for, and a control says whether every company
// performs it separately or whether one place operates it for everybody.
//
// The arithmetic that makes this worth having is one line in internal/entity:
// a control every company performs is exactly as covered as its worst
// company. A report showing the union of the evidence is green, and the
// subsidiary nobody connected is found by an auditor.

func entitiesPath(root string) string {
	return filepath.Join(assuranceDir(root), "entities.jsonl")
}

func reliancePath(root string) string {
	return filepath.Join(assuranceDir(root), "reliance.jsonl")
}

func cmdEntity(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"tree"}
	}
	switch args[0] {
	case "tree":
		return entityTree(root)
	case "report":
		return entityReport(root, args[1:])
	case "relies":
		return entityRelies(root, args[1:])
	default:
		return fmt.Errorf("unknown entity command %q; try tree, report or "+
			"relies", args[0])
	}
}

func loadTree(root string) (*entity.Tree, error) {
	t := entity.New()
	err := loadJSONL(entitiesPath(root), func(b []byte) error {
		var e entity.Entity
		if uerr := json.Unmarshal(b, &e); uerr != nil {
			return uerr
		}
		return t.Add(e)
	})
	if err != nil {
		return nil, err
	}
	if err := t.Close(); err != nil {
		return nil, err
	}
	return t, nil
}

func loadReliance(root string) ([]entity.Reliance, error) {
	var out []entity.Reliance
	err := loadJSONL(reliancePath(root), func(b []byte) error {
		var r entity.Reliance
		if uerr := json.Unmarshal(b, &r); uerr != nil {
			return uerr
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

func entityTree(root string) error {
	t, err := loadTree(root)
	if err != nil {
		return err
	}
	if w.JSON(t.All()) {
		return nil
	}
	if t.Len() == 0 {
		w.Human("no entities in %s\n", entitiesPath(root))
		w.Human("  %sone company per line, with its parent. Without this "+
			"every control is measured once against the whole "+
			"organisation%s\n", dim, reset)
		return nil
	}
	var walk func(id string, depth int)
	walk = func(id string, depth int) {
		e, _ := t.Get(id)
		pad := strings.Repeat("  ", depth)
		who := e.Owner
		colour := dim
		if strings.TrimSpace(who) == "" {
			who, colour = "nobody accountable", yellow
		}
		region := ""
		if e.Region != "" {
			region = "  " + e.Region
		}
		w.Human("%s%s%s%s%s%s  %s%s%s\n", pad, bold, e.ID, reset,
			dim, region, colour, who, reset)
		w.Human("%s  %s%s%s\n", pad, dim, e.Name, reset)
		for _, child := range t.Children(id) {
			walk(child, depth+1)
		}
	}
	walk(t.Root(), 0)
	w.Human("\n  %s%d compan(ies)%s\n", dim, t.Len(), reset)
	return nil
}

func entityReport(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	from := fs.String("from", "", "start of the period, as 2026-04-01")
	to := fs.String("to", "", "end of it; today by default")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	t, err := loadTree(root)
	if err != nil {
		return err
	}
	if t.Len() == 0 {
		return fmt.Errorf("no entities in %s", entitiesPath(root))
	}
	scope := t.Root()
	if len(pos) == 1 {
		scope = pos[0]
		if _, ok := t.Get(scope); !ok {
			return fmt.Errorf("there is no entity %q", scope)
		}
	}
	period, err := window(*from, *to)
	if err != nil {
		return err
	}
	controls, err := loadControls(root)
	if err != nil {
		return err
	}
	if len(controls) == 0 {
		return fmt.Errorf("no controls in %s", controlsPath(root))
	}
	evidence, err := loadEvidence(root)
	if err != nil {
		return err
	}
	relies, err := loadReliance(root)
	if err != nil {
		return err
	}

	g, divs := entity.Assess(t, scope, controls, evidence, relies, period)
	if w.JSON(map[string]any{"group": g, "controls": divs}) {
		return nil
	}

	w.Human("%s%s over %s%s\n", bold, t.Path(scope), period, reset)
	colour := green
	if g.Silent > 0 {
		colour = red
	} else if g.Uneven > 0 {
		colour = yellow
	}
	w.Human("%s%s%s\n", colour, g.Why(), reset)
	w.Human("  %s%d compan(ies), %d control(s), %d uneven, %d silent, %d "+
		"inherited without a record%s\n\n", dim, g.Companies, g.Controls,
		g.Uneven, g.Silent, g.Assumed, reset)

	for _, d := range divs {
		mark := green
		switch {
		case len(d.Silent) > 0:
			mark = red
		case !d.Even() || len(d.Assumed) > 0:
			mark = yellow
		}
		how := "one place, for everybody beneath"
		if d.PerEntity {
			how = "each company separately"
		}
		w.Human("%s%s%s  %s%s%s\n", bold, d.Control, reset, dim, how, reset)
		w.Human("  %s%s%s\n", mark, d.Why(), reset)
		if d.PerEntity {
			for _, e := range d.By {
				state := fmt.Sprintf("%.0f%%", e.Coverage.Share()*100)
				line := dim
				if e.Coverage.Observations == 0 {
					state, line = "nothing", red
				}
				via := ""
				if e.From != "" {
					via = "  via " + e.From
				}
				w.Human("    %s%-12s %s%s%s\n", dim, e.Entity, line,
					state+via, reset)
			}
		}
	}
	return nil
}

func entityRelies(root string, args []string) error {
	pos, flags := leadingArgs(args, 3)
	fs := flag.NewFlagSet("relies", flag.ContinueOnError)
	because := fs.String("because", "",
		"why the ancestor's control counts for this company's audit")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 3 {
		return fmt.Errorf(
			"usage: quilzo entity relies COMPANY ON CONTROL --because \"...\"")
	}
	t, err := loadTree(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	r := entity.Reliance{
		Entity: pos[0], On: pos[1], Control: pos[2],
		Because: strings.TrimSpace(*because), At: time.Now().UTC(),
		By: caller.Name, Kind: caller.Kind,
	}
	if err := r.Validate(t); err != nil {
		return err
	}
	controls, err := loadControls(root)
	if err != nil {
		return err
	}
	var known bool
	for _, c := range controls {
		if c.ID == r.Control {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("there is no control called %q", r.Control)
	}
	// Saying a subsidiary need not perform a control itself is a statement
	// its auditor will question: the same authority as publishing.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	if err := os.MkdirAll(assuranceDir(root), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(reliancePath(root),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	record(root, r.Record())

	if w.JSON(r) {
		return nil
	}
	w.Human("%s%s%s relies on %s%s%s for %s\n", bold, r.Entity, reset,
		bold, r.On, reset, r.Control)
	w.Human("  %s%s%s\n", dim, r.Because, reset)
	w.Human("  %srecorded, so the subsidiary's auditor has an answer rather "+
		"than an assumption%s\n", dim, reset)
	return nil
}
