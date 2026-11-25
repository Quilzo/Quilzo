// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/seckit"
	"github.com/quilzo/quilzo/internal/sources"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// `quilzo source`: where the record's facts come from, and whether they are
// still coming. A connector's source runs a shipped recipe (Entra, GitHub,
// Google Workspace, Okta) with a credential from the vault; a pipeline's
// takes pushes from one repository's one workflow; each declares how often
// it reports, and a stale one is named and its owner told, once.

func init() {
	registerCLI(cliModule{
		module:  "sources",
		command: "source",
		heading: "security programme: sources (connectors, pipelines and how fresh each is)",
		help: "  quilzo source list                       every source, whether it is reporting within its window, stale first\n" +
			"  quilzo source show NAME                  one source, its hosts, its last run and the least its credential needs\n" +
			"  quilzo source stale                      the stale sources, each named with its age\n" +
			"  quilzo source recipes                    the recipes a connector runs, and how each was verified\n" +
			"  quilzo source add NAME --recipe RECIPE [--param NAME=VALUE]  add a connector's source, reaching the hosts its\n" +
			"                                            recipe names and no others; --region, --every 24h, --owner ADDRESS\n" +
			"  quilzo source add-pipeline NAME --repository OWNER/NAME --workflow PATH  add a pipeline's source, which takes\n" +
			"                                            pushes from that workflow alone; --every 168h, --owner ADDRESS\n" +
			"  quilzo source owner NAME ADDRESS         name who is told when the source is stale\n" +
			"  quilzo source credential NAME CREDENTIAL  keep a connector's credential, sealed in the vault, from standard input\n" +
			"  quilzo source run NAME                   run a connector's source now\n",
		run: cmdSource,
		needs: map[string]need{
			"source":              {action: auth.ActEditDraft, hint: "a line of source that is not named as a read may write"},
			"source list":         {action: auth.ActView},
			"source show":         {action: auth.ActView},
			"source stale":        {action: auth.ActView},
			"source recipes":      {action: auth.ActView},
			"source add":          {action: auth.ActEditDraft, hint: "a source is written to the register"},
			"source add-pipeline": {action: auth.ActEditDraft, hint: "a source is written to the register"},
			"source owner":        {action: auth.ActEditDraft, hint: "a source's owner is written to the register"},
			"source credential":   {action: auth.ActEditDraft, hint: "a connector's credential is kept beside the register"},
			"source run":          {action: auth.ActEditDraft, hint: "a connector's run writes facts to the register"},
		},
		area:   register.Area,
		reads:  [][]string{{"source", "list"}, {"source", "stale"}, {"source", "recipes"}},
		absent: []string{"source", "show", "nobody-by-this-name"},
		ops:    sourceOps,
		bare:   "list",
		jobs:   sourceJobs,
		notForRuns: "a source's facts are the compliance area's record, which a run reads under the data classes its " +
			"model route accepts, and those are not yet declared",
	})
}

func cmdSource(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	one := func(usage string, n int) ([]string, error) {
		pos, err := positionals(args[1:], n)
		if err != nil {
			return nil, err
		}
		if len(pos) != n {
			return nil, errMisused{fmt.Errorf("usage: %s", usage)}
		}
		return pos, nil
	}
	switch args[0] {
	case "list", "stale":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return sourceList(root, args[0] == "stale")
	case "show":
		pos, err := one("quilzo source show NAME", 1)
		if err != nil {
			return err
		}
		return sourceShow(root, pos[0])
	case "recipes":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return sourceRecipes()
	case "add":
		fs := flag.NewFlagSet("source add", flag.ContinueOnError)
		recipe := fs.String("recipe", "", "the recipe it runs: "+strings.Join(recipeNames(), ", "))
		region := fs.String("region", "", "the tool's region, when the recipe has more than one")
		every := fs.Duration("every", 0, "how often it should report (the recipe's own when not given)")
		owner := fs.String("owner", "", "the mail address of whoever is told when it is stale")
		title := fs.String("title", "", "what people call it")
		var params multiFlag
		fs.Var(&params, "param", "a value the recipe takes, NAME=VALUE: tenant, org, installation")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 1); err != nil {
			return err
		}
		if len(pos) != 1 || *recipe == "" {
			return errMisused{fmt.Errorf("usage: quilzo source add NAME --recipe RECIPE [--param NAME=VALUE]...; the recipes are %s",
				strings.Join(recipeNames(), ", "))}
		}
		ps, err := sources.ParseParams(params)
		if err != nil {
			return errMisused{err}
		}
		return sourceAdd(root, func(owner register.ID) (register.Source, error) {
			return sources.ConnectorSource(sources.Connector{Name: pos[0], Title: *title, Recipe: *recipe, Region: *region,
				Params: ps, Fresh: *every, Owner: owner})
		}, *owner)
	case "add-pipeline":
		fs := flag.NewFlagSet("source add-pipeline", flag.ContinueOnError)
		repo := fs.String("repository", "", "the repository whose pipeline pushes: owner/name, or a GitLab project's path")
		workflow := fs.String("workflow", "", "the path of the workflow's file: .github/workflows/evidence.yml, .gitlab-ci.yml")
		every := fs.Duration("every", 0, "how often it should push (a week when not given)")
		owner := fs.String("owner", "", "the mail address of whoever is told when it is stale")
		title := fs.String("title", "", "what people call it")
		var pos []string
		if err := parseFlags(fs, args[1:], &pos, 1); err != nil {
			return err
		}
		if len(pos) != 1 || *repo == "" || *workflow == "" {
			return errMisused{errors.New("usage: quilzo source add-pipeline NAME --repository OWNER/NAME --workflow PATH")}
		}
		return sourceAdd(root, func(owner register.ID) (register.Source, error) {
			return sources.PipelineSource(sources.Pipeline{Name: pos[0], Title: *title, Repository: *repo, Workflow: *workflow,
				Fresh: *every, Owner: owner})
		}, *owner)
	case "owner":
		pos, err := one("quilzo source owner NAME ADDRESS", 2)
		if err != nil {
			return err
		}
		return sourceOwner(root, pos[0], pos[1])
	case "credential":
		pos, err := one("quilzo source credential NAME CREDENTIAL   (the value from standard input, or QUILZO_SECRET_VALUE)", 2)
		if err != nil {
			return err
		}
		return sourceCredential(root, pos[0], pos[1])
	case "run":
		pos, err := one("quilzo source run NAME", 1)
		if err != nil {
			return err
		}
		return sourceRun(root, pos[0])
	}
	return errMisused{fmt.Errorf("unknown source command %q; try list, show, stale, recipes, add, add-pipeline, owner, "+
		"credential or run", clip(args[0], 40))}
}

func recipeNames() []string {
	var out []string
	for _, r := range sources.Recipes() {
		out = append(out, r.Name)
	}
	return out
}

// sourceError is a sources error as the command line's exits say it.
func sourceError(err error) error {
	if errors.Is(err, sources.ErrNotFound) {
		return errNotFound{err}
	}
	if errors.Is(err, sources.ErrEgress) {
		return errBlocked{err}
	}
	return registerError(err)
}

func openSources(root string) (*sources.Sources, error) {
	r, err := openRegister(root)
	if err != nil {
		return nil, err
	}
	return sources.Open(r), nil
}

func sourceList(root string, staleOnly bool) error {
	src, err := openSources(root)
	if err != nil {
		return err
	}
	all, err := src.Standings(time.Now())
	if err != nil {
		return err
	}
	var shown []sources.Standing
	for _, st := range all {
		if st.Stale || !staleOnly {
			shown = append(shown, st)
		}
	}
	if shown == nil {
		shown = []sources.Standing{}
	}
	if w.JSON(map[string]any{"sources": shown}) {
		return nil
	}
	if len(shown) == 0 {
		if staleOnly {
			fmt.Println("No source is stale.")
		} else {
			fmt.Println("No source has been added. quilzo source add NAME --recipe RECIPE, or quilzo source add-pipeline.")
		}
		return nil
	}
	for _, st := range shown {
		word := "reporting"
		switch {
		case st.Stale:
			word = yellow + "STALE" + reset
		case st.Last.IsZero():
			word = "not yet reported"
		}
		fmt.Printf("  %-24s %-10s %-9s %s\n", st.Source.Name, st.Source.Type, word, st.Said)
	}
	return nil
}

func sourceShow(root, name string) error {
	src, err := openSources(root)
	if err != nil {
		return err
	}
	all, err := src.Standings(time.Now())
	if err != nil {
		return err
	}
	for _, st := range all {
		if st.Source.Name != name {
			continue
		}
		out := map[string]any{"source": st}
		var rc *sources.Recipe
		if st.Source.Type == "connector" {
			rc, _ = sources.RecipeNamed(st.Source.Recipe)
			out["recipe"], out["credentials_kept"] = rc, src.Vault.Names(name)
		}
		if w.JSON(out) {
			return nil
		}
		fmt.Printf("%s: %s\n", st.Source.Name, st.Said)
		fmt.Printf("  type %s, graded %s, expected every %s\n", st.Source.Type, st.Source.Grade, seckit.Age(st.Window()))
		if len(st.Source.Hosts) > 0 {
			fmt.Printf("  reaches only %s\n", strings.Join(st.Source.Hosts, ", "))
		}
		if st.Source.Repository != "" {
			fmt.Printf("  takes pushes from %s, workflow %s\n", st.Source.Repository, st.Source.Workflow)
		}
		if rc != nil {
			fmt.Printf("  recipe %s (%s), %s\n", rc.Name, rc.Tool, rc.Verified)
			for _, p := range rc.Privilege {
				fmt.Printf("    %s\n", p)
			}
			fmt.Printf("  credentials kept in the vault: %s\n", orNoneWord(strings.Join(src.Vault.Names(name), ", ")))
		}
		if a := st.Attempt; a != nil {
			state := "read everything"
			if !a.OK {
				state = "failed: " + a.Problem
			}
			fmt.Printf("  last run %s: %s; %d fact(s), %d written\n", a.At.Format("2 Jan 2006 15:04 MST"), state, a.Facts, a.Written)
			for _, n := range a.Notes {
				fmt.Printf("    %s\n", n)
			}
		}
		return nil
	}
	return errNotFound{fmt.Errorf("no source called %q; quilzo source list names them", clip(name, 64))}
}

func orNoneWord(s string) string {
	if s == "" {
		return "none yet"
	}
	return s
}

func sourceRecipes() error {
	all := sources.Recipes()
	if w.JSON(map[string]any{"recipes": all}) {
		return nil
	}
	for _, r := range all {
		fmt.Printf("%s: %s\n  %s\n", r.Name, r.Tool, r.About)
		for _, p := range r.Privilege {
			fmt.Printf("  needs: %s\n", p)
		}
		fmt.Printf("  %s\n\n", r.Verified)
	}
	return nil
}

func sourceAdd(root string, make func(owner register.ID) (register.Source, error), owner string) error {
	caller := resolveCaller(root, flagToken)
	r, by, err := registerWriter(root, caller)
	if err != nil {
		return err
	}
	var who register.ID
	if owner != "" {
		if !strings.Contains(owner, "@") {
			return errMisused{errors.New("--owner is the mail address of whoever is told when the source is stale")}
		}
		if who, err = r.SubjectFor(owner, "person"); err != nil {
			return err
		}
	}
	src, err := make(who)
	if err != nil {
		return errMisused{err}
	}
	rc, err := sources.Open(r).Add(by, src)
	if err != nil {
		return sourceError(err)
	}
	return sayWritten(map[string]any{"source": src, "receipt": rc}, "the source "+src.Name, rc)
}

func sourceOwner(root, name, owner string) error {
	if !strings.Contains(owner, "@") {
		return errMisused{errors.New("the owner is the mail address of whoever is told when the source is stale")}
	}
	caller := resolveCaller(root, flagToken)
	r, by, err := registerWriter(root, caller)
	if err != nil {
		return err
	}
	all := sources.Open(r)
	src, _, err := all.Source(name)
	if err != nil {
		return sourceError(err)
	}
	if src.Owner, err = r.SubjectFor(owner, "person"); err != nil {
		return err
	}
	rc, err := r.Put(by, "the owner of source "+name+" named", src)
	if err != nil {
		return sourceError(err)
	}
	return sayWritten(map[string]any{"source": src, "receipt": rc}, "the owner of "+name, rc)
}

func sourceCredential(root, name, credential string) error {
	src, err := openSources(root)
	if err != nil {
		return err
	}
	st, _, err := src.Source(name)
	if err != nil {
		return sourceError(err)
	}
	rc, ok := sources.RecipeNamed(st.Recipe)
	if !ok {
		return errMisused{fmt.Errorf("%s is not a connector's source, and keeps no credential", name)}
	}
	params, _ := sources.ParseParams(st.Params)
	m, err := rc.Manifest(st.Region, params)
	if err != nil {
		return err
	}
	if !slices.Contains(sources.Credentials(m), credential) {
		return errMisused{fmt.Errorf("the recipe %s names the credentials %s, not %q", rc.Name,
			strings.Join(sources.Credentials(m), " and "), clip(credential, 64))}
	}
	value, err := secretValue()
	if err != nil {
		return err
	}
	if err := src.Vault.Set(name, credential, value); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	record(root, caller.auditRecord("source.credential", register.Area, audit.Success,
		map[string]string{"source": name, "name": credential}))
	fmt.Printf("%s of %s is kept, sealed in the vault. It is never shown again; keep it again to change it.\n", credential, name)
	return nil
}

func sourceRun(root, name string) error {
	caller := resolveCaller(root, flagToken)
	r, _, err := registerWriter(root, caller)
	if err != nil {
		return err
	}
	src := sources.Open(r)
	rep, err := src.Run(context.Background(), name, func(act auth.Action, resource string) error {
		return authorise(root, caller, act, resource)
	})
	if w.JSON(rep) {
		if err != nil {
			return sourceError(err)
		}
		return nil
	}
	if err != nil {
		return sourceError(err)
	}
	fmt.Printf("%s read %d fact(s), %d new or changed, in %d request(s); the run is sealed as %s.\n", name, rep.Facts,
		rep.Written, rep.Requests, rep.Raw)
	for _, n := range rep.Notes {
		fmt.Printf("  %s\n", n)
	}
	return nil
}

// sourceJobs is the sources' work on the server's upkeep timer: each
// connector's source run when half its window has passed since it last
// ran, and each stale source's owner told, once.
func sourceJobs(root string) []upkeep.Job {
	return []upkeep.Job{
		{Name: "source runs", Do: func(now time.Time) (int, error) { return runDueSources(root, now) }},
		{Name: "stale sources", Do: func(now time.Time) (int, error) {
			src, err := timedSources(root, now)
			if err != nil || src == nil {
				return 0, err
			}
			alerts := &sources.Alerts{Sources: src,
				Mail: func(to, subject, body string) error {
					m, err := loadMailer(root)
					if err != nil {
						return err
					}
					if m == nil {
						return errors.New("no mail relay is set up (mail.json)")
					}
					return m.Send(to, subject, body)
				},
				Audit: func(rec audit.Record) error { return recordE(root, rec) }}
			return alerts.Tick(now)
		}},
	}
}

// timedSources is the sources of the store at root on the upkeep loop's
// clock, wired to record what they write; nil when the store holds no
// register yet.
func timedSources(root string, now time.Time) (*sources.Sources, error) {
	s, err := open(root)
	if err != nil {
		return nil, err
	}
	r := register.Open(s)
	if r.Head() == "" {
		return nil, nil
	}
	r.Audit = func(rec audit.Record) error { return recordE(root, rec) }
	r.Ready = func() error { return auditReady(root) }
	r.Now = func() time.Time { return now }
	src := sources.Open(r)
	src.Now = func() time.Time { return now }
	return src, nil
}

// runDueSources runs each connector's source whose last run is older than
// half its window, so one failed run still leaves time for another before
// it is stale. The server's own timer writes as the collector, which may
// write facts and nothing else.
func runDueSources(root string, now time.Time) (int, error) {
	src, err := timedSources(root, now)
	if err != nil || src == nil {
		return 0, err
	}
	all, err := src.Standings(now)
	if err != nil {
		return 0, err
	}
	ran := 0
	var problems []string
	for _, st := range all {
		if st.Source.Type != "connector" {
			continue
		}
		last := st.Last
		if st.Attempt != nil && st.Attempt.At.After(last) {
			last = st.Attempt.At
		}
		if !last.IsZero() && now.Sub(last) < st.Window()/2 {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		_, err := src.Run(ctx, st.Source.Name, nil)
		cancel()
		ran++
		if err != nil {
			problems = append(problems, st.Source.Name+": "+err.Error())
		}
	}
	if len(problems) > 0 {
		return ran, fmt.Errorf("%d source run(s) did not read everything: %s", len(problems), strings.Join(problems, "; "))
	}
	return ran, nil
}

// sourceOps is the sources on the agent interface: every source and how
// fresh it is, one source, the stale ones and the recipes, read. A run,
// adding a source and keeping a credential are a person's, on the command
// line or the Sources screen.
func sourceOps(srv *mcp.Server, root string, caller *Caller) {
	may := func() error { return registerMayRead(root, caller) }
	list := func(stale bool) func(map[string]any) (any, error) {
		return func(map[string]any) (any, error) {
			if err := may(); err != nil {
				return nil, err
			}
			src, err := openSources(root)
			if err != nil {
				return nil, err
			}
			all, err := src.Standings(time.Now())
			var out []sources.Standing
			for _, st := range all {
				if st.Stale || !stale {
					out = append(out, st)
				}
			}
			return map[string]any{"sources": out}, err
		}
	}
	srv.Register(mcp.Operation{
		Name: "source_list", NeedsRole: "reader", Area: register.Area,
		Summary:  "every source of the record, whether it is reporting within the window it declares, stale first",
		Keywords: []string{"sources", "connectors", "freshness", "stale", "pipelines"},
	}, list(false))
	srv.Register(mcp.Operation{
		Name: "source_stale", NeedsRole: "reader", Area: register.Area,
		Summary:  "the stale sources, each named in a line code writes with when it last reported",
		Keywords: []string{"sources", "stale", "freshness", "silent failure"},
	}, list(true))
	srv.Register(mcp.Operation{
		Name: "source_show", NeedsRole: "reader", Area: register.Area,
		Summary:  "one source: its hosts, its last run and how fresh it is",
		Args:     map[string]string{"name": "the source's machine name"},
		Keywords: []string{"source", "connector", "run", "freshness"},
	}, func(a map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		name, _ := a["name"].(string)
		src, err := openSources(root)
		if err != nil {
			return nil, err
		}
		all, err := src.Standings(time.Now())
		if err != nil {
			return nil, err
		}
		for _, st := range all {
			if st.Source.Name == name {
				return map[string]any{"source": st}, nil
			}
		}
		return nil, &mcp.ArgumentError{Reason: "no source has that name; source_list names them"}
	})
	srv.Register(mcp.Operation{
		Name: "source_recipes", NeedsRole: "reader", Area: register.Area,
		Summary:  "the recipes a connector runs, the least privilege each needs and how each was verified",
		Keywords: []string{"recipes", "entra", "github", "google workspace", "okta", "least privilege"},
	}, func(map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		return map[string]any{"recipes": sources.Recipes()}, nil
	})
}
