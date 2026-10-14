// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/research"
)

// Research projects, for an agent. An agent can find and cite works, run
// a project's code and pin the numbers it wrote, and draft the report; it
// cannot register or amend a plan, which is the researchers' commitment,
// and it cannot put a number in a report except by naming a claim, since
// every number it writes in the prose is flagged.

func registerResearchOps(srv *mcp.Server, root string, caller *Caller) {
	refuse := func(err error) (any, error) { return nil, &mcp.Refusal{Reason: err.Error()} }
	str := func(a map[string]any, k string) string { v, _ := a[k].(string); return strings.TrimSpace(v) }
	asJSON := func(v any) (any, error) {
		b, err := json.Marshal(v)
		return string(b), err
	}

	srv.Register(mcp.Operation{
		Name: "research_projects", NeedsRole: "reader",
		Summary:  "the research projects here: each question, whether its plan is registered, its claims and sources",
		Keywords: []string{"research", "science", "study", "project", "analysis"},
	}, func(map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActView, "/"); err != nil {
			return refuse(err)
		}
		all, err := researchStore(root).List()
		if err != nil {
			return nil, err
		}
		type row struct {
			Name       string `json:"name"`
			Question   string `json:"question"`
			Registered bool   `json:"plan_registered"`
			Claims     int    `json:"claims"`
			Sources    int    `json:"sources"`
		}
		out := []row{}
		for _, p := range all {
			out = append(out, row{p.Name, p.Question, p.Registered(), len(p.Claims), len(p.Sources)})
		}
		return asJSON(out)
	})

	srv.Register(mcp.Operation{
		Name: "research_project", NeedsRole: "reader",
		Summary: "one research project: its plan, computations, claims, sources, the report rendered, and what its check found",
		Detail: "The report says {{name}} where a claim's number goes and [@key] where a source is cited. " +
			"A problem in the check is something to fix before the report is final.",
		Args:     map[string]string{"name": "the project"},
		Keywords: []string{"research", "report", "claims", "citations", "provenance", "reproducibility"},
	}, func(a map[string]any) (any, error) {
		p, fs, err := researchCheck(root, str(a, "name"), caller)
		if err != nil {
			return refuse(err)
		}
		runs, _ := researchStore(root).Runs(p.Name)
		if len(runs) > 20 {
			runs = runs[:20]
		}
		for i := range runs {
			runs[i].Log = clampString(runs[i].Log, 2000)
		}
		type finding struct {
			Problem bool   `json:"problem"`
			Line    int    `json:"line,omitempty"`
			What    string `json:"what"`
		}
		var found []finding
		for _, f := range fs {
			found = append(found, finding{f.Problem, f.Line, f.What})
		}
		return asJSON(map[string]any{"project": p, "computations": runs, "check": found,
			"rendered": research.Markdown(p, runs)})
	})

	srv.Register(mcp.Operation{
		Name: "research_search", NeedsRole: "reader",
		Summary: "find works in OpenAlex by words; adds nothing",
		Detail: "Cite one with research_cite by the identifier given here, never by a title " +
			"remembered: a citation is kept only for a work an index returns.",
		Args:     map[string]string{"query": "the words", "limit": "optional, at most 25"},
		Keywords: []string{"literature", "papers", "search", "openalex", "pubmed", "arxiv", "citations"},
	}, func(a map[string]any) (any, error) {
		n := 10
		if f, ok := a["limit"].(float64); ok {
			n = int(f)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		found, err := researchSearch(ctx, root, str(a, "query"), n, caller)
		if err != nil {
			return refuse(err)
		}
		return asJSON(found)
	})

	srv.Register(mcp.Operation{
		Name: "research_cite", NeedsRole: "author", Writes: true,
		Summary: "add a work to a project's sources, only if an open index has it",
		Detail: "By its identifier: doi:…, pmid:…, arxiv:… or an OpenAlex W…. An identifier no " +
			"index has is refused, so a citation cannot be invented. The report cites it as [@key].",
		Args:     map[string]string{"name": "the project", "id": "the work's identifier", "key": "optional citation key"},
		Keywords: []string{"cite", "citation", "reference", "doi", "literature"},
	}, func(a map[string]any) (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		src, err := researchCite(ctx, root, str(a, "name"), str(a, "id"), str(a, "key"), caller)
		if err != nil {
			return refuse(err)
		}
		return asJSON(src)
	})

	srv.Register(mcp.Operation{
		Name: "research_run", NeedsRole: "author", Writes: true,
		Summary: "run a project's script (Python, R or Julia) in a box with no network, and keep what it wrote",
		Detail: "The script reads the inputs named and writes the numbers it found to values.json, as " +
			`{"name": 0.42} or {"name": {"value": 0.42, "unit": "%"}}. Those are the only numbers a ` +
			"report may state; pin them with research_claim.",
		Args: map[string]string{"name": "the project", "script": "its path in the project",
			"inputs": "optional comma-separated paths of the files it reads"},
		Keywords: []string{"compute", "analysis", "python", "statistics", "reproducible", "run"},
	}, func(a map[string]any) (any, error) {
		var inputs []string
		for _, in := range strings.Split(str(a, "inputs"), ",") {
			if in = strings.TrimSpace(in); in != "" {
				inputs = append(inputs, in)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), researchTimeout+time.Minute)
		defer cancel()
		r, err := researchRunScript(ctx, root, str(a, "name"), str(a, "script"), inputs, "", caller)
		if err != nil {
			return refuse(err)
		}
		r.Log = clampString(r.Log, 4000)
		return asJSON(r)
	})

	srv.Register(mcp.Operation{
		Name: "research_claim", NeedsRole: "author", Writes: true,
		Summary: "pin numbers a computation wrote down as claims a report may state as {{name}}",
		Args: map[string]string{"name": "the project", "run": "the computation",
			"values": "optional comma-separated value names; every one it wrote when empty"},
		Keywords: []string{"claim", "result", "number", "finding"},
	}, func(a map[string]any) (any, error) {
		var values []string
		for _, v := range strings.Split(str(a, "values"), ",") {
			if v = strings.TrimSpace(v); v != "" {
				values = append(values, v)
			}
		}
		claims, err := researchClaim(root, str(a, "name"), str(a, "run"), values, caller)
		if err != nil {
			return refuse(err)
		}
		return asJSON(claims)
	})

	srv.Register(mcp.Operation{
		Name: "research_write", NeedsRole: "author", Writes: true,
		Summary: "write a project's report draft; answers with what its check finds",
		Detail: "Markdown. A number goes in as {{claim}}, a number from the design as {{= 120}}, a " +
			"citation as [@key]. Any other number is flagged, and a sentence citing a work must be " +
			"supported by its abstract or a quoted passage.",
		Args:     map[string]string{"name": "the project", "report": "the whole report"},
		Keywords: []string{"report", "write", "draft", "paper", "manuscript"},
	}, func(a map[string]any) (any, error) {
		report, _ := a["report"].(string)
		fs, err := researchWrite(root, str(a, "name"), report, caller)
		if err != nil {
			return refuse(err)
		}
		var lines []string
		for _, f := range fs {
			if f.Problem {
				lines = append(lines, f.What)
			}
		}
		if len(lines) == 0 {
			return "kept; every number is linked and every citation supports its sentence", nil
		}
		return "kept, with these problems:\n" + strings.Join(lines, "\n"), nil
	})
}
