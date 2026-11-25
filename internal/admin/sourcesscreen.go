// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/seckit"
	"github.com/quilzo/quilzo/internal/sources"
)

// The Sources screens: every source of the record and whether it is still
// reporting, with the stale ones named first and their age; one source,
// with what its last run said and the least its credential needs; adding a
// connector's or a pipeline's source; a credential kept in the vault; and a
// connector run now. The same as `quilzo source`, registered from this file
// (modules.go).
//
// Nothing here is a figure a model wrote: every line is code's, from the
// source's record, its seals and its last run.

func init() {
	registerScreens(screens{
		module: "sources",
		routes: []screenRoute{
			{path: "/sources", handle: (*Server).handleSources},
			{path: "/sources/item/", handle: (*Server).handleSource},
			{path: "/sources/add", handle: (*Server).handleSourceAdd},
			{path: "/sources/run", handle: (*Server).handleSourceRun},
			{path: "/sources/credential", handle: (*Server).handleSourceCredential},
		},
		nav: []navEntry{{
			destination: destination{Key: "sources", Label: "Sources", Path: "/sources", Group: "Assurance",
				Doc: "compliance", Needs: auth.ActView},
			icon: "sync", area: register.Area,
			also: []string{"connectors", "freshness", "stale", "entra", "microsoft graph", "github", "google workspace",
				"okta", "ci push", "pipeline", "recipes"},
		}},
	})
}

// reSourceName is a source's machine name, as the register holds it.
var reSourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

var (
	reportingBadge = seckit.MustBadge(seckit.Good, "Reporting")
	neverBadge     = seckit.MustBadge(seckit.Warn, "Never reported")
	failedBadge    = seckit.MustBadge(seckit.Bad, "Last run failed")
	ranBadge       = seckit.MustBadge(seckit.Good, "Last run read everything")
)

func (s *Server) sourcesReady(w http.ResponseWriter, r *http.Request, act auth.Action) (principal, *sources.Sources, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return p, nil, false
	}
	if !s.can(w, r, p, act, register.Area) {
		return p, nil, false
	}
	return p, sources.Open(register.Open(s.Store)), true
}

func sourceFreshness(st sources.Standing) seckit.Badge {
	switch {
	case st.Stale:
		return seckit.Stale
	case st.Last.IsZero():
		return neverBadge
	}
	return reportingBadge
}

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/sources" {
		http.NotFound(w, r)
		return
	}
	p, src, ok := s.sourcesReady(w, r, auth.ActView)
	if !ok {
		return
	}
	now := time.Now()
	all, err := src.Standings(now)
	if err != nil {
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusServiceUnavailable, "Title": "Sources",
			"Principal": p, "Heading": "The sources could not be read", "Body": err.Error()})
		return
	}
	var rows []seckit.Row
	var stale []string
	for _, st := range all {
		last := seckit.TextCell("Never")
		if !st.Last.IsZero() {
			last = seckit.TimeCell(st.Last)
		}
		title := st.Source.Title
		if title == "" {
			title = st.Source.Name
		}
		rows = append(rows, seckit.Row{Head: seckit.LinkCell("/sources/item/"+url.PathEscape(st.Source.Name), title),
			Cells: []seckit.Cell{seckit.TextCell(kindWords(st.Source)), seckit.BadgeCell(gradeBadge(st.Source.Grade)),
				seckit.BadgeCell(sourceFreshness(st)), last, seckit.TextCell("every " + seckit.Age(st.Window()))}})
		if st.Stale {
			stale = append(stale, st.Said)
		}
	}
	table, err := seckit.NewTable(fmt.Sprintf("Sources of the record, %d in all, %d stale", len(all), len(stale)),
		[]string{"Source", "How its facts arrive", "Grade", "Freshness", "Last reported", "Expected"}, rows)
	if err != nil {
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusInternalServerError, "Title": "Sources",
			"Principal": p, "Heading": "The sources could not be shown", "Body": err.Error()})
		return
	}
	data := map[string]any{"Title": "Sources", "Nav": "sources", "Principal": p,
		"Header": seckit.Header{Title: "Sources", Lead: "Where the record's facts come from, and whether each is still " +
			"reporting within the window it declares. A stale source is named here and on the Posture of record, and its " +
			"owner is told once each time it goes stale."},
		"Table": table, "Stale": stale, "StaleBadge": seckit.Stale, "Recipes": sources.Recipes(),
		"CanAdd": s.allows(p, auth.ActEditDraft, register.Area), "Said": sourceSaid(r.URL.Query().Get("said"))}
	if len(all) == 0 {
		data["Empty"] = seckit.Empty{Title: "No source has been added yet",
			Body: "A connector reads Entra, GitHub, Google Workspace or Okta; a pipeline pushes from GitHub Actions or " +
				"GitLab CI; a file brought in as evidence makes a source of its own.",
			Href: "/sources/add", Action: "Add a source"}
	}
	s.render(w, r, "sources.html", data)
}

// sourceSaid is what a redirect after an act says, from a closed list, so a
// link from anywhere else cannot make the screen say something.
func sourceSaid(key string) string {
	switch key {
	case "added":
		return "The source was added."
	case "kept":
		return "The credential is kept, sealed in the vault. It is never shown again."
	case "ran":
		return "The source ran. What it read is below."
	case "failed":
		return "The source ran and did not read everything, so nothing was written. Why is below."
	}
	return ""
}

func kindWords(src register.Source) string {
	switch src.Type {
	case "connector":
		return "A connector, read through the recipe " + src.Recipe
	case "ci":
		return "Pushed by the pipeline of " + src.Repository
	case "import":
		return "Imported from another tool's files"
	case "upload":
		return "Uploaded by a person"
	}
	return string(src.Type)
}

func (s *Server) handleSource(w http.ResponseWriter, r *http.Request) {
	p, src, ok := s.sourcesReady(w, r, auth.ActView)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/sources/item/")
	all, err := src.Standings(time.Now())
	if err != nil {
		http.Error(w, "the sources could not be read", http.StatusServiceUnavailable)
		return
	}
	var st *sources.Standing
	for i := range all {
		if all[i].Source.Name == name {
			st = &all[i]
		}
	}
	if st == nil {
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusNotFound, "Title": "Sources", "Principal": p,
			"Heading": "No source has that name", "Body": "The Sources screen lists every source."})
		return
	}
	data := map[string]any{"Title": st.Source.Name, "Nav": "sources", "Principal": p, "Standing": st,
		"Header": seckit.Header{Title: "Source " + st.Source.Name, Lead: st.Said}, "Freshness": sourceFreshness(*st),
		"Grade": gradeBadge(st.Source.Grade), "Kind": kindWords(st.Source), "Every": seckit.Age(st.Window()),
		"CanAct": s.allows(p, auth.ActEditDraft, register.Area), "Said": sourceSaid(r.URL.Query().Get("said")),
		"Owner": seckit.Short(string(st.Source.Owner))}
	if st.Source.Type == "connector" {
		if rc, ok := sources.RecipeNamed(st.Source.Recipe); ok {
			data["Recipe"] = rc
			params, _ := sources.ParseParams(st.Source.Params)
			if m, err := rc.Manifest(st.Source.Region, params); err == nil {
				kept, explained := src.Vault.Names(st.Source.Name), rc.Entry().Credentials
				var creds []credentialRow
				for _, c := range sources.Credentials(m) {
					creds = append(creds, credentialRow{Name: c, Kept: slices.Contains(kept, c), About: explained[c]})
				}
				data["Credentials"] = creds
			}
		}
		if a := st.Attempt; a != nil {
			badge := ranBadge
			if !a.OK {
				badge = failedBadge
			}
			data["Attempt"], data["AttemptBadge"] = a, badge
		}
	}
	s.render(w, r, "source.html", data)
}

// credentialRow is one credential a recipe needs, and whether the vault
// keeps it; never its value.
type credentialRow struct {
	Name  string
	Kept  bool
	About string
}

// sourceForm is what the add form was sent, kept to show again.
type sourceForm struct {
	Kind, Name, Title, Recipe, Region, Tenant, Org, Installation, Repository, Workflow, Owner, Hours string
}

func (s *Server) sourceAddData(p principal, f sourceForm, problems []seckit.Problem) map[string]any {
	byField := map[string]seckit.Problem{}
	for _, pr := range problems {
		byField[pr.Field] = pr
	}
	status := http.StatusOK
	if len(problems) > 0 {
		status = http.StatusUnprocessableEntity
	}
	return map[string]any{"Status": status, "Title": "Add a source", "Nav": "sources", "Principal": p,
		"Header": seckit.Header{Title: "Add a source", Lead: "A connector reads a tool through a reviewed recipe, at " +
			"the hosts the recipe names and no others; a pipeline pushes from one repository's one workflow."},
		"Form": f, "Recipes": sources.Recipes(), "Problems": problems, "ByField": byField}
}

func (s *Server) handleSourceAdd(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.sourcesReady(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		s.render(w, r, "source_add.html", s.sourceAddData(p, sourceForm{Kind: "connector", Hours: "24"}, nil))
		return
	}
	f := sourceForm{Kind: r.FormValue("kind"), Name: strings.TrimSpace(r.FormValue("name")),
		Title: strings.TrimSpace(r.FormValue("title")), Recipe: r.FormValue("recipe"), Region: strings.TrimSpace(r.FormValue("region")),
		Tenant: strings.TrimSpace(r.FormValue("tenant")), Org: strings.TrimSpace(r.FormValue("org")),
		Installation: strings.TrimSpace(r.FormValue("installation")), Repository: strings.TrimSpace(r.FormValue("repository")),
		Workflow: strings.TrimSpace(r.FormValue("workflow")), Owner: strings.TrimSpace(r.FormValue("owner")),
		Hours: strings.TrimSpace(r.FormValue("hours"))}
	var problems []seckit.Problem
	bad := func(field, label, msg string) {
		problems = append(problems, seckit.Problem{Field: field, Label: label, Message: msg})
	}
	if f.Kind != "connector" && f.Kind != "pipeline" {
		bad("source-kind-connector", "How its facts arrive", "choose a connector or a pipeline")
	}
	if !reSourceName.MatchString(f.Name) {
		bad("source-name", "Its name", "a lower-case machine name of letters, digits, dots, dashes and underscores")
	}
	hours, err := strconv.Atoi(f.Hours)
	if err != nil || hours < 1 || hours > 24*400 {
		bad("source-hours", "How often it reports", "a whole number of hours, from 1")
	}
	reg, by, err := s.registerWriter(p)
	if err != nil {
		bad("source-name", "Its name", "the register cannot be written: "+err.Error())
	}
	if f.Owner != "" && !strings.Contains(f.Owner, "@") {
		bad("source-owner", "Its owner", "the owner's mail address, which is where a stale source is told")
	}
	var src register.Source
	if len(problems) == 0 {
		var owner register.ID
		if f.Owner != "" {
			if owner, err = reg.SubjectFor(f.Owner, "person"); err != nil {
				bad("source-owner", "Its owner", err.Error())
			}
		}
		fresh := time.Duration(hours) * time.Hour
		if f.Kind == "connector" {
			params := map[string]string{"tenant": f.Tenant, "org": f.Org, "installation": f.Installation}
			src, err = sources.ConnectorSource(sources.Connector{Name: f.Name, Title: f.Title, Recipe: f.Recipe,
				Region: f.Region, Params: params, Fresh: fresh, Owner: owner})
			if err != nil {
				bad("source-recipe", "Its recipe", strings.TrimPrefix(err.Error(), register.ErrInvalid.Error()+": "))
			}
		} else {
			src, err = sources.PipelineSource(sources.Pipeline{Name: f.Name, Title: f.Title, Repository: f.Repository,
				Workflow: f.Workflow, Fresh: fresh, Owner: owner})
			if err != nil {
				field := "source-repository"
				if strings.Contains(err.Error(), "workflow") {
					field = "source-workflow"
				}
				bad(field, "The pipeline", strings.TrimPrefix(err.Error(), register.ErrInvalid.Error()+": "))
			}
		}
	}
	if len(problems) == 0 {
		if _, err := sources.Open(reg).Add(by, src); err != nil {
			bad("source-name", "Its name", err.Error())
		}
	}
	if len(problems) > 0 {
		s.render(w, r, "source_add.html", s.sourceAddData(p, f, problems))
		return
	}
	http.Redirect(w, r, "/sources/item/"+url.PathEscape(src.Name)+"?said=added", http.StatusSeeOther)
}

func (s *Server) handleSourceRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "a source is run with POST", http.StatusMethodNotAllowed)
		return
	}
	p, _, ok := s.sourcesReady(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	name := r.FormValue("name")
	if evidence.Recorder == nil {
		http.Error(w, "this server was started without its audit log wired to the register, so it runs no source: "+
			"use quilzo source run", http.StatusServiceUnavailable)
		return
	}
	reg := register.Open(s.Store)
	evidence.Recorder(reg)
	src := sources.Open(reg)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	rep, err := src.Run(ctx, name, func(act auth.Action, resource string) error {
		if !s.allows(p, act, resource) {
			return fmt.Errorf("%s may not %s on %s through this session", p.Name, act, resource)
		}
		return nil
	})
	if errors.Is(err, sources.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	outcome := "ran"
	if err != nil || !rep.OK {
		outcome = "failed"
	}
	http.Redirect(w, r, "/sources/item/"+url.PathEscape(name)+"?said="+outcome, http.StatusSeeOther)
}

func (s *Server) handleSourceCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "a credential is kept with POST", http.StatusMethodNotAllowed)
		return
	}
	p, src, ok := s.sourcesReady(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	name, cred, value := r.FormValue("name"), r.FormValue("credential"), r.FormValue("value")
	st, _, err := src.Source(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rc, ok := sources.RecipeNamed(st.Recipe)
	params, _ := sources.ParseParams(st.Params)
	m, merr := rc.Manifest(st.Region, params)
	if !ok || merr != nil || !slices.Contains(sources.Credentials(m), cred) {
		http.Error(w, "the recipe does not name that credential", http.StatusUnprocessableEntity)
		return
	}
	if err := src.Vault.Set(name, cred, value); err != nil {
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusUnprocessableEntity, "Title": "Sources",
			"Principal": p, "Heading": "The credential was not kept", "Body": err.Error()})
		return
	}
	s.audit("source.credential", register.Area, map[string]string{"by": p.Name, "source": name, "name": cred})
	http.Redirect(w, r, "/sources/item/"+url.PathEscape(name)+"?said=kept", http.StatusSeeOther)
}
