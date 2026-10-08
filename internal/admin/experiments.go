// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/experiment"
)

// A/B tests on a screen: what is running, what can be concluded, and a form
// to set one up. Starting one is a publish, because it changes what visitors
// see.

// Experiments is the site's tests, supplied by whatever wired this server.
type Experiments struct {
	Load func() (*experiment.Set, error)
	Save func(s *experiment.Set, by, change, name string) error
	Days func(n int) ([]analytics.Day, error)
}

func (s *Server) handleExperiments(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	data := map[string]any{"Nav": "experiments", "Title": "Experiments", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanSave":   s.mayUse(p, auth.ActPublish, "/") && !p.Limits.ReadOnly,
		"MinSample": experiment.MinSample}
	if s.Experiments == nil || s.Experiments.Load == nil {
		data["Unavailable"] = "This build was started without experiments."
		s.render(w, r, "experiments.html", data)
		return
	}
	set, err := s.Experiments.Load()
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "experiments.html", data)
		return
	}
	var days []analytics.Day
	if s.Experiments.Days != nil {
		days, _ = s.Experiments.Days(90)
	}
	var reports []experiment.Report
	for _, e := range set.Experiments {
		reports = append(reports, experiment.Measure(e, days))
	}
	data["Reports"] = reports
	s.render(w, r, "experiments.html", data)
}

func (s *Server) handleExperimentChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "takes a POST", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if s.Experiments == nil || s.Experiments.Load == nil || s.Experiments.Save == nil {
		http.Error(w, "this build cannot change experiments", http.StatusServiceUnavailable)
		return
	}
	back := func(k, msg string) {
		http.Redirect(w, r, "/experiments?"+k+"="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	set, err := s.Experiments.Load()
	if err != nil {
		back("e", err.Error())
		return
	}
	op, name := r.FormValue("op"), strings.TrimSpace(r.FormValue("name"))
	switch op {
	case "add":
		page := strings.Trim(strings.TrimSpace(r.FormValue("page")), "/")
		variant := strings.Trim(strings.TrimSpace(r.FormValue("variant")), "/")
		// Publish on both pages: the experiment serves the variant's content
		// at the tested page's address. Checked per page, so a grant scoped
		// to /pricing covers a test on it and a deny on a path binds.
		if !s.canPage(w, r, p, auth.ActPublish, page) ||
			!s.canPage(w, r, p, auth.ActPublish, variant) {
			return
		}
		weight, _ := strconv.Atoi(r.FormValue("weight"))
		if weight <= 0 || weight >= 100 {
			weight = 50
		}
		err = set.Put(experiment.Experiment{Name: name, Page: page,
			Goal: strings.TrimSpace(r.FormValue("goal")),
			Variants: []experiment.Variant{{Name: "control", Page: page, Weight: 100 - weight},
				{Name: "variant", Page: variant, Weight: weight}}})
	case "start", "stop":
		e, found := set.Get(name)
		if !found {
			back("e", "there is no experiment called "+name)
			return
		}
		if !s.mayChangeExperiment(w, r, p, e) {
			return
		}
		e.Running = op == "start"
		err = set.Put(e)
	case "remove":
		if e, found := set.Get(name); found && !s.mayChangeExperiment(w, r, p, e) {
			return
		}
		if !set.Remove(name) {
			back("e", "there is no experiment called "+name)
			return
		}
	default:
		back("e", "that is not a change this screen makes")
		return
	}
	if err == nil {
		err = s.Experiments.Save(set, p.Name, op, name)
	}
	if err != nil {
		back("e", err.Error())
		return
	}
	back("m", "Saved.")
}

// mayChangeExperiment checks publish on every page an experiment touches.
func (s *Server) mayChangeExperiment(w http.ResponseWriter, r *http.Request,
	p principal, e experiment.Experiment) bool {

	for _, v := range e.Variants {
		if !s.canPage(w, r, p, auth.ActPublish, v.Page) {
			return false
		}
	}
	return true
}
