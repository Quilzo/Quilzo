// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/personalise"
)

// Personalisation rules on a screen, with a simulator: describe a visitor
// and see which rule, if any, they would get. See internal/personalise.

// Personalise is the site's rules, supplied by whatever wired this server.
type Personalise struct {
	Load     func() (*personalise.Set, error)
	Save     func(s *personalise.Set, by, change, name string) error
	Simulate func(campaign, referrer, lang, device, at string) (*http.Request, time.Time, error)
}

var ruleFields = []string{"campaign", "referrer", "language", "device", "weekday", "hour", "param"}

func (s *Server) handlePersonalise(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	q := r.URL.Query()
	data := map[string]any{"Nav": "personalise", "Title": "Personalisation", "Principal": p,
		"Message": q.Get("m"), "Error": q.Get("e"), "Fields": ruleFields,
		"CanSave": s.mayUse(p, auth.ActPublish, "/") && !p.Limits.ReadOnly, "Q": q}
	if s.Personalise == nil || s.Personalise.Load == nil {
		data["Unavailable"] = "This build was started without personalisation."
		s.render(w, r, "personalise.html", data)
		return
	}
	set, err := s.Personalise.Load()
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "personalise.html", data)
		return
	}
	data["Rules"] = set.Rules
	if page := strings.Trim(q.Get("page"), "/"); page != "" && s.Personalise.Simulate != nil {
		req, when, serr := s.Personalise.Simulate(q.Get("campaign"), q.Get("referrer"),
			q.Get("language"), q.Get("device"), q.Get("at"))
		if serr != nil {
			data["SimError"] = serr.Error()
		} else if rule, hit := set.For(page, req, when); hit {
			data["SimRule"] = rule
		} else {
			data["SimNone"] = page
		}
	}
	s.render(w, r, "personalise.html", data)
}

func (s *Server) handlePersonaliseChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "takes a POST", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if s.Personalise == nil || s.Personalise.Load == nil || s.Personalise.Save == nil {
		http.Error(w, "this build cannot change rules", http.StatusServiceUnavailable)
		return
	}
	back := func(k, msg string) {
		http.Redirect(w, r, "/personalise?"+k+"="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	set, err := s.Personalise.Load()
	if err != nil {
		back("e", err.Error())
		return
	}
	op, name := r.FormValue("op"), strings.TrimSpace(r.FormValue("name"))
	var rule personalise.Rule
	switch op {
	case "add":
		rule = personalise.Rule{Name: name,
			Page:     strings.Trim(strings.TrimSpace(r.FormValue("page")), "/"),
			Variant:  strings.Trim(strings.TrimSpace(r.FormValue("variant")), "/"),
			Timezone: strings.TrimSpace(r.FormValue("timezone"))}
		for i := 0; i < 3; i++ {
			field := r.FormValue("field" + string(rune('0'+i)))
			values := splitCSV(r.FormValue("values" + string(rune('0'+i))))
			if field == "" || len(values) == 0 {
				continue
			}
			rule.When = append(rule.When, personalise.Condition{Field: personalise.Field(field),
				Name: strings.TrimSpace(r.FormValue("param" + string(rune('0'+i)))), Values: values})
		}
	case "enable", "disable", "remove":
		found := false
		rule, found = set.Get(name)
		if !found {
			back("e", "there is no rule called "+name)
			return
		}
	default:
		back("e", "that is not a change this screen makes")
		return
	}
	// Publish on both pages, each by name: see experiments.go.
	if !s.canPage(w, r, p, auth.ActPublish, rule.Page) ||
		!s.canPage(w, r, p, auth.ActPublish, rule.Variant) {
		return
	}
	switch op {
	case "add":
		err = set.Put(rule)
	case "enable", "disable":
		rule.Enabled = op == "enable"
		err = set.Put(rule)
	case "remove":
		set.Remove(name)
	}
	if err == nil {
		err = s.Personalise.Save(set, p.Name, op, name)
	}
	if err != nil {
		back("e", err.Error())
		return
	}
	back("m", "Saved.")
}
