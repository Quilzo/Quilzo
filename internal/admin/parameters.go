// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/odp"
	"github.com/quilzo/quilzo/internal/oscal"
)

// The organisation's policy, as NIST organisation-defined parameters
// (internal/odp): what is declared, what the deployment does, whether the
// first is met; proposals waiting for a second administrator; OSCAL in and
// out. The same rules as `quilzo policy`, through the same package.

// Parameters gives the admin the policy.
type Parameters struct {
	// Path is where the policy is kept.
	Path string
	// OnlyAdmin reports whether a person is the only administrator, who may
	// then approve their own proposal; the policy says it was alone.
	OnlyAdmin func(name string) bool
	// Organisation names the exported profile.
	Organisation string
}

type paramRow struct {
	odp.Param
	Declared  *odp.Declared
	Effective string
	Met       bool
	Choices   []paramChoice
	Plain     string
}

type paramChoice struct {
	Words   string
	Value   string
	Checked bool
}

type paramProposal struct {
	odp.Proposal
	Mine    bool
	Expires string
	Lines   []string
}

func (s *Server) handleParameters(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Title": "Organisation policy", "Nav": "security", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Parameters == nil || s.Settings == nil || s.Settings.Load == nil {
		data["Unavailable"] = "This server was started without the configuration, so the policy cannot be shown."
		s.render(w, r, "parameters.html", data)
		return
	}
	pol, err := odp.Load(s.Parameters.Path)
	if err != nil {
		data["Broken"] = err.Error()
		s.render(w, r, "parameters.html", data)
		return
	}
	cfg, err := s.Settings.Load()
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "parameters.html", data)
		return
	}
	var rows []paramRow
	unmet := 0
	for _, prm := range odp.Params {
		row := paramRow{Param: prm, Effective: odp.Effective(prm, cfg), Met: true}
		if d, ok := pol.Find(prm.ID); ok {
			d := d
			row.Declared = &d
			row.Met = odp.Met(d, cfg)
			if !row.Met {
				unmet++
			}
		}
		if prm.Kind == odp.Choice {
			have := ""
			if row.Declared != nil {
				have = row.Declared.Value
			}
			for _, c := range prm.Choices {
				words := strings.TrimSpace(strings.Split(c, "{{")[0])
				words = strings.TrimSuffix(strings.TrimSuffix(words, " per"), " for")
				row.Choices = append(row.Choices, paramChoice{Words: words, Value: c,
					Checked: strings.Contains(have, strings.TrimSpace(strings.Split(c, "{{")[0]))})
			}
		}
		row.Plain = strings.ReplaceAll(row.Effective, "\n", "; ")
		rows = append(rows, row)
	}
	var pending []paramProposal
	for _, pr := range pol.Pending(time.Now()) {
		pp := paramProposal{Proposal: pr, Mine: pr.By == p.Name, Expires: pr.Expires.Format("2 January 15:04")}
		for _, c := range pr.Changes {
			if c.Value == "" {
				pp.Lines = append(pp.Lines, c.Param+": take the declaration away")
			} else {
				pp.Lines = append(pp.Lines, c.Param+" = "+strings.ReplaceAll(c.Value, "\n", "; "))
			}
		}
		pending = append(pending, pp)
	}
	data["Rows"], data["Pending"], data["Unmet"] = rows, pending, unmet
	data["Declared"] = len(pol.Declared)
	data["CanChange"] = s.shieldSiteAdmin(p) && !p.Limits.ReadOnly
	data["Alone"] = s.Parameters.OnlyAdmin != nil && s.Parameters.OnlyAdmin(p.Name)
	data["Life"] = int(odp.ProposalLife.Hours() / 24)
	s.render(w, r, "parameters.html", data)
}

func (s *Server) handleParametersAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	back := func(k, v string) {
		http.Redirect(w, r, "/security/parameters?"+url.Values{k: {v}}.Encode(), http.StatusSeeOther)
	}
	if s.Parameters == nil {
		back("e", "This build cannot change the policy.")
		return
	}
	if p.Limits.ReadOnly {
		http.Error(w, "this token is read-only", http.StatusForbidden)
		return
	}
	if !s.shieldSiteAdmin(p) {
		back("e", "Changing the organisation's policy takes an administrator of the whole site.")
		return
	}
	path, now := s.Parameters.Path, time.Now()
	reason := strings.TrimSpace(r.FormValue("reason"))
	id := strings.TrimSpace(r.FormValue("id"))
	switch r.FormValue("do") {
	case "propose":
		param := strings.TrimSpace(r.FormValue("param"))
		value := strings.TrimSpace(r.FormValue("value"))
		if vs := r.Form["choice"]; len(vs) > 0 {
			value = strings.Join(vs, "\n")
		}
		if r.FormValue("remove") == "1" {
			value = ""
		}
		var pr odp.Proposal
		err := odp.Update(path, func(pol *odp.Policy) error {
			var perr error
			pr, perr = pol.Propose([]odp.Change{{Param: param, Value: value}}, reason, p.Name, "", now)
			return perr
		})
		if err != nil {
			back("e", err.Error())
			return
		}
		s.audit("policy.proposed", "/settings", map[string]string{"by": p.Name, "proposal": pr.ID,
			"changes": param + " = " + strings.ReplaceAll(value, "\n", "; "), "reason": reason})
		back("m", "Proposed. Another administrator approves it here within a week.")
	case "import":
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			back("e", "Choose an OSCAL JSON file of at most 4 MiB.")
			return
		}
		f, _, err := r.FormFile("file")
		if err != nil {
			back("e", "Choose an OSCAL JSON file.")
			return
		}
		body, err := io.ReadAll(io.LimitReader(f, 4<<20))
		f.Close()
		if err != nil {
			back("e", err.Error())
			return
		}
		reason = strings.TrimSpace(r.FormValue("reason"))
		var im odp.Imported
		var pr odp.Proposal
		err = odp.Update(path, func(pol *odp.Policy) error {
			var ierr error
			if im, ierr = odp.FromOSCAL(body, pol); ierr != nil {
				return ierr
			}
			if len(im.Changes) == 0 {
				return nil
			}
			pr, ierr = pol.Propose(im.Changes, reason, p.Name, "import", now)
			return ierr
		})
		if err != nil {
			back("e", err.Error())
			return
		}
		msg := "Read a " + im.Kind + "."
		if pr.ID != "" {
			s.audit("policy.proposed", "/settings", map[string]string{"by": p.Name, "proposal": pr.ID,
				"source": "import", "reason": reason})
			msg += " Proposed " + countOf(len(pr.Changes), "change", "changes") + " for a second administrator."
		} else {
			msg += " Nothing to change."
		}
		if len(im.NotOurs) > 0 {
			msg += " " + countOf(len(im.NotOurs), "parameter is", "parameters are") + " about the organisation's people, processes or other systems, and left to them."
		}
		if len(im.Refused) > 0 {
			back("e", msg+" Cannot keep: "+strings.Join(im.Refused, "; "))
			return
		}
		back("m", msg)
	case "approve", "decline":
		approve := r.FormValue("do") == "approve"
		alone := s.Parameters.OnlyAdmin != nil && s.Parameters.OnlyAdmin(p.Name)
		var pr odp.Proposal
		err := odp.Update(path, func(pol *odp.Policy) error {
			var derr error
			pr, derr = pol.Decide(id, p.Name, approve, alone, now)
			return derr
		})
		if err != nil {
			if errors.Is(err, odp.ErrSameAdministrator) {
				s.audit("policy.refused", "/settings", map[string]string{"by": p.Name, "proposal": id, "reason": "proposer approving"})
			}
			back("e", err.Error())
			return
		}
		if !approve {
			s.audit("policy.declined", "/settings", map[string]string{"by": p.Name, "proposal": pr.ID})
			back("m", "Declined.")
			return
		}
		detail := map[string]string{"by": p.Name, "proposal": pr.ID, "proposed_by": pr.By}
		if pr.By == p.Name {
			detail["alone"] = "true"
		}
		s.audit("policy.approved", "/settings", detail)
		raised, err := s.raiseToPolicy(p.Name)
		if err != nil {
			back("e", "Approved, and the settings could not be brought up to it: "+err.Error()+". Upkeep will retry.")
			return
		}
		msg := "Approved."
		if raised > 0 {
			msg += " " + countOf(raised, "setting was", "settings were") + " raised to meet it."
		}
		back("m", msg)
	case "withdraw":
		var pr odp.Proposal
		err := odp.Update(path, func(pol *odp.Policy) error {
			var werr error
			pr, werr = pol.Withdraw(id, p.Name)
			return werr
		})
		if err != nil {
			back("e", err.Error())
			return
		}
		s.audit("policy.withdrawn", "/settings", map[string]string{"by": p.Name, "proposal": pr.ID})
		back("m", "Withdrawn.")
	default:
		back("e", "Nothing was asked for.")
	}
}

// raiseToPolicy brings the settings up to the policy just approved.
func (s *Server) raiseToPolicy(by string) (int, error) {
	if s.Settings == nil || s.Settings.Load == nil || s.Settings.Save == nil {
		return 0, errors.New("this server was started without the configuration")
	}
	pol, err := odp.Load(s.Parameters.Path)
	if err != nil {
		return 0, err
	}
	cfg, err := s.Settings.Load()
	if err != nil {
		return 0, err
	}
	raised, err := odp.Raise(pol, cfg, by)
	if err != nil || len(raised) == 0 {
		return 0, err
	}
	if err := s.Settings.Save(cfg); err != nil {
		return 0, err
	}
	for _, r := range raised {
		s.audit("policy.enforced", "/settings", map[string]string{"setting": r.Key, "from": r.From, "to": r.To,
			"param": r.Param, "after": by})
	}
	return len(raised), nil
}

// handleParametersExport is the policy as an OSCAL profile, to download.
func (s *Server) handleParametersExport(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.assuranceReader(w, r); !ok {
		return
	}
	if s.Parameters == nil || s.Settings == nil || s.Settings.Load == nil {
		http.Error(w, "this server cannot read the policy", http.StatusServiceUnavailable)
		return
	}
	pol, err := odp.Load(s.Parameters.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg, err := s.Settings.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	title := "Organisation-defined parameters"
	if s.Parameters.Organisation != "" {
		title = s.Parameters.Organisation + ": organisation-defined parameters"
	}
	prof, err := oscal.ParameterProfile(title, "1", time.Now(), odp.SetParameters(pol, cfg))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="parameters.oscal.json"`)
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(prof)
}
