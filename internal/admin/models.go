// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/gateway"
)

// The model gateway, on a screen: where prompts go, what happens when a
// provider is down, and what each chatbot and agent has spent today.
//
// Administrative, and so behind grant: a route decides who receives what
// visitors typed and what the site holds. Keys are never shown and never
// entered here — a route names the environment variable its key lives in,
// and the screen says whether that variable is set.

// Models is the gateway, supplied by whatever wired this server.
type Models struct {
	// Load returns the declaration, each route's health and today's
	// spending. A nil declaration means no gateway is configured.
	Load func() (*gateway.Config, []gateway.Health, []gateway.Spend, error)
	Save func(cfg *gateway.Config, by, change, name string) error
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	data := map[string]any{
		"Nav": "models", "Title": "Models", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
	}
	if s.Models == nil || s.Models.Load == nil {
		data["Unavailable"] = "This build was started without the model gateway."
		s.render(w, r, "models.html", data)
		return
	}
	cfg, health, spend, err := s.Models.Load()
	if err != nil {
		data["Unavailable"] = "The gateway declaration could not be read: " + err.Error()
		s.render(w, r, "models.html", data)
		return
	}
	data["Cfg"], data["Health"], data["Spend"] = cfg, health, spend
	data["Currency"] = ""
	if cfg != nil {
		data["Currency"] = cfg.Currency
	}
	s.render(w, r, "models.html", data)
}

func (s *Server) handleModelsChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "takes a POST", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	if s.Models == nil || s.Models.Load == nil || s.Models.Save == nil {
		http.Error(w, "this build cannot change the gateway", http.StatusServiceUnavailable)
		return
	}
	cfg, _, _, err := s.Models.Load()
	back := func(key, msg string) {
		http.Redirect(w, r, "/models?"+key+"="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	if err != nil {
		back("e", err.Error())
		return
	}
	if cfg == nil {
		cfg = &gateway.Config{}
	}
	op := r.FormValue("op")
	name := strings.TrimSpace(r.FormValue("name"))
	switch op {
	case "route-add", "route-remove", "route-first":
		var kept []gateway.Route
		var found *gateway.Route
		for _, rt := range cfg.Routes {
			if rt.Name == name {
				rt := rt
				found = &rt
				continue
			}
			kept = append(kept, rt)
		}
		switch op {
		case "route-add":
			kept = append(kept, gateway.Route{Name: name,
				URL:      strings.TrimSpace(r.FormValue("url")),
				Model:    strings.TrimSpace(r.FormValue("model")),
				KeyEnv:   strings.TrimSpace(r.FormValue("key_env")),
				PriceIn:  strings.TrimSpace(r.FormValue("price_in")),
				PriceOut: strings.TrimSpace(r.FormValue("price_out")),
				Personal: r.FormValue("personal") == "yes"})
		case "route-first":
			if found == nil {
				back("e", "there is no route called "+name)
				return
			}
			kept = append([]gateway.Route{*found}, kept...)
		case "route-remove":
			if found == nil {
				back("e", "there is no route called "+name)
				return
			}
		}
		cfg.Routes = kept
	case "budget", "budget-remove":
		var kept []gateway.Budget
		for _, b := range cfg.Budgets {
			if b.Consumer != name {
				kept = append(kept, b)
			}
		}
		if op == "budget" {
			pm, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("per_minute")))
			pd, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("chars_per_day")))
			tk, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("tokens_per_day")))
			kept = append(kept, gateway.Budget{Consumer: name, PerMinute: pm, CharsPerDay: pd, TokensPerDay: tk,
				MoneyPerDay:   strings.TrimSpace(r.FormValue("money_per_day")),
				MoneyPerMonth: strings.TrimSpace(r.FormValue("money_per_month"))})
		}
		cfg.Budgets = kept
	case "currency":
		cfg.Currency = strings.ToUpper(strings.TrimSpace(r.FormValue("currency")))
	default:
		back("e", "that is not a change this screen makes")
		return
	}
	if err := cfg.Validate(); err != nil {
		back("e", err.Error())
		return
	}
	if err := s.Models.Save(cfg, p.Name, op, name); err != nil {
		back("e", err.Error())
		return
	}
	back("m", "Saved.")
}
