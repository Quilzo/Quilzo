// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/provider"
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
	// Providers are the providers a route can name (internal/provider),
	// in the order a person reads them; nil offers only an address.
	Providers func() []provider.Provider
}

// providerChoice is a group of providers, for the form's list.
type providerChoice struct {
	Group     string
	Providers []provider.Provider
}

func (m *Models) choices() []providerChoice {
	if m == nil || m.Providers == nil {
		return nil
	}
	var out []providerChoice
	for _, p := range m.Providers() {
		name := provider.GroupName(p.Group)
		if len(out) == 0 || out[len(out)-1].Group != name {
			out = append(out, providerChoice{Group: name})
		}
		out[len(out)-1].Providers = append(out[len(out)-1].Providers, p)
	}
	return out
}

// providerOf is a provider by id, from the list the form offered.
func (m *Models) providerOf(id string) (provider.Provider, bool) {
	if m == nil || m.Providers == nil {
		return provider.Provider{}, false
	}
	for _, p := range m.Providers() {
		if p.ID == id {
			return p, true
		}
	}
	return provider.Provider{}, false
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
	data["Choices"] = s.Models.choices()
	// What each route's provider says it does with what it is sent, by id.
	known := map[string]provider.Provider{}
	if s.Models.Providers != nil {
		for _, pv := range s.Models.Providers() {
			known[pv.ID] = pv
		}
	}
	data["Known"] = known
	if d := s.ModelDoor; d != nil && d.Enabled != nil {
		data["Door"], data["DoorOn"], data["Origin"] = true, d.Enabled(), s.ownOrigin(r)
	}
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
			params := gateway.RouteParams{MaxTokens: strings.TrimSpace(r.FormValue("max_tokens_field")),
				Timeout: strings.TrimSpace(r.FormValue("timeout")), AutoToolChoice: r.FormValue("auto_tool_choice") == "yes",
				Effort: strings.TrimSpace(r.FormValue("effort")), Geo: strings.TrimSpace(r.FormValue("geo")),
				Fallback: r.FormValue("server_fallback") == "yes"}
			for _, f := range []struct {
				field string
				into  **float64
			}{{"temperature", &params.Temperature}, {"top_p", &params.TopP}} {
				if raw := strings.TrimSpace(r.FormValue(f.field)); raw != "" {
					v, err := strconv.ParseFloat(raw, 64)
					if err != nil {
						back("e", f.field+" is a number")
						return
					}
					*f.into = &v
				}
			}
			route := gateway.Route{Name: name,
				URL:          strings.TrimSpace(r.FormValue("url")),
				Model:        strings.TrimSpace(r.FormValue("model")),
				KeyEnv:       strings.TrimSpace(r.FormValue("key_env")),
				KeySecret:    strings.TrimSpace(r.FormValue("key_secret")),
				PriceIn:      strings.TrimSpace(r.FormValue("price_in")),
				PriceOut:     strings.TrimSpace(r.FormValue("price_out")),
				Personal:     r.FormValue("personal") == "yes",
				Params:       params,
				Draws:        r.FormValue("draws") == "yes",
				PricePicture: strings.TrimSpace(r.FormValue("price_picture"))}
			// A provider chosen: its address from its profile, its
			// parameter checked before it goes into a host name, and its
			// key's credential named the way it suggests.
			if id := strings.TrimSpace(r.FormValue("provider")); id != "" {
				pv, ok := s.Models.providerOf(id)
				if !ok {
					back("e", id+" is not a provider here")
					return
				}
				values := map[string]string{}
				if len(pv.Params) > 0 {
					values[pv.Params[0].Name] = strings.TrimSpace(r.FormValue("provider_param"))
				}
				base, _, perr := pv.Endpoint(values)
				if perr != nil {
					back("e", perr.Error())
					return
				}
				route.Provider = pv.ID
				if err := route.CheckWire(pv.Wire); err != nil {
					back("e", err.Error())
					return
				}
				if len(pv.Params) > 0 {
					route.ProviderParams = values
				}
				if route.URL == "" {
					route.URL = base
				}
				if route.KeySecret == "" && route.KeyEnv == "" && pv.Auth != "none" {
					route.KeySecret = pv.Key
				}
			} else if route.URL == "" {
				back("e", "choose a provider, or give the address of one")
				return
			} else if err := route.CheckWire(""); err != nil {
				back("e", err.Error())
				return
			}
			kept = append(kept, route)
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
