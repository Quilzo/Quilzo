// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/gateway"
)

func modelsRig() (*Models, *gateway.Config) {
	cfg := &gateway.Config{}
	return &Models{
		Load: func() (*gateway.Config, []gateway.Health, []gateway.Spend, error) {
			var hs []gateway.Health
			for _, r := range cfg.Routes {
				hs = append(hs, gateway.Health{Route: r, KeySet: r.KeyEnv == ""})
			}
			cp := *cfg
			return &cp, hs, []gateway.Spend{{Consumer: "chatbot:help", Chars: 700, Calls: 3, Budget: 1000}}, nil
		},
		Save: func(c *gateway.Config, _, _, _ string) error { *cfg = *c; return nil },
	}, cfg
}

func TestRoutesAndBudgetsAreChangedOnTheScreen(t *testing.T) {
	srv, token := setup(t)
	m, cfg := modelsRig()
	srv.Models = m
	decideForm(t, srv, "/models/change", token, url.Values{"op": {"route-add"}, "name": {"local"},
		"url": {"http://localhost:11434/v1"}, "model": {"gpt-oss:20b"}})
	decideForm(t, srv, "/models/change", token, url.Values{"op": {"route-add"}, "name": {"hosted"},
		"url": {"https://api.example/v1"}, "model": {"big"}, "key_env": {"HOSTED_KEY"}})
	decideForm(t, srv, "/models/change", token, url.Values{"op": {"route-first"}, "name": {"hosted"}})
	if len(cfg.Routes) != 2 || cfg.Routes[0].Name != "hosted" {
		t.Fatalf("%+v", cfg.Routes)
	}
	decideForm(t, srv, "/models/change", token, url.Values{"op": {"budget"}, "name": {"chatbot:help"},
		"chars_per_day": {"1000"}})
	if b, ok := cfg.BudgetFor("chatbot:help"); !ok || b.CharsPerDay != 1000 {
		t.Fatalf("%+v", cfg.Budgets)
	}
	body := get(t, srv, "/models", token).Body.String()
	for _, want := range []string{"$HOSTED_KEY", "not set", `<meter`, "700 of 1000"} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen does not show %q", want)
		}
	}
	// A key pasted where its variable's name belongs is refused, with why.
	w := decideForm(t, srv, "/models/change", token, url.Values{"op": {"route-add"}, "name": {"x"},
		"url": {"https://api.example/v1"}, "model": {"m"}, "key_env": {"sk-live-123"}})
	if !strings.Contains(w.Header().Get("Location"), "e=") || len(cfg.Routes) != 2 {
		t.Fatal("a key was accepted as a variable name")
	}
}

func TestOnlyAnAdministratorDecidesWherePromptsGo(t *testing.T) {
	m, cfg := modelsRig()
	pub, token := asRole(t, auth.RolePublisher)
	pub.Models = m
	if w := get(t, pub, "/models", token); w.Code == http.StatusOK {
		t.Fatal("a publisher opened the models screen")
	}
	decideForm(t, pub, "/models/change", token, url.Values{"op": {"route-add"}, "name": {"evil"},
		"url": {"https://collector.example/v1"}, "model": {"m"}})
	if len(cfg.Routes) != 0 {
		t.Fatal("a publisher added a route")
	}
}
