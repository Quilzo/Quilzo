// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/provider"
)

// A route is added by choosing its provider: the address comes from the
// profile, a parameter is checked before it goes into a host, and the key's
// sealed credential is named the way the provider suggests.
func TestARouteIsAddedByChoosingItsProvider(t *testing.T) {
	srv, token := setup(t)
	m, cfg := modelsRig()
	cat, err := provider.Load("")
	if err != nil {
		t.Fatal(err)
	}
	m.Providers = cat.All
	srv.Models = m

	body := get(t, srv, "/models", token).Body.String()
	whole(t, body)
	for _, want := range []string{`<optgroup label="On this machine or your network">`, `<option value="groq">Groq`,
		`<option value="azure-openai">Azure OpenAI`, `name="key_secret"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the form does not offer %q", want)
		}
	}

	decideForm(t, srv, "/models/change", token, url.Values{"op": {"route-add"}, "name": {"fast"},
		"provider": {"groq"}, "model": {"llama-3.3-70b-versatile"}})
	decideForm(t, srv, "/models/change", token, url.Values{"op": {"route-add"}, "name": {"azure"},
		"provider": {"azure-openai"}, "provider_param": {"contoso-ai"}, "model": {"gpt-prod"}, "key_secret": {"azure-prod"}})
	if len(cfg.Routes) != 2 {
		t.Fatalf("%+v", cfg.Routes)
	}
	g, a := cfg.Routes[0], cfg.Routes[1]
	if g.Provider != "groq" || g.URL != "https://api.groq.com/openai/v1" || g.KeySecret != "groq" {
		t.Fatalf("%+v", g)
	}
	if a.URL != "https://contoso-ai.openai.azure.com/openai/v1" || a.ProviderParams["resource"] != "contoso-ai" ||
		a.KeySecret != "azure-prod" {
		t.Fatalf("%+v", a)
	}
	body = get(t, srv, "/models", token).Body.String()
	for _, want := range []string{"sealed as <code>groq</code>", "Groq · United States"} {
		if !strings.Contains(body, want) {
			t.Errorf("the routes do not say %q", want)
		}
	}

	// A resource that would be another host, and no provider and no
	// address: refused, with why, and nothing added.
	for _, v := range []url.Values{
		{"op": {"route-add"}, "name": {"bad"}, "provider": {"azure-openai"}, "provider_param": {"evil.example/x"}, "model": {"m"}},
		{"op": {"route-add"}, "name": {"none"}, "model": {"m"}},
		{"op": {"route-add"}, "name": {"who"}, "provider": {"nobody"}, "model": {"m"}},
	} {
		w := decideForm(t, srv, "/models/change", token, v)
		if !strings.Contains(w.Header().Get("Location"), "e=") || len(cfg.Routes) != 2 {
			t.Errorf("%v was not refused: %s", v, w.Header().Get("Location"))
		}
	}
}
