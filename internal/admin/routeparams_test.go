// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/gateway"
)

// What a route's model is sent is set on the screen, checked as on the
// command line, and shown in the list of routes.
func TestARoutesFieldsAreSetOnTheScreen(t *testing.T) {
	srv, token := setup(t)
	m, cfg := modelsRig()
	srv.Models = m
	decideForm(t, srv, "/models/change", token, url.Values{"op": {"route-add"}, "name": {"reasoner"},
		"url": {"https://api.example/v1"}, "model": {"o-big"}, "max_tokens_field": {"max_completion_tokens"},
		"temperature": {"1"}, "timeout": {"300s"}, "auto_tool_choice": {"yes"}})
	if len(cfg.Routes) != 1 {
		t.Fatalf("%+v", cfg.Routes)
	}
	p := cfg.Routes[0].Params
	if p.MaxTokens != "max_completion_tokens" || p.Temperature == nil || *p.Temperature != 1 || p.TopP != nil ||
		p.Timeout != "300s" || !p.AutoToolChoice {
		t.Fatalf("%+v", p)
	}
	if body := get(t, srv, "/models", token).Body.String(); !strings.Contains(body, "max_completion_tokens, temperature 1") {
		t.Error("the list of routes does not say what the route sends")
	}
	for _, bad := range []url.Values{{"temperature": {"warm"}}, {"temperature": {"9"}}, {"top_p": {"0"}},
		{"timeout": {"forever"}}, {"max_tokens_field": {"max_output"}}} {
		v := url.Values{"op": {"route-add"}, "name": {"x"}, "url": {"https://api.example/v1"}, "model": {"m"}}
		for k, vs := range bad {
			v[k] = vs
		}
		w := decideForm(t, srv, "/models/change", token, v)
		if !strings.Contains(w.Header().Get("Location"), "e=") || len(cfg.Routes) != 1 {
			t.Errorf("%v was accepted", bad)
		}
	}
}

// A request the provider refused as malformed is answered as the caller's
// mistake, not as the gateway's.
func TestARefusedRequestIsTheCallersToFix(t *testing.T) {
	if got := doorStatus(&assist.StatusError{Code: http.StatusBadRequest, Body: "bad"}); got != http.StatusBadRequest {
		t.Errorf("400 became %d", got)
	}
	if got := doorStatus(fmt.Errorf("x: %w", &assist.StatusError{Code: http.StatusUnprocessableEntity})); got != http.StatusUnprocessableEntity {
		t.Errorf("422 became %d", got)
	}
	if got := doorStatus(fmt.Errorf("%w: hosted: model returned 503", gateway.ErrNoRoute)); got != http.StatusServiceUnavailable {
		t.Errorf("no route became %d", got)
	}
	if got := doorStatus(errors.New("something else")); got != http.StatusBadGateway {
		t.Errorf("an unknown failure became %d", got)
	}
}
