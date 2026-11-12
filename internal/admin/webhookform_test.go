// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/webhook"
)

// hookedServer is a server whose Integrations screen keeps its endpoints in
// memory, with every audit record it writes.
func hookedServer(t *testing.T) (*Server, string, *[]webhook.Endpoint, *[]auditCall) {
	t.Helper()
	srv, token := setup(t)
	var stored []webhook.Endpoint
	srv.Integrations = &Integrations{
		Webhooks: func() ([]webhook.Endpoint, []webhook.Delivery, error) { return stored, nil, nil },
		UpdateWebhooks: func(f func([]webhook.Endpoint) ([]webhook.Endpoint, error)) error {
			next, err := f(append([]webhook.Endpoint(nil), stored...))
			if err != nil {
				return err
			}
			stored = next
			return nil
		},
	}
	var calls []auditCall
	srv.Audit = func(action, resource string, detail map[string]string) {
		calls = append(calls, auditCall{action, detail})
	}
	return srv, token, &stored, &calls
}

type auditCall struct {
	action string
	detail map[string]string
}

// The Integrations screen registers an endpoint by the rule `quilzo webhook
// add` does, and refuses what it refuses.
//
// The form checked only that the address began with https://, so it stored
// an address with a password in it, an address inside the network and a
// subscription to an event that is never sent, each of which the command
// line refuses. Each was shown as added, with a new key, and nothing could
// ever be delivered to it; and the password went into the audit log.
func TestTheIntegrationsScreenRegistersAnEndpointAsTheCommandLineDoes(t *testing.T) {
	for _, c := range []struct{ name, url, types string }{
		{"a password in the address", "https://hookuser:hookpass@hooks.example.org/x9gui", ""},
		{"an address inside the network", "https://10.0.0.5/x9gui", ""},
		{"the metadata service", "https://169.254.169.254/latest", ""},
		{"an event that is never sent", "https://hooks.example.org/x9gui", "nonsense"},
		{"plain http", "http://hooks.example.org/x9gui", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, token, stored, calls := hookedServer(t)
			res := postForm(t, srv, "/integrations/webhook", token,
				url.Values{"url": {c.url}, "types": {c.types}}.Encode())
			loc := res.Header().Get("Location")
			if res.Code != http.StatusSeeOther || !strings.Contains(loc, "e=") {
				t.Errorf("the screen answered %d, to %q, for %s", res.Code, loc, c.url)
			}
			if len(*stored) != 0 {
				t.Errorf("the screen stored %+v", *stored)
			}
			if len(*calls) != 0 {
				t.Errorf("a refused endpoint was recorded as %+v", *calls)
			}
			if strings.Contains(loc, "hookpass") {
				t.Errorf("the refusal carried the password in its redirect: %s", loc)
			}
		})
	}

	// And what the command line takes, the screen takes.
	srv, token, stored, _ := hookedServer(t)
	res := postForm(t, srv, "/integrations/webhook", token,
		url.Values{"url": {"https://hooks.example.org/x9gui"}, "types": {"published, submitted"}}.Encode())
	if res.Code != http.StatusOK || len(*stored) != 1 || strings.Join((*stored)[0].Types, ",") != "published,submitted" {
		t.Fatalf("a usable endpoint answered %d and stored %+v", res.Code, *stored)
	}
}

// What the Integrations screen records of an endpoint added, removed or
// turned off names its host, and never the path or query of its address.
//
// An incoming-webhook address (Slack, Teams, Discord) is a credential in its
// path, and many receivers take ?token=. The screen recorded the address in
// full, so the auditor, who reads the log and should change nothing, and
// every copy of the log forwarded to a SIEM could post as the site. The
// screen's redirect after a removal carried it too, into the browser's
// history and the access log.
func TestTheIntegrationsScreenDoesNotLogAWebhooksSecretAddress(t *testing.T) {
	const addr = "https://hooks.slack.example/services/T00000000/B00000000/XXXXSECRETXXXX?token=abc123SECRETvalue"
	srv, token, stored, calls := hookedServer(t)
	if res := postForm(t, srv, "/integrations/webhook", token, url.Values{"url": {addr}}.Encode()); res.Code != http.StatusOK {
		t.Fatalf("adding the endpoint answered %d", res.Code)
	}
	if len(*stored) != 1 || (*stored)[0].URL != addr {
		t.Fatalf("the endpoint was stored as %+v, not as it was typed", *stored)
	}
	var redirects []string
	for _, form := range []url.Values{{"url": {addr}, "disable": {"1"}}, {"url": {addr}}} {
		res := postForm(t, srv, "/integrations/webhook/remove", token, form.Encode())
		redirects = append(redirects, res.Header().Get("Location"))
	}
	if len(*stored) != 0 {
		t.Fatalf("the endpoint was not removed: %+v", *stored)
	}

	var actions []string
	refs := map[string]bool{}
	for _, c := range *calls {
		actions = append(actions, c.action)
		for k, v := range c.detail {
			if strings.Contains(v, "SECRET") {
				t.Errorf("%s recorded %s=%q", c.action, k, v)
			}
		}
		if c.detail["url"] != "https://hooks.slack.example/…" {
			t.Errorf("%s recorded the endpoint as %q", c.action, c.detail["url"])
		}
		refs[c.detail["endpoint_ref"]] = true
	}
	if strings.Join(actions, " ") != "webhook.add webhook.toggle webhook.remove" {
		t.Errorf("the screen recorded %v", actions)
	}
	// One endpoint, so one reference, by which its records line up.
	if len(refs) != 1 || refs[""] {
		t.Errorf("one endpoint's records carry the references %v", refs)
	}
	for _, loc := range redirects {
		if strings.Contains(loc, "SECRET") {
			t.Errorf("the screen redirected to %s", loc)
		}
	}
}
