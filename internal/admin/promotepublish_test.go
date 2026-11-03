// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/site"
)

// Promoting into production on the Publishing screen is publishing, and
// takes every check Review → Publish takes, on what is promoted.
//
// It took none. With one approval required and no provenance recorded,
// Publish refused the draft and Promote put it live, straight from the
// draft or by way of staging, and told no webhook it had.
func TestPromotingIntoProductionOnTheScreenTakesThePublishChecks(t *testing.T) {
	srv, token := fullyWired(t)
	envs := &site.Envs{Environments: []site.Env{
		{Name: "staging", Ref: "env-staging", Order: 50},
		{Name: "production", Ref: site.RefLive, Order: 100, Production: true},
	}}
	srv.Publishing.Envs = func() (*site.Envs, error) { return envs, nil }
	required := 1
	srv.Approvals = &Approvals{
		Policy: func() (collab.Policy, error) { return collab.Policy{Required: required}, nil },
		Current: func() (*collab.Proposal, error) {
			return &collab.Proposal{Content: srv.Store.GetRef(site.RefDraft), Author: "someone"}, nil
		},
		Save:   func(*collab.Proposal) error { return nil },
		KindOf: func(string) string { return "human" },
	}
	told := make(chan string, 8)
	srv.Told = func(event, commit string, _ []string) { told <- event + " " + commit }
	promote := func(form url.Values) *http.Response {
		return postForm(t, srv, "/publishing/promote", token, form.Encode()).Result()
	}

	if w := postForm(t, srv, "/publish", token, "reason=go"); w.Code == http.StatusOK {
		t.Fatal("control: Publish did not refuse")
	}
	promote(url.Values{"from": {"draft"}, "to": {"production"}, "skip": {"1"}})
	promote(url.Values{"from": {"draft"}, "to": {"production"}, "skip": {"1"}, "reason": {"go"}})
	if live := srv.Store.GetRef(site.RefLive); live != "" {
		t.Fatal("the Publishing screen put an unchecked draft live")
	}
	// Staging is not public, and the draft goes there as before.
	promote(url.Values{"from": {"draft"}, "to": {"staging"}})
	if srv.Store.GetRef("env-staging") == "" {
		t.Fatal("the draft did not reach staging")
	}
	r := promote(url.Values{"from": {"staging"}, "to": {"production"}, "reason": {"go"}})
	if live := srv.Store.GetRef(site.RefLive); live != "" {
		t.Fatalf("an unchecked draft reached production by way of staging (%d)", r.StatusCode)
	}

	// With nothing left in the way but what a reason waives, the reason
	// promotes it, as publishing does, and the webhooks are told.
	required = 0
	if r := promote(url.Values{"from": {"staging"}, "to": {"production"}}); srv.Store.GetRef(site.RefLive) != "" {
		t.Fatalf("unmarked pages went live with no reason given (%d)", r.StatusCode)
	}
	page := postForm(t, srv, "/publishing/promote", token, url.Values{"from": {"staging"}, "to": {"production"}}.Encode()).Body.String()
	if !strings.Contains(page, `action="/publishing/promote"`) || !strings.Contains(page, `name="from" value="staging"`) {
		t.Error("the refusal's reason box does not promote what was being promoted")
	}
	promote(url.Values{"from": {"staging"}, "to": {"production"}, "reason": {"hand-written, marking pending"}})
	staged := srv.Store.GetRef("env-staging")
	if live := srv.Store.GetRef(site.RefLive); live != staged {
		t.Fatalf("live is %q, staging holds %q", live, staged)
	}
	select {
	case got := <-told:
		if got != "published "+staged {
			t.Fatalf("told %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("promoting into production told nobody it was published")
	}
}
