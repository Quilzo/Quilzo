// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
)

// What Quilzo records about itself reaches the same queue as every other
// platform's events, through the shipped quilzo.* rules.
func TestQuilzoWatchesItsOwnAuditLog(t *testing.T) {
	root, rules := packSite(t)
	dana := &Caller{Name: "dana", Kind: audit.KindHuman, Verified: true}
	for _, r := range []audit.Record{
		dana.auditRecord("token.issue", "/", audit.Success,
			map[string]string{"role": "admin", "for": "sam", "issued_id": "t1"}),
		dana.auditRecord("config.set", "/", audit.Success,
			map[string]string{"setting": "admin.behind_tls_proxy", "from": "true",
				"to": "false", "accepted_risk": "the proxy is being replaced"}),
		dana.auditRecord("token.issue", "/", audit.Success,
			map[string]string{"role": "author", "for": "ann", "issued_id": "t2"}),
		{Action: "auth.failures", Resource: "/admin", Outcome: audit.Denied,
			Principal: "203.0.113.9", Kind: audit.KindUnknown,
			Detail: map[string]string{"failures": "6", "surface": "admin"}},
		// What the public site's detection points record.
		{Action: "site.chatbot-injection", Resource: "/", Outcome: audit.Denied,
			Principal: "203.0.113.10", Kind: audit.KindUnknown,
			Detail: map[string]string{"count": "1"}},
		{Action: "site.admin-hunt", Resource: "/", Outcome: audit.Denied,
			Principal: "203.0.113.11", Kind: audit.KindUnknown,
			Detail: map[string]string{"count": "3"}},
	} {
		if err := recordE(root, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	for _, want := range []string{"quilzo.admin-token-issued",
		"quilzo.setting-weakened", "quilzo.signin-failures",
		"quilzo.chatbot-injection", "quilzo.admin-hunted"} {
		if len(got[want]) != 1 {
			t.Errorf("%s opened %d findings", want, len(got[want]))
		}
	}
	// An author's token is ordinary, and not a finding.
	if n := len(got["quilzo.admin-token-issued"]); n > 1 {
		t.Errorf("an author's token was reported as an administrator's (%d)", n)
	}

	// The reason somebody typed for weakening a setting is theirs, and not
	// copied into the event store; only that there was one.
	for _, f := range got["quilzo.setting-weakened"] {
		for _, e := range f.Evidence {
			if strings.Contains(e.What, "proxy is being replaced") {
				t.Errorf("the typed reason reached the evidence: %s", e.What)
			}
		}
	}

	// Run again: nothing new is copied, and nothing is reported twice.
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	again := bySource(queue(t, root))
	if len(again["quilzo.admin-token-issued"]) != 1 {
		t.Error("the same audit record was read twice")
	}
}
