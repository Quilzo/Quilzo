// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/out"
)

// secretHook is an incoming-webhook address of the kind Slack, Teams and
// Discord hand out, whose path is the credential, with a ?token= as many
// other receivers take.
const secretHook = "https://hooks.slack.example/services/T00000000/B00000000/XXXXSECRETXXXX?token=abc123SECRETvalue"

// webhookRecords are the log's records of endpoints, and fails the test if
// the log holds the secret part of secretHook anywhere at all.
func webhookRecords(t *testing.T, root string) []audit.Event {
	t.Helper()
	raw, err := os.ReadFile(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SECRET") {
		t.Error("the audit log holds the endpoint's secret address")
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, e := range events {
		if strings.HasPrefix(e.Action, "webhook.") {
			out = append(out, e)
		}
	}
	return out
}

// sameEndpoint checks the records name the endpoint by its host and one
// reference, and are the acts given.
func sameEndpoint(t *testing.T, got []audit.Event, acts ...string) {
	t.Helper()
	var names []string
	refs := map[string]bool{}
	for _, e := range got {
		names = append(names, e.Action)
		if e.Detail["endpoint"] != "https://hooks.slack.example/…" {
			t.Errorf("%s recorded the endpoint as %q", e.Action, e.Detail["endpoint"])
		}
		refs[e.Detail["endpoint_ref"]] = true
	}
	if strings.Join(names, " ") != strings.Join(acts, " ") {
		t.Errorf("the log recorded %v, want %v", names, acts)
	}
	if len(refs) != 1 || refs[""] {
		t.Errorf("one endpoint's records carry the references %v", refs)
	}
}

// What `quilzo webhook add` and `remove` record of an endpoint names its
// host, and never the path or query of its address.
//
// They recorded the address in full. The path of an incoming-webhook address
// is a credential, as is a ?token=, so the auditor, who reads the log and
// should change nothing, and every copy of the log forwarded to a SIEM could
// post as the site. `webhook list` still shows the address in full, to the
// administrators it always showed it to.
func TestAWebhooksAddressIsNotWrittenToTheAuditLog(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	old := w
	w = out.New(false)
	t.Cleanup(func() { w = old })
	root := storeFolder(t)
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := hookAdd(root, []string{secretHook}); err != nil {
		t.Fatal(err)
	}
	f := &hookFile{}
	if err := loadJSON(hooksPath(root), f); err != nil || len(f.Endpoints) != 1 || f.Endpoints[0].URL != secretHook {
		t.Fatalf("the endpoint was not stored as it was typed: %v %+v", err, f.Endpoints)
	}
	if err := hookRemove(root, []string{secretHook}); err != nil {
		t.Fatal(err)
	}
	sameEndpoint(t, webhookRecords(t, root), "webhook.add", "webhook.remove")
}

// What a feature records of the endpoints it adds, changes and takes away
// names their hosts, as `quilzo webhook add` does.
func TestAFeaturesWebhookAddressIsNotWrittenToTheAuditLog(t *testing.T) {
	root := demoStore(t)
	seedPolicy(t, root, [2]string{"dana", "admin"})
	pkg := func(version, types string) string {
		path := filepath.Join(t.TempDir(), "hooky.json")
		body := `{"format": 1, "name": "hooky", "version": "` + version + `", "title": "Hooky",
			"purpose": "Tells a receiver when a page is published.",
			"webhooks": [{"url": "` + secretHook + `", "types": [` + types + `]}]}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := installFeatureFile(root, pkg("1.0.0", ""), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if err := installFeatureFile(root, pkg("1.1.0", `"published"`), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if err := removeFeature(root, "hooky", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	sameEndpoint(t, webhookRecords(t, root), "webhook.add", "webhook.change", "webhook.remove")
}
