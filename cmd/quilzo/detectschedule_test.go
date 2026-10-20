// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// auditHas reports whether the log holds an action whose details include
// every pair given.
func auditHas(t *testing.T, root, action string, detail map[string]string) bool {
	t.Helper()
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action != action {
			continue
		}
		ok := true
		for k, v := range detail {
			ok = ok && e.Detail[k] == v
		}
		if ok {
			return true
		}
	}
	return false
}

// A new store has the shipped rules as its own files; a store that keeps
// its own rules is left exactly as it is.
func TestANewStoreStartsWithTheShippedRules(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(root, "detections", "quilzo.admin-granted.json")
	if _, err := os.Stat(rule); err != nil {
		t.Fatalf("a new store has no rule about an administrator being made: %v", err)
	}
	if err := os.Remove(rule); err != nil {
		t.Fatal(err)
	}
	if err := ensureRules(root, "server-start"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rule); err == nil {
		t.Error("a rule the organisation removed from its own directory came back")
	}
}

// With no collection and no feeds, the server's timer reads Quilzo's own
// log: an administrator made on the command line is a finding within one
// tick, and a tick with nothing new to read does not run a pass.
func TestTheTimerReadsQuilzosOwnLogWithNoOtherSource(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := ensureRules(root, "server-start"); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "dana", "admin"}); err != nil {
		t.Fatal(err)
	}
	job := detectJob(root)
	if _, err := job.Do(time.Now()); err != nil {
		t.Fatal(err)
	}
	reg, _, err := finding.Load(findingsPath(root))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range reg.All(time.Now()) {
		found = found || f.Source == "quilzo.admin-granted"
	}
	if !found {
		t.Fatal("an administrator made on the command line raised nothing on the timer")
	}
	runs := func() int {
		events, _ := audit.Read(auditPath(root))
		n := 0
		for _, e := range events {
			if e.Action == "detect.run" {
				n++
			}
		}
		return n
	}
	before := runs()
	if _, err := job.Do(time.Now()); err != nil {
		t.Fatal(err)
	}
	if runs() != before {
		t.Error("a tick with nothing new ran a pass, so every pass would be the reason for the next")
	}
}

// Provisioning records the roles it gives and takes, so a group mapped to
// admin is seen by the rule about administrators.
func TestProvisioningRecordsTheRolesItGives(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := scimSync(root, "alex", []string{"admin"}, false); err != nil {
		t.Fatal(err)
	}
	if !auditHas(t, root, "scim.granted", map[string]string{"role": "admin"}) {
		t.Error("provisioning made an administrator and recorded no role")
	}
	if err := scimSync(root, "alex", nil, false); err != nil {
		t.Fatal(err)
	}
	if !auditHas(t, root, "scim.revoked", map[string]string{"role": "admin"}) {
		t.Error("provisioning took the role away and recorded nothing")
	}
}

// The session a script asks for in JSON is recorded like any other.
func TestATokenExchangeInJSONIsRecorded(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue("ci", "dana", "admin", "/", time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
	old := w
	w = out.New(true)
	t.Cleanup(func() { w = old })
	if err := tokenExchange(root, []string{"--ttl", "10m"}); err != nil {
		t.Fatal(err)
	}
	if !auditHas(t, root, "token.exchange", nil) {
		t.Error("a session minted for a script left no record")
	}
}

// A webhook a feature package adds is recorded on its own, with where it
// sends, and the install records how risky its card said it was.
func TestAFeaturesWebhooksAreRecordedOneByOne(t *testing.T) {
	root := featureSite(t)
	path := writePackage(t, func(p *feature.Package) {
		withoutAddress(p)
		p.Webhooks = []feature.Webhook{{URL: "https://hooks.quilzo.io/samples", Types: []string{"published"}}}
	})
	if err := installFeatureFile(root, path, "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if pending, _ := pendingFeatures(root); len(pending) > 0 {
		if err := decideFeature(root, pending[0].ID, true, asAdmin("sam")); err != nil {
			t.Fatal(err)
		}
	}
	if !auditHas(t, root, "webhook.add", map[string]string{"endpoint": "https://hooks.quilzo.io/samples",
		"feature": "lab-samples"}) {
		t.Error("a webhook a package added was not recorded")
	}
	events, _ := audit.Read(auditPath(root))
	risk := ""
	for _, e := range events {
		if e.Action == "feature.installed" {
			risk = e.Detail["risk"]
		}
	}
	if risk == "" || !strings.Contains("low medium high", risk) {
		t.Errorf("the install did not record its card's risk: %q", risk)
	}
}

// The detection job is one of the server's own, not something a person
// has to remember to start.
func TestTheServerRunsTheDetectionsOnItsTimer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	for _, j := range upkeepJobs(root, upkeep.Job{Name: "posture"}) {
		if j.Name == "detect" {
			return
		}
	}
	t.Error("the server's timer does not run the detections")
}
