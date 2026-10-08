// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/odp"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/posture"
)

// as runs a command as the holder of a token, the way --token would.
func as(t *testing.T, secret string, run func() error) error {
	t.Helper()
	old := flagToken
	flagToken = secret
	defer func() { flagToken = old }()
	return run()
}

func twoAdmins(t *testing.T) (root, dana, lee string) {
	t.Helper()
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	root = t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	for _, who := range []string{"dana", "lee"} {
		if err := cmdAuth(root, []string{"grant", who, "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	dana, _, err = ts.Issue("dana", "dana", auth.RoleAdmin, "", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	lee, _, err = ts.Issue("lee", "lee", auth.RoleAdmin, "", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	return root, dana, lee
}

func pendingID(t *testing.T, root string) string {
	t.Helper()
	pol, err := odp.Load(paramsPath(root))
	if err != nil || len(pol.Proposals) == 0 {
		t.Fatalf("no proposal: %v", err)
	}
	return pol.Proposals[len(pol.Proposals)-1].ID
}

// One proposes, another approves, the settings rise to meet it, nobody
// sets them below it, and upkeep puts back a hand edit.
func TestThePolicyTakesTwoAndHoldsTheSettings(t *testing.T) {
	root, dana, lee := twoAdmins(t)

	if err := as(t, dana, func() error {
		return policyPropose(root, []string{"ac-12_odp=4 hours", "ac-07_odp.01=3", "--reason", "audit finding 12"})
	}); err != nil {
		t.Fatal(err)
	}
	id := pendingID(t, root)
	if err := as(t, dana, func() error { return policyDecide(root, "approve", []string{id}) }); !errors.Is(err, odp.ErrSameAdministrator) {
		t.Fatalf("the proposer approved their own change: %v", err)
	}
	if err := as(t, lee, func() error { return policyDecide(root, "approve", []string{id}) }); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Raw("session.max") != "4h" || cfg.Raw("auth.throttle.after") != "3" {
		t.Fatalf("not raised: session.max=%s after=%s", cfg.Raw("session.max"), cfg.Raw("auth.throttle.after"))
	}

	var below *config.ErrBelowPolicy
	if err := cfg.Set("session.max", "6h", "the night shift", "dana"); !errors.As(err, &below) {
		t.Fatalf("a setting went below the policy: %v", err)
	}
	if err := cfg.Set("session.max", "2h", "", "dana"); err != nil {
		t.Fatalf("stricter than the policy was refused: %v", err)
	}

	// By hand, below it; upkeep raises it and says so in the log.
	if err := os.WriteFile(configPath(root), []byte(`{"values":{"session.max":"10h"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	raised, err := enforcePolicy(root, "quilzo")
	if err != nil || strings.Join(raised, ",") != "auth.throttle.after,session.max" {
		t.Fatalf("raised %v, %v", raised, err)
	}
	if cfg, _ := loadConfig(root); cfg.Raw("session.max") != "4h" {
		t.Fatalf("still %s", cfg.Raw("session.max"))
	}
	events, _ := audit.Read(auditPath(root))
	var actions []string
	for _, e := range events {
		actions = append(actions, e.Action)
	}
	for _, want := range []string{"policy.proposed", "policy.refused", "policy.approved", "policy.enforced"} {
		if !strings.Contains(strings.Join(actions, " "), want) {
			t.Errorf("no %s in the log: %v", want, actions)
		}
	}
	if st := Observe(root, t.TempDir(), posture.ServerFacts{}); !st.Parameters.Checked || len(st.Parameters.Unmet) != 0 {
		t.Fatalf("posture: %+v", st.Parameters)
	}
}

// What cannot be kept is refused at import, and the rest is proposed.
func TestAnImportedPlanIsReadAgainstTheClosedList(t *testing.T) {
	root, dana, _ := twoAdmins(t)
	ssp := filepath.Join(t.TempDir(), "ssp.json")
	if err := os.WriteFile(ssp, []byte(`{"system-security-plan":{"control-implementation":{"set-parameters":[
		{"param-id":"ac-02.05_odp","values":["15 minutes"]},
		{"param-id":"ac-07_odp.04","values":["24 hours"]},
		{"param-id":"pe-03_odp.01","values":["entry and exit points"]}]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := as(t, dana, func() error { return policyImport(root, []string{ssp, "--reason", "the 2026 SSP"}) })
	if err == nil || !strings.Contains(err.Error(), "cannot be kept") {
		t.Fatalf("an unkeepable parameter passed quietly: %v", err)
	}
	pol, _ := odp.Load(paramsPath(root))
	if len(pol.Proposals) != 1 || len(pol.Proposals[0].Changes) != 1 || pol.Proposals[0].Changes[0].Param != "ac-02.05_odp" {
		t.Fatalf("%+v", pol.Proposals)
	}
}

// The export is an OSCAL profile a governance tool reads back.
func TestThePolicyExportsAsAProfile(t *testing.T) {
	root, _, _ := twoAdmins(t)
	r, wpipe, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = wpipe
	err := policyExport(root, nil)
	wpipe.Close()
	os.Stdout = stdout
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	body := buf.String()
	for _, want := range []string{`"profile"`, `"set-parameters"`, `"param-id": "ac-07_odp.01"`, `"au-11_odp"`, `"indefinitely`} {
		if !strings.Contains(body, want) {
			t.Errorf("export lacks %s", want)
		}
	}
	if _, err := odp.FromOSCAL(buf.Bytes(), &odp.Policy{}); err != nil {
		t.Fatalf("the export does not read back: %v", err)
	}
}
