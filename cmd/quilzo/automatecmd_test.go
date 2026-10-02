// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/automate"
	"github.com/quilzo/quilzo/internal/geo"
)

func geoOffices(t *testing.T, root string) {
	t.Helper()
	b, _ := json.Marshal(geoConfig{Networks: []geo.Network{
		{Prefix: "198.51.100.0/24", Place: geo.Place{Network: "London office", Kind: "office", City: "London", Country: "GB", Lat: 51.5074, Lon: -0.1278}},
		{Prefix: "203.0.113.0/24", Place: geo.Place{City: "Sydney", Country: "AU", Lat: -33.8688, Lon: 151.2093}},
		{Prefix: "192.0.2.0/24", Place: geo.Place{Network: "Corporate VPN", Kind: "vpn"}},
	}})
	if err := os.WriteFile(geoPath(root), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// London, then Sydney a moment later: the second sign-in is stepped up as
// it is made, and the run is on record. The sign-in that proves it is
// recorded and never stepped up itself.
func TestImpossibleTravelStepsTheSignInUpAsItHappens(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	geoOffices(t, root)
	if err := cmdAutomate(root, []string{"add", "impossible-travel"}); err != nil {
		t.Fatal(err)
	}
	check := signInRisk(root)
	if v := check(admin.SignInFacts{Principal: "ada", Role: auth.RoleAdmin, How: "token", Addr: "198.51.100.7"}); v.StepUp {
		t.Fatal("the first sign-in, from the office, was stepped up")
	}
	v := check(admin.SignInFacts{Principal: "ada", Role: auth.RoleAdmin, How: "token", Addr: "203.0.113.9"})
	if !v.StepUp || !strings.HasPrefix(v.Reason, "Sydney, AU") || !strings.Contains(v.Reason, "from London office") {
		t.Fatalf("Sydney a moment after London: %+v", v)
	}
	runs := settled(t, root)
	if len(runs) != 1 || runs[0].State != "done" || !runs[0].Steps[0].OK {
		t.Fatalf("runs %+v", runs)
	}
	// No mail is set up: the step says so rather than claiming it told anybody.
	if runs[0].Steps[1].OK || !strings.Contains(runs[0].Steps[1].Said, "no mail is set up") &&
		!strings.Contains(runs[0].Steps[1].Said, "no address") {
		t.Errorf("notify claimed success: %+v", runs[0].Steps[1])
	}
	if v := check(admin.SignInFacts{Principal: "ada", How: "passkey", Addr: "203.0.113.9", Verifying: true}); v.StepUp {
		t.Error("the sign-in that proves it was stepped up")
	}
	// Through the VPN, nothing is claimed about where anybody is.
	if v := check(admin.SignInFacts{Principal: "bo", How: "token", Addr: "198.51.100.8"}); v.StepUp {
		t.Error("bo's first sign-in was stepped up")
	}
	if v := check(admin.SignInFacts{Principal: "bo", How: "token", Addr: "192.0.2.4"}); v.StepUp {
		t.Error("a sign-in through the VPN was called impossible travel")
	}
}

// settled is the history once the background steps have finished, as they
// do on the server.
func settled(t *testing.T, root string) []automate.Run {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runs, _ := automationEngine(root).Runs()
		busy := false
		for _, r := range runs {
			for _, st := range r.Steps {
				busy = busy || st.Pending
			}
		}
		if !busy || time.Now().After(deadline) {
			return runs
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A rule left watching records what it would do and steps nobody up.
func TestAWatchingRuleStepsNobodyUp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	geoOffices(t, root)
	if err := cmdAutomate(root, []string{"add", "impossible-travel"}); err != nil {
		t.Fatal(err)
	}
	rules, _ := automationEngine(root).Rules()
	if err := cmdAutomate(root, []string{"mode", rules[0].ID, "watch"}); err != nil {
		t.Fatal(err)
	}
	check := signInRisk(root)
	check(admin.SignInFacts{Principal: "cy", How: "token", Addr: "198.51.100.7"})
	if v := check(admin.SignInFacts{Principal: "cy", How: "token", Addr: "203.0.113.9"}); v.StepUp {
		t.Error("a watching rule stepped a sign-in up")
	}
	runs, _ := automationEngine(root).Runs()
	if len(runs) != 1 || runs[0].State != "watched" {
		t.Errorf("runs %+v", runs)
	}
}

// The sessions a person already has are reached by a rule acting on
// something seen elsewhere: each one must then prove its person.
func TestStepUpReachesSessionsAlreadyOpen(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	ts, _ := loadTokens(root)
	for i := 0; i < 2; i++ {
		if _, _, err := ts.IssueSession("s", "dee@example.com", auth.RoleAuthor, "/", 3600e9, auth.RoleAdmin); err != nil {
			t.Fatal(err)
		}
	}
	_ = saveJSON(tokensPath(root), ts)
	said, err := automationActions(root)["step-up"].Run(automateEvent("dee@example.com"), nil)
	if err != nil || !strings.HasPrefix(said, "2 open session") {
		t.Fatalf("%q %v", said, err)
	}
	ts, _ = loadTokens(root)
	for _, tok := range ts.Snapshot() {
		if tok.Principal == "dee@example.com" && tok.StepUp == "" {
			t.Error("a session was not marked")
		}
	}
}

// A stepped-up session's secret, copied out of a browser and given to the
// command line, runs nothing.
func TestASteppedUpSessionRunsNothingFromATerminal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "ada", "admin"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	secret, tok, err := ts.IssueSession("browser", "ada", auth.RoleAdmin, "/", 3600e9, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.RequireStepUp(tok.ID, "Sydney, moments after London"); err != nil {
		t.Fatal(err)
	}
	_ = saveJSON(tokensPath(root), ts)
	t.Setenv("QUILZO_TOKEN", secret)
	for _, c := range [][]string{{"finding", "list"}, {"auth", "list"}, {"publish"}} {
		if err := authoriseCommand(root, c[0], c[1:]); err == nil {
			t.Errorf("a stepped-up session ran %v", c)
		}
	}
}

// The rules built on what the research says to check, beyond location,
// each through the real hooks: Tor, a moved session, and a person saying a
// sign-in was not them.
func TestTheSignalsBeyondLocationReachTheirRules(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	geoOffices(t, root)
	if err := os.MkdirAll(filepath.Dir(geoTorPath(root)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(geoTorPath(root), []byte("185.220.101.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tpl := range []string{"anonymous", "session-moved", "reported"} {
		if err := cmdAutomate(root, []string{"add", tpl}); err != nil {
			t.Fatal(err)
		}
	}
	check := signInRisk(root)
	if v := check(admin.SignInFacts{Principal: "eve", How: "token", Addr: "185.220.101.4"}); !v.StepUp || !strings.Contains(v.Reason, "Tor") {
		t.Errorf("a sign-in through Tor: %+v", v)
	}
	_, moved, reported, _ := sessionHooks(root)
	if v := moved(admin.SessionMove{Principal: "eve", From: admin.SessionContext{Device: "Chrome on Windows", Country: "GB"},
		To: admin.SessionContext{Device: "a script on another system", Country: "NL"}}); !v.StepUp {
		t.Errorf("a moved session was not stepped up: %+v", v)
	}
	ts, _ := loadTokens(root)
	if _, _, err := ts.IssueSession("s", "eve", auth.RoleAuthor, "/", 3600e9, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	_ = saveJSON(tokensPath(root), ts)
	reported("eve", "")
	settled(t, root)
	ts, _ = loadTokens(root)
	for _, tok := range ts.Snapshot() {
		if tok.Principal == "eve" && !tok.Revoked {
			t.Error("reporting a sign-in left a session of theirs alive")
		}
	}
}
