// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/vuln"
)

// vulnSite is a store with three advisories against one library on two
// machines, one of them attested as exploited.
func vulnSite(t *testing.T) (root, advs, inv string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root = t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	known := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)
	fresh := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	adv := func(id, fixed string, epss float64, extra string) string {
		return fmt.Sprintf(`{"id":%q,"summary":"something is wrong",`+
			`"known":%q,"cvss":7.5,"epss":%v,"epss_at":%q,"affects":`+
			`[{"ecosystem":"npm","package":"left-pad","introduced":"1.0.0",`+
			`"fixed":%q}]%s}`, id, known, epss, fresh, fixed, extra)
	}
	advs = filepath.Join(dir, "advisories.jsonl")
	inv = filepath.Join(dir, "inventory.jsonl")
	write := func(path string, lines ...string) {
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"),
			0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(advs, adv("CVE-2026-1001", "1.2.5", 0.10, ""),
		adv("CVE-2026-1002", "1.4.0", 0.20,
			`,"exploited":[{"by":"cisa-kev","at":"`+fresh+`"}]`),
		adv("CVE-2026-1003", "1.3.1", 0.05, ""))
	write(inv,
		`{"ecosystem":"npm","name":"left-pad","version":"1.2.0","where":{"issuer":"mdm","value":"LAPTOP-1"}}`,
		`{"ecosystem":"npm","name":"left-pad","version":"1.1.0","where":{"issuer":"mdm","value":"LAPTOP-2"}}`)
	return root, advs, inv
}

func loaded(t *testing.T) string {
	t.Helper()
	root, advs, inv := vulnSite(t)
	if err := cmdVuln(root, []string{"load", "--advisories", advs,
		"--inventory", inv}); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLoadingPutsTheListsInTheStoreAndThePlanReadsThem(t *testing.T) {
	root := loaded(t)
	now := time.Now().UTC()
	v, err := loadVulnView(root, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Advisories) != 3 || len(v.Inventory) != 2 || len(v.Live()) != 6 {
		t.Fatalf("%d advisories, %d components, %d exposures",
			len(v.Advisories), len(v.Inventory), len(v.Live()))
	}
	ups := vuln.Upgrades(v.Live(), v.Advisories, now)
	if len(ups) != 1 || ups[0].To != "1.4.0" || len(ups[0].Clears) != 3 ||
		!ups[0].Exploited {
		t.Errorf("the plan: %+v", ups)
	}
	// The day is on the trend, as counts and nothing else.
	if len(v.History) != 1 || v.History[0].Vulnerabilities != 3 {
		t.Errorf("history: %+v", v.History)
	}
	raw, _ := os.ReadFile(vulnHistoryPath(root))
	if strings.Contains(string(raw), "LAPTOP") {
		t.Error("the trend names a machine")
	}
	// The commands run against the store from a directory with no files.
	t.Chdir(t.TempDir())
	for _, args := range [][]string{{"plan"}, {"queue"},
		{"why", "CVE-2026-1002"}} {
		if err := cmdVuln(root, args); err != nil {
			t.Errorf("vuln %v: %v", args, err)
		}
	}
	events, _ := audit.Read(auditPath(root))
	found := false
	for _, e := range events {
		found = found || e.Action == "vuln.loaded"
	}
	if !found {
		t.Error("replacing the inventory left no record")
	}
}

// What is stored is what was validated: a bad line refuses the whole file
// and leaves what was there, and an empty file does not become a clean
// inventory.
func TestABadOrEmptyFileReplacesNothing(t *testing.T) {
	root := loaded(t)
	before, _ := os.ReadFile(storedInventory(root))
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.jsonl")
	os.WriteFile(bad, []byte(
		`{"ecosystem":"npm","name":"ok","version":"1.0.0","where":{"issuer":"mdm","value":"A"}}`+"\n"+
			`{"ecosystem":"npm","name":"no-version","where":{"issuer":"mdm","value":"A"}}`+"\n"), 0o600)
	if err := cmdVuln(root, []string{"load", "--inventory", bad}); err == nil {
		t.Error("a component with no version was stored")
	}
	empty := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(empty, []byte("# nothing\n\n"), 0o600)
	if err := cmdVuln(root, []string{"load", "--inventory", empty}); err == nil {
		t.Error("an empty inventory replaced a real one")
	}
	after, _ := os.ReadFile(storedInventory(root))
	if string(before) != string(after) {
		t.Error("a refused load changed what is stored")
	}
	// With nothing loaded the plan refuses rather than reporting clean.
	bare, _, _ := vulnSite(t)
	if err := cmdVuln(bare, []string{"plan"}); err == nil ||
		!strings.Contains(err.Error(), "not a clean bill") {
		t.Errorf("an unloaded store planned: %v", err)
	}
}

func TestAcceptingTakesItOutUntilADayAndAnExploitedOneForLess(t *testing.T) {
	root := loaded(t)
	now := time.Now().UTC()
	day := func(n int) string { return now.AddDate(0, 0, n).Format("2006-01-02") }

	if err := cmdVuln(root, []string{"accept", "CVE-2026-1001",
		"npm:left-pad", "--owner", "sam", "--until", day(60), "--because",
		"replaced in the November release"}); err != nil {
		t.Fatal(err)
	}
	v, _ := loadVulnView(root, now)
	if len(v.Live()) != 4 {
		t.Errorf("%d exposures still live; the accepted one is on two "+
			"machines", len(v.Live()))
	}
	if last := v.History[len(v.History)-1]; last.Accepted != 2 ||
		last.Vulnerabilities != 2 {
		t.Errorf("the trend did not follow the decision: %+v", last)
	}
	// Sixty days is too long for the one being exploited.
	err := cmdVuln(root, []string{"accept", "CVE-2026-1002", "npm:left-pad",
		"--owner", "sam", "--until", day(60), "--because", "later"})
	if err == nil || !strings.Contains(err.Error(), "being exploited") {
		t.Errorf("an exploited vulnerability was accepted for sixty days: %v",
			err)
	}
	if err := cmdVuln(root, []string{"accept", "CVE-2026-1002",
		"npm:left-pad", "--owner", "sam", "--until", day(10), "--because",
		"change window on the 8th"}); err != nil {
		t.Errorf("ten days was refused: %v", err)
	}
	for _, bad := range [][]string{
		{"accept", "CVE-2026-1003", "npm:left-pad", "--until", day(5),
			"--because", "x"}, // no owner
		{"accept", "CVE-2026-1003", "npm:left-pad", "--owner", "sam",
			"--because", "x"}, // no end
		{"accept", "CVE-2026-1003", "npm:left-pad", "--owner", "sam",
			"--until", day(200), "--because", "x"},
	} {
		if cmdVuln(root, bad) == nil {
			t.Errorf("accepted: %v", bad)
		}
	}
	events, _ := audit.Read(auditPath(root))
	accepted := 0
	for _, e := range events {
		if e.Action == "vuln.accepted" {
			accepted++
			if e.Detail["owner"] == "sam" {
				t.Error("the owner's name is in the log in clear")
			}
		}
	}
	if accepted != 2 {
		t.Errorf("%d acceptances on the record, not 2", accepted)
	}
}

// From the screen an assessment names something the store holds.
func TestAScreenAssessmentMustNameSomethingInTheStore(t *testing.T) {
	root := loaded(t)
	a := vuln.Assessment{Advisory: "CVE-1999-0001", Component: "npm:left-pad",
		Status: vuln.Fixed, At: time.Now().UTC(), By: "dana",
		Kind: audit.KindHuman, Because: "patched"}
	if recordAssessment(root, a, true) == nil {
		t.Error("an assessment of an advisory nobody loaded was stored")
	}
	a.Advisory, a.Component = "CVE-2026-1001", "npm:something-else"
	if recordAssessment(root, a, true) == nil {
		t.Error("an assessment of a package the advisory does not mention")
	}
	a.Component = "npm:left-pad"
	if err := recordAssessment(root, a, true); err != nil {
		t.Fatal(err)
	}
	a.Kind = audit.KindAI
	if recordAssessment(root, a, true) == nil {
		t.Error("a model's assessment was stored")
	}
}

func TestTheVEXDraftIsTheDecisionsWithoutTheNames(t *testing.T) {
	root := loaded(t)
	if err := cmdVuln(root, []string{"assess", "CVE-2026-1003",
		"npm:left-pad", "not_affected", "--reason",
		"vulnerable_code_not_in_execute_path", "--because",
		"ticket SEC-881", "--impact", "never called with user input"}); err != nil {
		t.Fatal(err)
	}
	pipe, read := captureStdout(t)
	err := cmdVuln(root, []string{"vex", "--author", "Example Ltd", "--id",
		"https://example.test/vex/1"})
	pipe.Close()
	text := read()
	if err != nil {
		t.Fatal(err)
	}
	var d vuln.Document
	if uerr := json.Unmarshal([]byte(text), &d); uerr != nil {
		t.Fatalf("not a document: %v\n%s", uerr, text)
	}
	if len(d.Statements) != 1 || d.Statements[0].Status != vuln.NotAffected ||
		d.Statements[0].Impact != "never called with user input" {
		t.Errorf("%+v", d.Statements)
	}
	if strings.Contains(text, "SEC-881") {
		t.Error("the internal evidence is in a document meant for outside")
	}
	if cmdVuln(root, []string{"vex"}) == nil {
		t.Error("a statement from nobody")
	}
}

// An agent gets the plan and the counts: no advisory text, no host names,
// and no way to decide anything.
func TestAnAgentReadsThePlanWithoutTextOrHosts(t *testing.T) {
	root := loaded(t)
	srv := mcp.NewServer("quilzo", "test")
	srv.Authorise = func(mcp.Operation) error { return nil }
	registerSecurityOps(srv, root, &Caller{Name: "dana",
		Kind: audit.KindHuman, Verified: true})
	text, merr := callTool(t, srv, "quilzo_read", "vuln_plan", nil)
	if merr != nil {
		t.Fatal(merr.Message)
	}
	for _, want := range []string{`"to":"1.4.0"`, "CVE-2026-1002",
		`"vulnerabilities":3`} {
		if !strings.Contains(text, want) {
			t.Errorf("the plan lacks %s:\n%s", want, text)
		}
	}
	for _, banned := range []string{"LAPTOP", "something is wrong"} {
		if strings.Contains(text, banned) {
			t.Errorf("the plan carries %q", banned)
		}
	}
	// Nothing loaded is a refusal, not an empty plan.
	bare, _, _ := vulnSite(t)
	srv2 := mcp.NewServer("quilzo", "test")
	srv2.Authorise = func(mcp.Operation) error { return nil }
	registerSecurityOps(srv2, bare, &Caller{Name: "dana",
		Kind: audit.KindHuman, Verified: true})
	if text, merr := callTool(t, srv2, "quilzo_read", "vuln_plan", nil); merr == nil &&
		!strings.Contains(text, "not a clean result") {
		t.Errorf("an unloaded store gave an agent a plan: %s", text)
	}
}
