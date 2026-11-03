// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/selfvuln"
	"github.com/quilzo/quilzo/internal/shield"

	"github.com/quilzo/quilzo/internal/compliance"
)

// Quilzo's own bill of materials, read the way any bill is read, names its
// standard library as the Go vulnerability database does: before, it said
// pkg:generic/go and no Go advisory could ever match it.
func TestOurOwnBillMatchesTheGoDatabase(t *testing.T) {
	s, err := compliance.Generate(time.Now())
	if err != nil {
		t.Skip("no build info")
	}
	body, err := compliance.Render(s)
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(body, &bom); err != nil {
		t.Fatalf("our own bill does not read as CycloneDX: %v", err)
	}
	found := false
	for _, c := range bom.Components {
		if strings.HasPrefix(c.PURL, "pkg:golang/stdlib@") {
			found = true
		}
	}
	if !found {
		t.Fatal("the standard library is not in our bill as the Go database names it")
	}
}

func TestASettingWeakenedByHandIsPutBackAndADecisionIsNot(t *testing.T) {
	root := shieldRoot(t)
	// Edited into the file: most of the internet may write its own address.
	if err := os.WriteFile(configPath(root), []byte(`{"values":{"network.trusted_proxies":"0.0.0.0/0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reverted, err := revertDrift(root, time.Now())
	if err != nil || len(reverted) != 1 || reverted[0].Was != "0.0.0.0/0" || !strings.Contains(reverted[0].Again, "--accept-risk") {
		t.Fatalf("%+v %v", reverted, err)
	}
	cfg, _ := loadConfig(root)
	if !cfg.IsDefault("network.trusted_proxies") {
		t.Fatal("not put back")
	}
	if b, _ := os.ReadFile(revertedPath(root)); !strings.Contains(string(b), "0.0.0.0/0") {
		t.Fatal("what it was is not kept")
	}
	// Set with a reason, it is a decision, and stays.
	if err := cfg.Set("network.trusted_proxies", "0.0.0.0/0", "a test rig behind a load balancer we do not control", "dana"); err != nil {
		t.Fatal(err)
	}
	saveConfig(root, cfg)
	if reverted, _ := revertDrift(root, time.Now()); len(reverted) != 0 {
		t.Fatalf("a decision was undone: %+v", reverted)
	}
	// Somebody was told: a case was opened for the first.
	st, _ := shield.Load(root)
	if len(st.Responses) == 0 || st.Responses[0].Playbook != "setting-reverted" {
		t.Fatalf("%+v", st.Responses)
	}
}

// flawIn is a self-check that found one flaw in this build to upgrade for.
func flawIn(id string) selfReport {
	return selfReport{Report: selfvuln.Report{Findings: []selfvuln.Finding{{ID: id,
		Summary: "a flaw in net/http", Applies: true, Decision: selfvuln.Tell}}}}
}

// mailsAbout are the messages that name what they are about.
func mailsAbout(box *mailbox, about string) int {
	n := 0
	for _, m := range box.read() {
		if strings.Contains(m.Body, about) || strings.Contains(m.Subject, about) {
			n++
		}
	}
	return n
}

// The self-check runs every hour and raises the same flaw each time; the
// playbook tells the security contact once a day. Each run used to build
// a new engine, which forgot that it had just told them, so they heard of
// the same flaw every hour.
func TestAFlawInThisBuildIsToldOnceADayNotEveryHour(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := shieldRoot(t)
	box := securityMailbox(t, root)
	now := time.Now()
	tellTheShield(root, flawIn("GO-2026-0001"), now)
	tellTheShield(root, flawIn("GO-2026-0001"), now.Add(time.Hour))
	if n := mailsAbout(box, "A flaw in this build"); n != 1 {
		t.Fatalf("two runs an hour apart told the security contact %d times", n)
	}
	// A day on, it is still there: they are reminded, as the playbook says.
	tellTheShield(root, flawIn("GO-2026-0001"), now.Add(25*time.Hour))
	if n := mailsAbout(box, "A flaw in this build"); n != 2 {
		t.Fatalf("a run a day later told the security contact %d times in all", n)
	}
}

// The same forgetting, wherever a signal was raised away from a request:
// every prompt from one caller that carried a credential mailed the
// security contact, where the playbook says once a day.
func TestACallerPastingCredentialsIsToldOnceADay(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := shieldRoot(t)
	box := securityMailbox(t, root)
	for i := 0; i < 3; i++ {
		noteMasked(root, "chatbot:help", "main", map[string]int{"secret": 1})
	}
	if n := mailsAbout(box, "A credential was in a prompt"); n != 1 {
		t.Fatalf("three prompts in a row told the security contact %d times", n)
	}
}

// kevMissing is what the posture says about the exploited catalogue, for
// this store.
func kevMissing(t *testing.T, root string) []posture.Finding {
	t.Helper()
	var found []posture.Finding
	for _, f := range posture.Scan(Observe(root, t.TempDir(), posture.ServerFacts{}), nil).Findings {
		if f.Rule == "self.kev-missing" {
			found = append(found, f)
		}
	}
	return found
}

// kevFile is CISA's catalogue as an operator fetches it, released then.
func kevFile(t *testing.T, released time.Time) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "known_exploited_vulnerabilities.json")
	body := fmt.Sprintf(`{"dateReleased":%q,"vulnerabilities":[{"cveID":"CVE-2026-0001"}]}`,
		released.UTC().Format(time.RFC3339Nano))
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Without CISA's catalogue, or with one long out of date, a flaw in this
// build that is being exploited is never contained at once, and nothing
// said so: self check showed the Go database's age and not the
// catalogue's, and no posture rule looked. Both say it now.
func TestAMissingOrOldExploitedCatalogueIsSaid(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := connectStore(t)
	var said bytes.Buffer
	w = out.New(false)
	w.Out = &said
	if err := selfCheck(root); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(said.String(), "quilzo self kev") {
		t.Errorf("self check with no catalogue says:\n%s", said.String())
	}
	if got := kevMissing(t, root); len(got) != 1 || !strings.Contains(got[0].Detail, "no catalogue") {
		t.Errorf("the posture with no catalogue: %+v", got)
	}

	old := time.Now().AddDate(0, 0, -40)
	if err := selfKEV(root, []string{kevFile(t, old)}); err != nil {
		t.Fatal(err)
	}
	said.Reset()
	if err := selfCheck(root); err != nil {
		t.Fatal(err)
	}
	if s := said.String(); !strings.Contains(s, old.UTC().Format("2 January 2006")) || !strings.Contains(s, "40 days old") {
		t.Errorf("self check with a catalogue 40 days old says:\n%s", s)
	}
	if got := kevMissing(t, root); len(got) != 1 || !strings.Contains(got[0].Detail, "40 days") {
		t.Errorf("the posture with a catalogue 40 days old: %+v", got)
	}

	recent := time.Now().AddDate(0, 0, -2)
	if err := selfKEV(root, []string{kevFile(t, recent)}); err != nil {
		t.Fatal(err)
	}
	said.Reset()
	if err := selfCheck(root); err != nil {
		t.Fatal(err)
	}
	if s := said.String(); !strings.Contains(s, recent.UTC().Format("2 January 2006")) || strings.Contains(s, "quilzo self kev") {
		t.Errorf("self check with a current catalogue says:\n%s", s)
	}
	if got := kevMissing(t, root); len(got) != 0 {
		t.Errorf("the posture with a current catalogue: %+v", got)
	}
}
