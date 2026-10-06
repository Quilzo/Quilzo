// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package odp

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/oscal"
)

func TestPeriodsAsTheyAreWritten(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"15 minutes": 15 * time.Minute, "one hour": time.Hour, "8 hours": 8 * time.Hour,
		"90 days": 90 * day, "1 year": year, "a year": year, "PT15M": 15 * time.Minute,
		"P90D": 90 * day, "P1Y": year, "p1dt12h": 36 * time.Hour, "15m": 15 * time.Minute,
		"1 day, 12 hours": 36 * time.Hour, "15 minutes of inactivity": 15 * time.Minute,
		"2 weeks": 14 * day,
	} {
		got, err := ParsePeriod(in)
		if err != nil || got != want {
			t.Errorf("%q: %v %v, want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "at the end of the day", "15", "minutes", "P", "PT", "P1H", "PT1D", "fifteen", "1 fortnight"} {
		if _, err := ParsePeriod(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if Words(15*time.Minute) != "15 minutes" || Words(time.Hour) != "1 hour" || Words(year) != "1 year" || Words(90*day) != "90 days" {
		t.Error("words")
	}
}

// What can be kept is accepted; what cannot is refused when declared.
func TestTheListIsClosedAndEachDeclarationCanBeKept(t *testing.T) {
	ok := map[string]string{
		"ac-07_odp.01": "5", "ac-02.05_odp": "15 minutes", "ac-12_odp": "8 hours",
		"ia-05_odp.01": "365 days", "au-11_odp": "6 years", "ac-07_odp.02": "15 minutes",
		"ac-07_odp.03": "delay next logon prompt per {{ insert: param, ac-07_odp.05 }}\nnotify system administrator",
	}
	for id, v := range ok {
		p, _ := Lookup(id)
		if err := p.Check(v); err != nil {
			t.Errorf("%s=%q refused: %v", id, v, err)
		}
	}
	refused := map[string]string{
		"ac-07_odp.02": "1 day",       // counted over an hour, not a day
		"ac-07_odp.04": "24 hours",    // a hard lockout lasts an hour
		"ac-07_odp.05": "exponential", // described, not declared
		"ac-12_odp":    "13 hours",    // longer than any session may last
		"ac-02.05_odp": "1 minute",    // shorter than the floor on idling
		"ac-07_odp.03": "lock the account or node until released by an administrator",
		"ac-07_odp.01": "five",
	}
	for id, v := range refused {
		p, _ := Lookup(id)
		if err := p.Check(v); err == nil {
			t.Errorf("%s=%q accepted", id, v)
		}
	}
	var pol Policy
	if _, err := pol.Propose([]Change{{Param: "ac-02_odp.01", Value: "x"}}, "r", "a", "", time.Now()); err == nil ||
		!strings.Contains(err.Error(), "ac-07_odp.01") {
		t.Fatalf("an unknown parameter: %v", err)
	}
}

// The second administrator is a different one, unless there is only one.
func TestChangingThePolicyTakesTwo(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	var pol Policy
	if _, err := pol.Propose([]Change{{Param: "ac-07_odp.01", Value: "3"}}, "", "dana", "", now); err == nil {
		t.Fatal("a proposal without a reason")
	}
	pr, err := pol.Propose([]Change{{Param: "AC-07_ODP.01", Value: " 3 "}}, "audit finding 12", "dana", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pol.Decide(pr.ID, "dana", true, false, now); !errors.Is(err, ErrSameAdministrator) {
		t.Fatalf("the proposer approved: %v", err)
	}
	if _, err := pol.Withdraw(pr.ID, "lee"); err == nil {
		t.Fatal("somebody else withdrew it")
	}
	if _, err := pol.Decide(pr.ID, "lee", true, false, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	d, ok := pol.Find("ac-07_odp.01")
	if !ok || d.Value != "3" || d.By != "dana" || d.ApprovedBy != "lee" || d.Alone {
		t.Fatalf("%+v", d)
	}
	late, _ := pol.Propose([]Change{{Param: "ac-12_odp", Value: "4 hours"}}, "r", "dana", "", now)
	if _, err := pol.Decide(late.ID, "lee", true, false, now.Add(ProposalLife+time.Minute)); err == nil {
		t.Fatal("an expired proposal was approved")
	}
	alone, _ := pol.Propose([]Change{{Param: "ac-12_odp", Value: "4 hours"}}, "r", "dana", "", now)
	if _, err := pol.Decide(alone.ID, "dana", true, true, now); err != nil {
		t.Fatal(err)
	}
	if d, _ := pol.Find("ac-12_odp"); !d.Alone {
		t.Fatal("approved alone and not recorded as such")
	}
	gone, _ := pol.Propose([]Change{{Param: "ac-12_odp", Value: ""}}, "r", "dana", "", now)
	if _, err := pol.Decide(gone.ID, "lee", true, false, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := pol.Find("ac-12_odp"); ok {
		t.Fatal("a removal did not remove")
	}
	path := filepath.Join(t.TempDir(), "parameters.json")
	if err := Save(path, &pol); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil || len(back.Declared) != 1 {
		t.Fatalf("%v %+v", err, back)
	}
}

// A declaration is a floor: stricter is allowed, weaker is not, and the
// switches a declared action needs cannot be turned off.
func TestADeclarationIsAFloorUnderItsSetting(t *testing.T) {
	pol := &Policy{Declared: []Declared{
		{Param: "ac-07_odp.01", Value: "5"},
		{Param: "ac-02.05_odp", Value: "30 minutes"},
		{Param: "ac-07_odp.03", Value: "lock the account or node for {{ insert: param, ac-07_odp.04 }}"},
	}}
	cfg := config.New().WithFloors(Floors(pol))
	if err := cfg.Set("auth.throttle.after", "3", "", "dana"); err != nil {
		t.Fatalf("stricter refused: %v", err)
	}
	var below *config.ErrBelowPolicy
	if err := cfg.Set("auth.throttle.after", "8", "a reason", "dana"); !errors.As(err, &below) || below.Floor.Param != "ac-07_odp.01" {
		t.Fatalf("weaker allowed with a reason: %v", err)
	}
	if err := cfg.Set("auth.throttle", "false", "a reason", "dana"); !errors.As(err, &below) {
		t.Fatalf("the throttle the limit depends on was turned off: %v", err)
	}
	if err := cfg.Set("session.idle", "0s", "", "dana"); err == nil {
		t.Fatal("idle sign-out turned off under a policy requiring it")
	}
	if err := cfg.Unset("session.idle"); err == nil {
		t.Fatal("unset to a default below the floor")
	}

	// Below the floor by hand: Unmet says so, and Enforce says what to set.
	unmet := config.New().WithFloors(Floors(pol))
	if len(unmet.Unmet()) == 0 {
		t.Fatal("defaults below the policy (idle 0, no hard lockout) are not unmet")
	}
	for _, d := range pol.Declared {
		for k, v := range Enforce(unmet, d) {
			if err := unmet.Put(k, v, "the policy", "upkeep"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if u := unmet.Unmet(); len(u) != 0 {
		t.Fatalf("still unmet after enforcing: %+v", u)
	}
	if unmet.Raw("session.idle") != "30m" || unmet.Raw("auth.lockout.hard") != "true" {
		t.Fatalf("enforced to %s / %s", unmet.Raw("session.idle"), unmet.Raw("auth.lockout.hard"))
	}
}

// Out as a profile, in from any OSCAL document, against the closed list.
func TestThePolicyTravelsAsOSCAL(t *testing.T) {
	pol := &Policy{Declared: []Declared{{Param: "ac-12_odp", Value: "4 hours"}}}
	cfg := config.New()
	sps := SetParameters(pol, cfg)
	if len(sps) != len(Params) {
		t.Fatalf("%d of %d", len(sps), len(Params))
	}
	// Declared four hours; the default session is eight, so it is not met
	// until upkeep enforces it, and the export says so rather than
	// exporting the declaration as if it were the behaviour.
	prof, err := oscal.ParameterProfile("Acme", "1", time.Now(), sps)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(prof)
	for _, want := range []string{`"param-id":"ac-12_odp"`, `"values":["4 hours"]`, `"name":"met","ns":"https://quilzo.org/ns/oscal","value":"false"`,
		`"href":"` + oscal.CatalogHref, `"oscal-version":"` + oscal.Version} {
		if !strings.Contains(string(body), want) {
			t.Errorf("profile lacks %s", want)
		}
	}

	ssp := `{"system-security-plan":{"control-implementation":{"set-parameters":[
		{"param-id":"ac-07_odp.01","values":["3"]},
		{"param-id":"ac-02_odp.06","values":["30 days"]},
		{"param-id":"ac-07_odp.04","values":["24 hours"]}],
		"implemented-requirements":[{"set-parameters":[{"param-id":"au-11_odp","values":["P6Y"]}]}]}}}`
	im, err := FromOSCAL([]byte(ssp), pol)
	if err != nil {
		t.Fatal(err)
	}
	if im.Kind != "system security plan" || len(im.Changes) != 2 || len(im.NotOurs) != 1 || len(im.Refused) != 1 {
		t.Fatalf("%+v", im)
	}
	if _, _, err := oscal.ReadSetParameters([]byte(`{"set-parameters":[{"param-id":"ac-12_odp","values":["1 hour"]},{"param-id":"AC-12_ODP","values":["2 hours"]}]}`)); err == nil {
		t.Fatal("a parameter set twice to different values was read")
	}
}

// The ids are the catalogue's: lower case, the _odp form, a known control.
func TestTheIDsAreTheCatalogues(t *testing.T) {
	for _, p := range Params {
		if p.ID != strings.ToLower(p.ID) || !strings.Contains(p.ID, "_odp") {
			t.Errorf("%s is not an OSCAL parameter id", p.ID)
		}
		ctl := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(p.Control, "(", "."), ")", ""))
		parts := strings.SplitN(ctl, "-", 2)
		want := parts[0] + "-" + pad(parts[1])
		if !strings.HasPrefix(p.ID, want+"_odp") {
			t.Errorf("%s does not belong to %s (want prefix %s)", p.ID, p.Control, want)
		}
		if p.How == Set {
			if p.Kind != Choice {
				if _, ok := config.Lookup(p.Setting); !ok {
					t.Errorf("%s names setting %q, which does not exist", p.ID, p.Setting)
				}
			}
		}
	}
}

// pad writes "7" as "07" and "2.5" as "02.05", as the catalogue's ids do.
func pad(s string) string {
	parts := strings.Split(s, ".")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ".")
}
