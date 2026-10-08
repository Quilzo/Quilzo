// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// packSite is a store with the pack installed.
func packSite(t *testing.T) (root, rules string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root = t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDetect(root, []string{"pack", "install"}); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(root, "detections")
}

// signInOn is one sign-in on one platform by one person, as collection
// would have stored it.
func signInOn(source, id, person, ip string, failed bool, at time.Time) labelled {
	d := telemetry.DispositionAllowed
	if failed {
		d = telemetry.DispositionFailed
	}
	issuer := strings.SplitN(source, "/", 2)[0]
	e := telemetry.Event{Source: source, Class: telemetry.ClassAuthentication,
		Disposition: d, Actor: telemetry.ID{Issuer: issuer, Value: id},
		Message: "sign-in", Time: at, Received: at.Add(time.Second),
		Raw: map[string]string{}}
	if person != "" {
		e.Raw["person"] = person
	}
	if ip != "" {
		e.Observables = []telemetry.Observable{{Kind: telemetry.ObservableIP, Value: ip}}
	}
	return labelled{source + " " + person, failed, e}
}

func bySource(q []finding.Finding) map[string][]finding.Finding {
	out := map[string][]finding.Finding{}
	for _, f := range q {
		out[f.Source] = append(out[f.Source], f)
	}
	return out
}

// Okta knows her by one identifier and Entra by another. Failing on both
// within the half hour is one finding about one person — and failing on
// one alone, or two people each failing once, is not.
func TestOnePersonFailingOnTwoPlatformsIsOneFindingAboutThem(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	appendEvents(t, root, []labelled{
		// Dana: two platforms, two identifiers, one address.
		signInOn("okta/system", "00u1", "dana@acme.com", "203.0.113.9", true, at(1)),
		signInOn("entra/signin", "7a1f", "dana@acme.com", "203.0.113.9", true, at(4)),
		// Sam fails twice on one platform: a typo.
		signInOn("okta/system", "00u2", "sam@acme.com", "198.51.100.7", true, at(2)),
		signInOn("okta/system", "00u2", "sam@acme.com", "198.51.100.7", true, at(3)),
		// Li fails once on Entra, Omar once on Okta: two people, not one.
		signInOn("entra/signin", "9b2c", "li@acme.com", "198.51.100.8", true, at(5)),
		signInOn("okta/system", "00u4", "omar@acme.com", "198.51.100.9", true, at(6)),
		// Mei signs in on both and it works.
		signInOn("okta/system", "00u5", "mei@acme.com", "198.51.100.10", false, at(7)),
		signInOn("entra/signin", "c3d4", "mei@acme.com", "198.51.100.10", false, at(8)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	cross := got["corr.signin-failures-across-platforms"]
	if len(cross) != 1 || cross[0].Entity.String() != "person:dana@acme.com" {
		t.Fatalf("across platforms: %+v", cross)
	}
	// The failures themselves raise nothing: they are counted, not shown.
	for _, quiet := range []string{"okta.signin-failed", "entra.signin-failed"} {
		if len(got[quiet]) != 0 {
			t.Errorf("%s raised %d findings of its own", quiet, len(got[quiet]))
		}
	}
	if len(got["corr.password-spray"]) != 0 || len(got["corr.signin-failures-one-person"]) != 0 {
		t.Errorf("a correlation fired under its threshold: %v", got)
	}
}

// One address failing against many people is a spray; many people failing
// from their own addresses is a Monday.
func TestOneAddressFailingAsManyPeopleIsASprayAndManyAddressesIsNot(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	var events []labelled
	for i := 0; i < 12; i++ {
		// One address, twelve people, two platforms.
		src, id := "okta/system", fmt.Sprintf("00u%d", i)
		if i%2 == 1 {
			src, id = "entra/signin", fmt.Sprintf("guid-%d", i)
		}
		events = append(events, signInOn(src, id, fmt.Sprintf("p%d@acme.com", i),
			"203.0.113.66", true, w0.Add(time.Duration(i)*time.Minute)))
		// Twelve other people, each from their own address.
		events = append(events, signInOn("okta/system", fmt.Sprintf("00v%d", i),
			fmt.Sprintf("q%d@acme.com", i), fmt.Sprintf("198.51.100.%d", 10+i),
			true, w0.Add(time.Duration(i)*time.Minute)))
	}
	appendEvents(t, root, events)
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	spray := bySource(queue(t, root))["corr.password-spray"]
	if len(spray) != 1 || !strings.Contains(spray[0].Entity.String(), "203.0.113.66") {
		t.Fatalf("spray: %+v", spray)
	}
}

// Her second factor is reset in Okta; the same day her GitHub login removes
// a branch protection. Two platforms, two identifiers, one person.
func TestAnIdentityChangeThenACodeChangeByOnePersonIsJoined(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow().Add(-30 * time.Hour).Truncate(24 * time.Hour)
	okta := func(who, person, eventType string, at time.Time) labelled {
		return labelled{who, true, telemetry.Event{Source: "okta/system",
			Class: telemetry.ClassAPIActivity, Disposition: telemetry.DispositionAllowed,
			Actor: telemetry.ID{Issuer: "okta", Value: who}, Message: eventType,
			Time: at, Received: at.Add(time.Second),
			Raw: map[string]string{"eventType": eventType, "person": person}}}
	}
	github := func(login, person, action string, at time.Time) labelled {
		raw := map[string]string{"action": action}
		if person != "" {
			raw["person"] = person
		}
		return labelled{login, true, telemetry.Event{Source: "github/audit",
			Class: telemetry.ClassAPIActivity, Disposition: telemetry.DispositionAllowed,
			Actor: telemetry.ID{Issuer: "github", Value: login}, Message: action,
			Time: at, Received: at.Add(time.Second), Raw: raw}}
	}
	appendEvents(t, root, []labelled{
		okta("00u1", "dana@acme.com", "user.mfa.factor.reset_all", w0.Add(time.Hour)),
		github("dana-gh", "dana@acme.com", "protected_branch.destroy", w0.Add(3*time.Hour)),
		// Sam's factor is reset and Li removes a protection: two people.
		okta("00u2", "sam@acme.com", "user.mfa.factor.reset_all", w0.Add(time.Hour)),
		github("li-gh", "li@acme.com", "protected_branch.destroy", w0.Add(2*time.Hour)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	joined := got["corr.identity-then-code"]
	if len(joined) != 1 || joined[0].Entity.String() != "person:dana@acme.com" {
		t.Fatalf("identity then code: %+v", joined)
	}
	// Each half is also a finding in its own right.
	if len(got["okta.mfa-reset"]) != 2 || len(got["github.branch-protection-removed"]) != 2 {
		t.Errorf("the single rules: %d resets, %d removals",
			len(got["okta.mfa-reset"]), len(got["github.branch-protection-removed"]))
	}
}

// Installing again leaves an edited rule alone, and a quiet rule nothing
// counts is refused rather than run in silence.
func TestThePackIsCopiedOnceAndAQuietRuleNothingCountsIsRefused(t *testing.T) {
	root, rules := packSite(t)
	edited := filepath.Join(rules, "okta.mfa-reset.json")
	b, _ := os.ReadFile(edited)
	mine := strings.Replace(string(b), `"severity": 4`, `"severity": 5`, 1)
	if err := os.WriteFile(edited, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdDetect(root, []string{"pack", "install"}); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(edited); string(after) != mine {
		t.Error("a second install overwrote a rule somebody had edited")
	}
	if err := cmdDetect(root, []string{"pack"}); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, root, []labelled{signInOn("okta/system", "00u1",
		"dana@acme.com", "", true, time.Now().UTC().Add(-time.Hour))})
	if err := os.Remove(filepath.Join(rules, "correlations.yml")); err != nil {
		t.Fatal(err)
	}
	if err := detectRun(root, []string{"--rules", rules}); err == nil ||
		!strings.Contains(err.Error(), "quiet") {
		t.Errorf("quiet rules ran with nothing counting them: %v", err)
	}
}
