// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package boundary

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/source"
)

// TestOnlyTheCollectorReachesOutward.
//
// The distinction the package exists for. If more than one part were
// outward-facing, the line would be in the wrong place.
func TestOnlyTheCollectorReachesOutward(t *testing.T) {
	var outward []string
	for _, p := range Parts() {
		if p.Side.Outward() {
			outward = append(outward, p.Name)
		}
	}
	if len(outward) != 1 || outward[0] != "collector" {
		t.Fatalf("outward parts = %v", outward)
	}
	for _, p := range Parts() {
		if p.Name == "collector" {
			if p.Generalises() {
				t.Fatal("the collector's argument was marked as one that " +
					"generalises, which would mean separating everything")
			}
			continue
		}
		if !p.Generalises() {
			t.Errorf("%s does not generalise; only the collector should "+
				"be special", p.Name)
		}
	}
}

// TestEveryPartSaysHowItIsStoppedFromRewritingItsOwnRecord.
//
// The argument that does generalise, and it is already answered without
// separating anything.
func TestEveryPartSaysHowItIsStoppedFromRewritingItsOwnRecord(t *testing.T) {
	for _, p := range Parts() {
		if strings.TrimSpace(p.Tamper) == "" {
			t.Errorf("%s does not say how it is kept from editing its own "+
				"record", p.Name)
		}
		if strings.TrimSpace(p.Holds) == "" {
			t.Errorf("%s does not say what compromising it gets somebody",
				p.Name)
		}
	}
	// The three mechanisms that answer it are all named somewhere.
	all := ""
	for _, p := range Parts() {
		all += " " + p.Tamper
	}
	for _, want := range []string{"logd", "spool", "chain"} {
		if !strings.Contains(all, want) {
			t.Errorf("no part credits %s, and all three are what makes "+
				"separation unnecessary elsewhere", want)
		}
	}
}

// TestTheExpensivePairingIsNamedSpecifically.
//
// A rule that separates everything is not advice. The useful answer names
// the one pairing that costs something.
func TestTheExpensivePairingIsNamedSpecifically(t *testing.T) {
	why, ok := Together("collector", "application")
	if !ok {
		t.Fatal("the pairing that matters is not described")
	}
	for _, want := range []string{"blast radius", "every platform"} {
		if !strings.Contains(why, want) {
			t.Fatalf("why = %q", why)
		}
	}

	// And the pairings that cost nothing say so, rather than being
	// discouraged by a blanket rule.
	free, ok := Together("detection", "vulnerability")
	if !ok {
		t.Fatal("no answer for two analysing parts")
	}
	if !strings.Contains(free, "costs nothing") {
		t.Fatalf("two read-only parts were discouraged: %q", free)
	}

	if _, ok := Together("collector", "collector"); ok {
		t.Fatal("a part was compared with itself")
	}
	if _, ok := Together("collector", "nonsense"); ok {
		t.Fatal("an unknown part was compared")
	}
}

// TestTheCredentialTableCoversEverySourceThisProgramReads.
//
// A source that can be collected and has no entry here is a credential
// nobody has thought about.
func TestTheCredentialTableCoversEverySourceThisProgramReads(t *testing.T) {
	var missing []string
	for _, s := range source.Known() {
		name := s.Issuer + "/" + s.Stream
		if _, ok := CredentialFor(name); !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf(
			"these sources can be collected and nothing says what "+
				"credential that costs: %s", strings.Join(missing, ", "))
	}
	// And nothing in the table names a source that does not exist.
	for _, c := range Credentials() {
		issuer, stream, _ := strings.Cut(c.Source, "/")
		if _, ok := source.Find(issuer, stream); !ok {
			t.Errorf("%q is in the credential table and is not a source",
				c.Source)
		}
	}
}

// TestSomePlatformsCannotBeNarrowedAndThatIsTheFinding.
func TestSomePlatformsCannotBeNarrowedAndThatIsTheFinding(t *testing.T) {
	var broad []string
	for _, c := range Credentials() {
		if strings.TrimSpace(c.Narrowest) == "" {
			t.Errorf("%s does not say what the narrowest credential is",
				c.Source)
		}
		if c.Narrowness == Broader {
			broad = append(broad, c.Source)
			if strings.TrimSpace(c.Reach) == "" {
				t.Errorf("%s carries more than reading and does not say "+
					"what", c.Source)
			}
		}
	}
	if len(broad) == 0 {
		t.Fatal("nothing in the table carries more than reading, which " +
			"would mean the table is describing a world that does not " +
			"exist")
	}
	// GitHub is the case worth remembering: the log-only scope had to be
	// asked for, which is why the others are the way they are.
	gh, _ := CredentialFor("github/audit")
	if gh.Narrowness != LogOnly {
		t.Fatalf("github = %s", gh.Narrowness)
	}
	if !strings.Contains(gh.Note, "did not exist until it was asked for") {
		t.Fatalf("note = %q", gh.Note)
	}
}

// TestConcentrationIsTheSumNobodyComputes.
func TestConcentrationIsTheSumNobodyComputes(t *testing.T) {
	var all []string
	for _, s := range source.Known() {
		all = append(all, s.Issuer+"/"+s.Stream)
	}
	c := Across(all)
	if c.Sources != len(all) {
		t.Fatalf("covered %d of %d", c.Sources, len(all))
	}
	if c.Remote() >= c.Sources {
		t.Fatal("every source was counted as needing a remote credential; " +
			"a local file needs none")
	}
	if c.Broader == 0 {
		t.Fatal("nothing was counted as unfixable")
	}
	why := c.Why()
	for _, want := range []string{"Compromising the collector reads all",
		"cannot be narrowed to reading alone", "not a configuration mistake"} {
		if !strings.Contains(why, want) {
			t.Fatalf("why does not say %q:\n%s", want, why)
		}
	}
	// A deployment collecting only local sources holds nothing.
	local := Across([]string{"auditd/events", "kubernetes/audit"})
	if local.Remote() != 0 {
		t.Fatalf("local-only remote = %d", local.Remote())
	}
	if strings.Contains(local.Why(), "cannot be narrowed") {
		t.Fatalf("a local-only deployment was warned about scopes: %s",
			local.Why())
	}
	if Across(nil).Why() != "nothing is being collected, so the collector "+
		"holds nothing" {
		t.Fatalf("empty = %q", Across(nil).Why())
	}
}

// TestTheWorstAreFirst, because a list somebody works down starts with
// what cannot be fixed.
func TestTheWorstAreFirst(t *testing.T) {
	w := Worst()
	if len(w) == 0 {
		t.Fatal("no credentials")
	}
	if w[0].Narrowness != Broader {
		t.Fatalf("the first is %s", w[0].Narrowness)
	}
	seenAcceptable := false
	for _, c := range w {
		if c.Narrowness.Acceptable() {
			seenAcceptable = true
			continue
		}
		if seenAcceptable {
			t.Fatal("an unfixable credential sorted below a fixable one")
		}
	}
}

// TestEverySideSaysWhatItIsExposedTo.
func TestEverySideSaysWhatItIsExposedTo(t *testing.T) {
	for _, s := range Sides {
		if s.Why() == string(s) {
			t.Errorf("%s explains nothing", s)
		}
	}
	if !Collect.Outward() {
		t.Fatal("collect does not reach outward")
	}
	for _, s := range []Side{Analyse, Serve, Record} {
		if s.Outward() {
			t.Errorf("%s was marked outward", s)
		}
	}
}
