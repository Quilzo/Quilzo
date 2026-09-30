// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/indicator"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// went is one connection by one account to one address, some minutes ago.
func went(who, ip string, minutesAgo int, msg string) labelled {
	at := time.Now().UTC().Add(-time.Duration(minutesAgo) * time.Minute).
		Truncate(time.Second)
	e := signIn("proxy/egress", who, telemetry.DispositionAllowed, msg, at)
	e.Observables = []telemetry.Observable{{Kind: telemetry.ObservableIP,
		Value: ip, Name: "dst"}}
	return labelled{who, true, e}
}

func intelFindings(t *testing.T, root string) []finding.Finding {
	t.Helper()
	var out []finding.Finding
	for _, f := range queue(t, root) {
		if strings.HasPrefix(f.Source, "intel/") {
			out = append(out, f)
		}
	}
	return out
}

// The report came out today about a campaign last week: the events already
// held are read for it, and the near miss beside each is left alone.
func TestANewIndicatorIsLookedForInWhatIsAlreadyHeld(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, rules := siemSite(t, []labelled{
		went("dana", "203.0.113.9", 7*24*60, "connect"),
		went("dana", "203.0.113.9", 6*24*60, "connect"),
		went("sam", "203.0.113.90", 60, "connect to a neighbour"),
		// The listed address, written in a message by whoever could write
		// one. Not a connection to it.
		went("li", "198.51.100.1", 50, "blocked 203.0.113.9 for li"),
	})
	list := put(t, filepath.Join(t.TempDir(), "feed.txt"),
		"# feed\n203[.]0[.]113[.]9\n10.0.0.5\nevil[.]example\n")
	if err := cmdIntel(root, []string{"import", list}); err == nil {
		t.Error("a list from nobody was imported")
	}
	if err := cmdIntel(root, []string{"import", list, "--source", "cert"}); err != nil {
		t.Fatal(err)
	}
	found := intelFindings(t, root)
	if len(found) != 1 || found[0].Entity.Value != "dana" || found[0].Seen != 2 {
		t.Fatalf("the look back found %+v; dana connected twice and nobody "+
			"else did", found)
	}
	if !strings.Contains(found[0].Title, "203.0.113.9") ||
		!strings.Contains(found[0].Title, "cert") || !found[0].Evidence[0].Tainted {
		t.Errorf("the finding does not say what, or whose claim: %+v", found[0])
	}
	set, _ := loadIndicators(root)
	if set.Len() != 2 {
		t.Errorf("%d indicators held; the private address is not one", set.Len())
	}

	// The same list again finds nothing new and counts nothing twice.
	if err := cmdIntel(root, []string{"import", list, "--source", "cert"}); err != nil {
		t.Fatal(err)
	}
	// Then events arrive: the next run sees the new one once, and does not
	// read the old ones again.
	appendEvents(t, root, []labelled{went("dana", "203.0.113.9", 1, "connect"),
		went("omar", "203.0.113.9", 1, "connect")})
	for i := 0; i < 2; i++ {
		if err := detectRun(root, []string{"--rules", rules}); err != nil {
			t.Fatal(err)
		}
	}
	by := map[string]int{}
	for _, f := range intelFindings(t, root) {
		by[f.Entity.Value] = f.Seen
	}
	if len(by) != 2 || by["dana"] != 3 || by["omar"] != 1 {
		t.Errorf("counts %v; dana connected three times and omar once", by)
	}
	// A different indicator added later is looked for by itself: what the
	// first one already found is not read again.
	if err := cmdIntel(root, []string{"add", "198.51.100.200", "--source",
		"cert"}); err != nil {
		t.Fatal(err)
	}
	for _, f := range intelFindings(t, root) {
		if f.Entity.Value == "dana" && f.Seen != 3 {
			t.Errorf("adding another indicator counted dana's %d times", f.Seen)
		}
	}
	// A second feed saying so is one indicator with two sources.
	if err := cmdIntel(root, []string{"add", "203.0.113.9", "--source",
		"isac", "--note", "Qakbot C2"}); err != nil {
		t.Fatal(err)
	}
	set, _ = loadIndicators(root)
	var same indicator.Indicator
	for _, i := range set.All() {
		if i.Value == "203.0.113.9" {
			same = i
		}
	}
	if set.Len() != 3 || strings.Join(same.Sources, ",") != "cert,isac" {
		t.Errorf("%d held, sources %v", set.Len(), same.Sources)
	}
	if by2 := intelFindings(t, root); len(by2) != 2 || by2[0].Seen+by2[1].Seen != 4 {
		t.Error("adding a second source read the events again")
	}
	if err := cmdIntel(root, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	events, _ := audit.Read(auditPath(root))
	n := 0
	for _, e := range events {
		if e.Action == "intel.added" {
			n++
		}
	}
	if n != 4 {
		t.Errorf("%d records of indicators being added, not 4", n)
	}
}

// Past its date an indicator is about whoever holds the address now, and
// removed it matches nothing; what it already found stays.
func TestALapsedOrRemovedIndicatorFindsNothingNew(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, rules := siemSite(t, []labelled{went("dana", "203.0.113.9", 60, "connect")})
	if err := cmdIntel(root, []string{"add", "203.0.113.9", "--source", "cert"}); err != nil {
		t.Fatal(err)
	}
	if len(intelFindings(t, root)) != 1 {
		t.Fatal("the look back found nothing")
	}
	// Lapse it.
	set, _ := loadIndicators(root)
	all := set.All()
	all[0].Until = time.Now().UTC().Add(-time.Hour)
	if err := saveIndicators(root, indicator.NewSet(all)); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, root, []labelled{went("omar", "203.0.113.9", 0, "connect")})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if got := intelFindings(t, root); len(got) != 1 || got[0].Entity.Value != "dana" {
		t.Errorf("a lapsed indicator raised a finding: %+v", got)
	}
	if err := cmdIntel(root, []string{"remove", all[0].ID}); err != nil {
		t.Fatal(err)
	}
	if cmdIntel(root, []string{"remove", all[0].ID}) == nil {
		t.Error("removed twice")
	}
	if len(intelFindings(t, root)) != 1 {
		t.Error("removing an indicator removed what it had found")
	}
}

func TestAModelAddsNoIndicatorAndTheNeverOnesAreRefusedByHandToo(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, _ := siemSite(t, []labelled{went("dana", "203.0.113.9", 60, "connect")})
	now := time.Now().UTC()
	i, _ := indicator.New(indicator.IP, "203.0.113.9", "cert", "", time.Time{},
		time.Time{}, now)
	ai := &Caller{Name: "agent", Kind: audit.KindAI, Verified: true}
	if _, err := takeIndicators(root, ai, []indicator.Indicator{i},
		indicator.Report{}, now); err == nil {
		t.Error("a model added an indicator")
	}
	if removeIndicator(root, ai, i.ID) == nil {
		t.Error("a model removed an indicator")
	}
	if set, _ := loadIndicators(root); set.Len() != 0 || len(intelFindings(t, root)) != 0 {
		t.Error("the refused indicator was stored, or looked for")
	}
	for name, args := range map[string][]string{
		"a private address":  {"add", "192.168.1.1", "--source", "x"},
		"a shared domain":    {"add", "github.io", "--source", "x"},
		"nobody's claim":     {"add", "203.0.113.9"},
		"an end in the past": {"add", "203.0.113.9", "--source", "x", "--until", "2020-01-01"},
		"not anything":       {"add", "hello world", "--source", "x"},
		"the wrong kind":     {"add", "203.0.113.9", "--source", "x", "--kind", "hash"},
	} {
		if cmdIntel(root, args) == nil {
			t.Errorf("%s was added", name)
		}
	}
	// A bundle of nothing usable is an error, not a quiet success.
	empty := put(t, filepath.Join(t.TempDir(), "b.json"),
		`{"type":"bundle","objects":[{"type":"indicator","pattern":"[ipv4-addr:value = '10.0.0.1']"}]}`)
	if cmdIntel(root, []string{"import", empty, "--source", "x"}) == nil {
		t.Error("a bundle with nothing usable imported cleanly")
	}
}
