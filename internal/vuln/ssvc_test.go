// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package vuln

import (
	"fmt"
	"strings"
	"testing"
)

// testTree is a table in the published shape with an outcome that rises
// with every input. Not CERT/CC's table: the arithmetic here is only so a
// test can say what the answer should be.
func testTree(t *testing.T) (Tree, string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("row,Exploitation v1.1.0,System Exposure v1.0.1," +
		"Automatable v2.0.0,Human Impact v2.0.2," +
		"\"Defer, Scheduled, Out-of-Cycle, Immediate v1.0.0\"\n")
	n := 0
	for a, x := range Exploitations {
		for e, y := range Exposures {
			for c, z := range Automatables {
				for h, w := range Impacts {
					score := a*2 + e + c + h // 0..10
					fmt.Fprintf(&b, "%d,%s,%s,%s,%s,%s\n", n, x, y, z, w,
						Outcomes[score*3/10])
					n++
				}
			}
		}
	}
	tree, err := ParseTree([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	return tree, b.String()
}

func TestATreeWithAHoleOrAStrangeWordIsRefused(t *testing.T) {
	_, text := testTree(t)
	lines := strings.Split(strings.TrimSpace(text), "\n")
	for name, bad := range map[string]string{
		"a row missing":           strings.Join(lines[:len(lines)-1], "\n"),
		"a row twice":             text + lines[5] + "\n",
		"an unknown outcome":      strings.Replace(text, ",defer\n", ",ignore\n", 1),
		"an unknown exposure":     strings.Replace(text, ",small,", ",tiny,", 1),
		"an unknown automatable":  strings.Replace(text, ",no,low,", ",maybe,low,", 1),
		"an unknown impact":       strings.Replace(text, ",no,low,", ",no,slight,", 1),
		"an unknown exploitation": strings.Replace(text, ",none,small,", ",rumour,small,", 1),
		"no outcome column":       strings.Replace(text, "\"Defer, Scheduled, Out-of-Cycle, Immediate v1.0.0\"", "Notes", 1),
		"only a header":           lines[0] + "\n",
		"not a table":             "hello",
	} {
		if _, err := ParseTree([]byte(bad)); err == nil {
			t.Errorf("a table with %s was accepted", name)
		}
	}
	// The older spelling of one value is the same value.
	if _, err := ParseTree([]byte(strings.ReplaceAll(text, ",public poc,", ",PoC,"))); err != nil {
		t.Errorf("poc: %v", err)
	}
}

func TestADecisionIsARangeWhenAnInputIsMissingAndSaysWhich(t *testing.T) {
	tree, _ := testTree(t)
	a := advisory("CVE-S", 7, 0.1)
	e := Exposure{Advisory: a, Component: comp("left-pad", "1.2.0", 1)}
	where := e.Component.Where.String()

	// Nothing known but that nobody attests exploitation.
	d := tree.Decide(e, nil)
	if d.Settled() || d.Best != "defer" || d.Worst == d.Best || len(d.Unknown) != 3 {
		t.Fatalf("with nothing recorded: %+v", d)
	}
	if !strings.Contains(d.Says(), "depending on") ||
		!strings.Contains(d.Says(), where) {
		t.Errorf("it does not say what is missing: %s", d.Says())
	}

	// Everything known: one answer, and it is the table's.
	yesB := true
	e.Advisory.Exploitation, e.Advisory.Automatable = "public poc", &yesB
	tags := Tags{{Match: where, Exposure: "open", Impact: "high", By: "dana",
		Because: "internet-facing"}}
	d = tree.Decide(e, tags)
	want := tree[[4]string{"public poc", "open", "yes", "high"}]
	if !d.Settled() || d.Worst != want || d.Best != want || d.Says() != want {
		t.Errorf("fully known: %+v, the table says %s", d, want)
	}

	// Attested exploitation is active, whatever the annotation says.
	e.Advisory.Exploited = []Attestation{{By: "cisa-kev", At: now}}
	e.Advisory.Exploitation = "none"
	if d = tree.Decide(e, tags); d.Exploitation != "active" ||
		d.Worst != tree[[4]string{"active", "open", "yes", "high"}] {
		t.Errorf("an attested vulnerability was decided as %+v", d)
	}
	// A narrower range is never wider than the one it narrows.
	e.Advisory.Automatable = nil
	wide := tree.Decide(e, nil)
	narrow := tree.Decide(e, tags)
	if urgency(narrow.Worst) > urgency(wide.Worst) ||
		urgency(narrow.Best) < urgency(wide.Best) {
		t.Errorf("knowing more widened the range: %+v then %+v", wide, narrow)
	}
	if !narrow.More(Decision{Worst: "defer", Best: "defer"}) {
		t.Error("ordering")
	}
	// No table, no answer.
	if d := (Tree{}).Decide(e, tags); d.Worst != "" || d.Settled() {
		t.Errorf("an empty table decided %+v", d)
	}
}

func TestAnAssetTagIsTheMostSpecificOneAndNeverTheWholeEstate(t *testing.T) {
	tags := Tags{
		{Match: "ec:*", Exposure: "controlled", Impact: "medium"},
		{Match: "ec:srv-web-*", Exposure: "open", Impact: "high"},
		{Match: "ec:srv-web-01", Exposure: "open", Impact: "very high"},
	}
	for where, want := range map[string]string{
		"ec:srv-web-01": "very high", "ec:srv-web-02": "high",
		"ec:laptop-9": "medium",
	} {
		if got, ok := tags.For(where); !ok || got.Impact != want {
			t.Errorf("%s: %+v, want %s", where, got, want)
		}
	}
	if _, ok := tags.For("mdm:MBP-1"); ok {
		t.Error("a tag for one tool's assets applied to another's")
	}
	ok := AssetTag{Match: "ec:srv-*", Exposure: "open", Impact: "high",
		By: "dana", Because: "the web tier"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AssetTag){
		"everything":           func(a *AssetTag) { a.Match = "*" },
		"every tool":           func(a *AssetTag) { a.Match = "srv*" },
		"a star in the middle": func(a *AssetTag) { a.Match = "ec:*-web" },
		"nothing":              func(a *AssetTag) { a.Match = " " },
		"an exposure not one":  func(a *AssetTag) { a.Exposure = "public" },
		"an impact not one":    func(a *AssetTag) { a.Impact = "critical" },
		"nobody":               func(a *AssetTag) { a.By = "" },
		"no reason":            func(a *AssetTag) { a.Because = " " },
	} {
		bad := ok
		change(&bad)
		if bad.Validate() == nil {
			t.Errorf("a tag for %s was accepted", name)
		}
	}
}
