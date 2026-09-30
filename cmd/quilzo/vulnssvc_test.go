// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/vuln"
)

// treeCSV is a table in the published shape whose outcome rises with every
// input. It is not CERT/CC's: it exists so a test knows the answer.
func treeCSV() string {
	var b strings.Builder
	b.WriteString("row,Exploitation v1.1.0,System Exposure v1.0.1," +
		"Automatable v2.0.0,Human Impact v2.0.2," +
		"\"Defer, Scheduled, Out-of-Cycle, Immediate v1.0.0\"\n")
	n := 0
	for a, x := range vuln.Exploitations {
		for e, y := range vuln.Exposures {
			for c, z := range vuln.Automatables {
				for h, w := range vuln.Impacts {
					fmt.Fprintf(&b, "%d,%s,%s,%s,%s,%s\n", n, x, y, z, w,
						vuln.Outcomes[(a*2+e+c+h)*3/10])
					n++
				}
			}
		}
	}
	return b.String()
}

func TestNoTableNoDecisionAndATableWithAHoleIsNotLoaded(t *testing.T) {
	root := loaded(t)
	v, err := loadVulnView(root, time.Now().UTC())
	if err != nil || v.Tree != nil {
		t.Fatalf("a decision table out of nowhere: %v %v", v.Tree, err)
	}
	dir := t.TempDir()
	lines := strings.Split(strings.TrimSpace(treeCSV()), "\n")
	holed := put(t, filepath.Join(dir, "holed.csv"),
		strings.Join(lines[:len(lines)-3], "\n")+"\n")
	if cmdVuln(root, []string{"ssvc-tree", holed}) == nil {
		t.Error("a table missing three rows was loaded")
	}
	if _, err := os.Stat(ssvcTreePath(root)); err == nil {
		t.Error("the refused table was stored")
	}
	good := put(t, filepath.Join(dir, "tree.csv"), treeCSV())
	if err := cmdVuln(root, []string{"ssvc-tree", good}); err != nil {
		t.Fatal(err)
	}
	if v, _ = loadVulnView(root, time.Now().UTC()); len(v.Tree) != 72 {
		t.Fatalf("%d rows loaded", len(v.Tree))
	}
	// The queue still prints, now with a decision per vulnerability.
	if err := cmdVuln(root, []string{"queue"}); err != nil {
		t.Fatal(err)
	}
}

func TestATagNarrowsADecisionAndIsAPersons(t *testing.T) {
	root := loaded(t)
	tree := put(t, filepath.Join(t.TempDir(), "tree.csv"), treeCSV())
	if err := cmdVuln(root, []string{"ssvc-tree", tree}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	decide := func() map[string]vuln.Decision {
		v, err := loadVulnView(root, now)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]vuln.Decision{}
		for _, e := range v.Live() {
			if e.Advisory.ID == "CVE-2026-1001" {
				out[e.Component.Where.String()] = v.Tree.Decide(e, v.Tags)
			}
		}
		return out
	}
	before := decide()
	if d := before["mdm:LAPTOP-1"]; d.Settled() || d.Worst == d.Best {
		t.Fatalf("with no tag the decision is %+v, not a range", d)
	}
	if err := cmdVuln(root, []string{"asset", "mdm:LAPTOP-1", "--exposure",
		"small", "--impact", "low", "--because", "a lab machine"}); err != nil {
		t.Fatal(err)
	}
	after := decide()
	one, two := after["mdm:LAPTOP-1"], after["mdm:LAPTOP-2"]
	if one.Exposure != "small" || one.Impact != "low" ||
		len(one.Unknown) != len(before["mdm:LAPTOP-1"].Unknown)-1 {
		t.Errorf("the tagged machine: %+v", one)
	}
	if two.Exposure != "" || len(two.Unknown) != len(before["mdm:LAPTOP-2"].Unknown) {
		t.Errorf("a tag on one machine changed another's: %+v", two)
	}
	// A prefix covers the rest, and the exact tag still wins.
	if err := cmdVuln(root, []string{"asset", "mdm:*", "--exposure", "open",
		"--impact", "high", "--because", "staff laptops travel"}); err != nil {
		t.Fatal(err)
	}
	after = decide()
	if after["mdm:LAPTOP-1"].Exposure != "small" || after["mdm:LAPTOP-2"].Exposure != "open" {
		t.Errorf("exact and prefix: %+v", after)
	}
	for name, args := range map[string][]string{
		"the whole estate":    {"asset", "*", "--exposure", "open", "--impact", "high", "--because", "x"},
		"no reason":           {"asset", "mdm:LAPTOP-2", "--exposure", "open", "--impact", "high"},
		"a made-up level":     {"asset", "mdm:LAPTOP-2", "--exposure", "public", "--impact", "high", "--because", "x"},
		"removing a stranger": {"asset", "mdm:NOPE", "--remove"},
	} {
		if cmdVuln(root, args) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	ai := &Caller{Name: "agent", Kind: audit.KindAI, Verified: true}
	if setAssetTag(root, ai, vuln.AssetTag{Match: "mdm:LAPTOP-2",
		Exposure: "small", Impact: "low", Because: "it looks unimportant"}) == nil {
		t.Error("a model decided how much a machine matters")
	}
	if removeAssetTag(root, ai, "mdm:*") == nil {
		t.Error("a model removed a tag")
	}
	// Refused, and nothing written: a judgement that was stored and then
	// reported as an error is a judgement in force.
	held, _ := loadAssetTags(root)
	for _, t2 := range held {
		if t2.By == "agent" {
			t.Error("the model's tag was stored anyway")
		}
	}
	if _, ok := held.For("mdm:LAPTOP-9"); !ok {
		t.Error("the model's removal took the prefix tag away anyway")
	}
	if err := cmdVuln(root, []string{"asset", "mdm:LAPTOP-1", "--remove"}); err != nil {
		t.Fatal(err)
	}
	if got := decide()["mdm:LAPTOP-1"].Exposure; got != "open" {
		t.Errorf("with its own tag removed the prefix applies: %q", got)
	}
	if err := cmdVuln(root, []string{"assets"}); err != nil {
		t.Fatal(err)
	}
}

// CISA's annotations say whether an exploit is public and whether an attack
// can be automated. "Active" in an annotation is not an attestation.
func TestAnnotationsFillTheTwoInputsAboutTheVulnerability(t *testing.T) {
	root := loaded(t)
	dir := t.TempDir()
	rec := func(id, exploitation, automatable string) string {
		return `{"cveMetadata":{"cveId":"` + id + `"},"containers":{"adp":[{"metrics":[` +
			`{"cvssV3_1":{"baseScore":9.8}},` +
			`{"other":{"type":"ssvc","content":{"id":"` + id + `","options":[` +
			`{"Exploitation":"` + exploitation + `"},{"Automatable":"` + automatable +
			`"},{"Technical Impact":"total"}]}}}]}]}}`
	}
	put(t, filepath.Join(dir, "CVE-2026-1001.json"), rec("CVE-2026-1001", "poc", "yes"))
	put(t, filepath.Join(dir, "CVE-2026-1003.json"), rec("CVE-2026-1003", "active", "no"))
	put(t, filepath.Join(dir, "CVE-2020-0001.json"), rec("CVE-2020-0001", "none", "no"))
	put(t, filepath.Join(dir, "junk.json"), `{"hello":"world"}`)
	if err := cmdVuln(root, []string{"import", "--ssvc", dir}); err != nil {
		t.Fatal(err)
	}
	a, _ := advisoryByID(t, root, "CVE-2026-1001")
	if a.Exploitation != "public poc" || a.Automatable == nil || !*a.Automatable {
		t.Errorf("CVE-2026-1001: %q %v", a.Exploitation, a.Automatable)
	}
	c, _ := advisoryByID(t, root, "CVE-2026-1003")
	if yes, _ := c.Attested(); yes || c.Exploitation != "public poc" ||
		c.Automatable == nil || *c.Automatable {
		t.Errorf("an annotation saying active became an attestation, or "+
			"was lost: %q %v %+v", c.Exploitation, c.Automatable, c.Exploited)
	}
	if b, _ := advisoryByID(t, root, "CVE-2026-1002"); b.Exploitation != "" || b.Automatable != nil {
		t.Error("an advisory nobody annotated was annotated")
	}
	// A later advisory refresh does not drop what the annotation said.
	one := put(t, filepath.Join(dir, "osv.json"),
		`{"id":"CVE-2026-1001","summary":"something is wrong","affected":`+
			`[{"package":{"ecosystem":"npm","name":"left-pad"},"ranges":`+
			`[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.5"}]}]}]}`)
	if err := cmdVuln(root, []string{"import", "--osv", one}); err != nil {
		t.Fatal(err)
	}
	if a, _ = advisoryByID(t, root, "CVE-2026-1001"); a.Exploitation != "public poc" ||
		a.Automatable == nil || !*a.Automatable {
		t.Errorf("a refresh dropped the annotation: %q %v", a.Exploitation,
			a.Automatable)
	}

	empty := t.TempDir()
	put(t, filepath.Join(empty, "junk.json"), `{"hello":"world"}`)
	if cmdVuln(root, []string{"import", "--ssvc", empty}) == nil {
		t.Error("a directory with no annotation in it imported cleanly")
	}
}
