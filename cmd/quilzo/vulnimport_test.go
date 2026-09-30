// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/vuln"
)

const billOfStorefront = `{"bomFormat":"CycloneDX","specVersion":"1.5",
 "metadata":{"component":{"bom-ref":"app","name":"storefront","version":"1.0.0"}},
 "components":[
  {"bom-ref":"a","name":"express","version":"4.18.0","purl":"pkg:npm/express@4.18.0"},
  {"bom-ref":"b","name":"qs","version":"6.5.0","purl":"pkg:npm/qs@6.5.0"},
  {"bom-ref":"c","name":"net","version":"v0.38.0","purl":"pkg:golang/golang.org/x/net@v0.38.0"},
  {"bom-ref":"d","name":"handwritten","version":"1.0.0"}],
 "dependencies":[{"ref":"app","dependsOn":["a","c"]},{"ref":"a","dependsOn":["b"]}]}`

func osvRecord(id, eco, pkg, events, extra string) string {
	return `{"id":"` + id + `","summary":"something is wrong","published":"2026-01-02T00:00:00Z",` +
		`"affected":[{"package":{"ecosystem":"` + eco + `","name":"` + pkg + `"},` +
		`"ranges":[{"type":"SEMVER","events":[` + events + `]}]}]` + extra + `}`
}

func importSite(t *testing.T) (root, dir string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root, dir = t.TempDir(), t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	return root, dir
}

func put(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func advisoryByID(t *testing.T, root, id string) (vuln.Advisory, bool) {
	t.Helper()
	all, err := loadAdvisories(storedAdvisories(root))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range all {
		if a.ID == id {
			return a, true
		}
	}
	return vuln.Advisory{}, false
}

func TestABillReplacesOneAssetAndLeavesTheOthers(t *testing.T) {
	root, dir := importSite(t)
	bill := put(t, filepath.Join(dir, "bom.json"), billOfStorefront)
	if err := cmdVuln(root, []string{"import", "--bom", bill}); err == nil {
		t.Fatal("a bill was imported as no asset in particular")
	}
	for _, asset := range []string{"repo:storefront", "repo:admin"} {
		if err := cmdVuln(root, []string{"import", "--bom", bill, "--where",
			asset}); err != nil {
			t.Fatal(err)
		}
	}
	inv, _ := loadInventory(storedInventory(root))
	if len(inv) != 6 {
		t.Fatalf("%d components; three with a package URL on each of two "+
			"assets", len(inv))
	}
	direct := map[string]bool{}
	for _, c := range inv {
		direct[c.Name] = c.Direct
	}
	if !direct["express"] || direct["qs"] {
		t.Errorf("direct: %v; express is chosen and qs comes with it", direct)
	}
	// Again, for one asset: that asset's three are replaced, not added.
	if err := cmdVuln(root, []string{"import", "--bom", bill, "--where",
		"repo:admin"}); err != nil {
		t.Fatal(err)
	}
	if inv, _ = loadInventory(storedInventory(root)); len(inv) != 6 {
		t.Errorf("a second import of one asset left %d components", len(inv))
	}
}

func TestAdvisoriesAreKeptOnlyForWhatIsInstalledAndRememberWhenTheyWereLearned(t *testing.T) {
	root, dir := importSite(t)
	bill := put(t, filepath.Join(dir, "bom.json"), billOfStorefront)
	osv := filepath.Join(dir, "osv")
	put(t, filepath.Join(osv, "GHSA-1.json"), osvRecord("GHSA-1", "npm",
		"express", `{"introduced":"0"},{"fixed":"4.21.3"}`, `,"aliases":["CVE-2026-4410"]`))
	put(t, filepath.Join(osv, "GHSA-2.json"), osvRecord("GHSA-2", "npm",
		"left-pad", `{"introduced":"0"},{"fixed":"1.3.0"}`, ""))
	put(t, filepath.Join(osv, "GHSA-3.json"), osvRecord("GHSA-3", "npm",
		"qs", `{"introduced":"0"},{"fixed":"6.9.0"}`, `,"withdrawn":"2026-02-01T00:00:00Z"`))
	// A Go module, whose installed version carries a v the advisory's does not.
	put(t, filepath.Join(osv, "GO-1.json"), osvRecord("GO-1", "Go",
		"golang.org/x/net", `{"introduced":"0"},{"fixed":"0.41.0"}`, ""))
	// Affected up to a version the installed one is past: not a finding.
	put(t, filepath.Join(osv, "GHSA-4.json"), osvRecord("GHSA-4", "npm",
		"qs", `{"introduced":"0"},{"last_affected":"6.4.9"}`, ""))
	put(t, filepath.Join(osv, "notes.txt"), "not an advisory")
	put(t, filepath.Join(osv, "broken.json"), "{not json")

	if err := cmdVuln(root, []string{"import", "--osv", osv}); err == nil {
		t.Fatal("advisories were imported against no inventory")
	}
	if err := cmdVuln(root, []string{"import", "--bom", bill, "--where",
		"repo:storefront", "--osv", osv}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"CVE-2026-4410": true, "GHSA-2": false,
		"GHSA-3": false, "GO-1": true, "GHSA-4": true} {
		if _, got := advisoryByID(t, root, id); got != want {
			t.Errorf("%s stored: %v, want %v", id, got, want)
		}
	}
	now := time.Now().UTC()
	v, err := loadVulnView(root, now)
	if err != nil {
		t.Fatal(err)
	}
	open := map[string]bool{}
	for _, e := range v.Live() {
		open[e.Advisory.ID] = true
	}
	if !open["CVE-2026-4410"] || !open["GO-1"] {
		t.Errorf("the queue holds %v; express 4.18.0 and x/net v0.38.0 are "+
			"both before their fixes", open)
	}
	if open["GHSA-4"] {
		t.Error("qs 6.5.0 was reported for an advisory that stops at 6.4.9")
	}

	// A later import does not reset the day it was learned, which is the
	// day every deadline runs from.
	all, _ := loadAdvisories(storedAdvisories(root))
	for i := range all {
		all[i].Known = now.Add(-40 * 24 * time.Hour)
	}
	if err := writeJSONL(storedAdvisories(root), all); err != nil {
		t.Fatal(err)
	}
	if err := cmdVuln(root, []string{"import", "--osv", osv}); err != nil {
		t.Fatal(err)
	}
	if a, _ := advisoryByID(t, root, "CVE-2026-4410"); now.Sub(a.Known) < 39*24*time.Hour {
		t.Errorf("a second import moved the day it was learned to %s", a.Known)
	}
	// Withdrawn after it was stored: removed, not left.
	put(t, filepath.Join(osv, "GHSA-1.json"), osvRecord("GHSA-1", "npm",
		"express", `{"introduced":"0"},{"fixed":"4.21.3"}`, `,"withdrawn":"2026-09-01T00:00:00Z"`))
	if err := cmdVuln(root, []string{"import", "--osv", osv}); err != nil {
		t.Fatal(err)
	}
	if _, still := advisoryByID(t, root, "CVE-2026-4410"); still {
		t.Error("a withdrawn advisory is still in the store")
	}
}

func TestExploitationAndProbabilityAreJoinedByAliasAndSurviveARefresh(t *testing.T) {
	root, dir := importSite(t)
	bill := put(t, filepath.Join(dir, "bom.json"), billOfStorefront)
	one := put(t, filepath.Join(dir, "GHSA-1.json"), osvRecord("GHSA-1", "npm",
		"express", `{"introduced":"0"},{"fixed":"4.21.3"}`, `,"aliases":["CVE-2026-4410"]`))
	kev := put(t, filepath.Join(dir, "kev.json"), `{"vulnerabilities":[
	 {"cveID":"CVE-2026-4410","dateAdded":"2026-09-20","knownRansomwareCampaignUse":"Known"},
	 {"cveID":"CVE-2020-0001","dateAdded":"2020-01-01"}]}`)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("#model_version:v2025.03.14,score_date:2026-09-29T00:00:00+0000\n" +
		"cve,epss,percentile\nCVE-2026-4410,0.4321,0.97\nCVE-2020-0001,0.9,0.99\n"))
	zw.Close()
	epss := put(t, filepath.Join(dir, "epss.csv.gz"), gz.String())

	if err := cmdVuln(root, []string{"import", "--bom", bill, "--where",
		"repo:storefront", "--osv", one, "--kev", kev, "--epss", epss}); err != nil {
		t.Fatal(err)
	}
	a, _ := advisoryByID(t, root, "CVE-2026-4410")
	if yes, who := a.Attested(); !yes || who[0] != KEVSource ||
		a.Exploited[0].Note == "" {
		t.Errorf("not attested through its alias: %+v", a.Exploited)
	}
	if a.EPSS != 0.4321 || a.EPSSAt.Format("2006-01-02") != "2026-09-29" {
		t.Errorf("EPSS %v as of %s", a.EPSS, a.EPSSAt)
	}
	// Refreshing the advisories keeps what the other two feeds said.
	if err := cmdVuln(root, []string{"import", "--osv", one}); err != nil {
		t.Fatal(err)
	}
	if a, _ = advisoryByID(t, root, "CVE-2026-4410"); len(a.Exploited) != 1 || a.EPSS != 0.4321 {
		t.Errorf("an advisory refresh dropped the enrichment: %+v", a)
	}
	// Twice is still one attestation, and off the list is off.
	if err := cmdVuln(root, []string{"import", "--kev", kev}); err != nil {
		t.Fatal(err)
	}
	if a, _ = advisoryByID(t, root, "CVE-2026-4410"); len(a.Exploited) != 1 {
		t.Errorf("%d attestations after importing the same catalogue twice",
			len(a.Exploited))
	}
	gone := put(t, filepath.Join(dir, "kev2.json"),
		`{"vulnerabilities":[{"cveID":"CVE-2020-0001","dateAdded":"2020-01-01"}]}`)
	if err := cmdVuln(root, []string{"import", "--kev", gone}); err != nil {
		t.Fatal(err)
	}
	if a, _ = advisoryByID(t, root, "CVE-2026-4410"); len(a.Exploited) != 0 {
		t.Error("still attested by a catalogue that no longer lists it")
	}

	// The files that would quietly make things look better are refused.
	for name, body := range map[string]string{
		"empty catalogue": `{"vulnerabilities":[]}`,
	} {
		f := put(t, filepath.Join(dir, "bad.json"), body)
		if cmdVuln(root, []string{"import", "--kev", f}) == nil {
			t.Errorf("%s was imported", name)
		}
	}
	for name, body := range map[string]string{
		"no date":        "cve,epss,percentile\nCVE-2026-4410,0.1,0.5\n",
		"a percentage":   "#score_date:2026-09-29T00:00:00+0000\ncve,epss\nCVE-2026-4410,43.2\n",
		"nothing scored": "#score_date:2026-09-29T00:00:00+0000\ncve,epss\n",
	} {
		f := put(t, filepath.Join(dir, "bad.csv"), body)
		if cmdVuln(root, []string{"import", "--epss", f}) == nil {
			t.Errorf("EPSS with %s was imported", name)
		}
	}
	if a, _ = advisoryByID(t, root, "CVE-2026-4410"); a.EPSS != 0.4321 {
		t.Error("a refused file changed a score")
	}
}

// The archive osv.dev publishes, read without writing any of it anywhere.
func TestAnArchiveIsReadInPlaceAndItsNamesAreOnlyNames(t *testing.T) {
	root, dir := importSite(t)
	bill := put(t, filepath.Join(dir, "bom.json"), billOfStorefront)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, body string) {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(body))
	}
	add("GHSA-1.json", osvRecord("GHSA-1", "npm", "express",
		`{"introduced":"0"},{"fixed":"4.21.3"}`, ""))
	add("../../escape.json", osvRecord("GHSA-9", "npm", "qs",
		`{"introduced":"0"},{"fixed":"6.9.0"}`, ""))
	add("README.md", "not an advisory")
	add("broken.json", "{")
	zw.Close()
	archive := put(t, filepath.Join(dir, "all.zip"), buf.String())
	if err := cmdVuln(root, []string{"import", "--bom", bill, "--where",
		"repo:storefront", "--osv", archive}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"GHSA-1", "GHSA-9"} {
		if _, ok := advisoryByID(t, root, id); !ok {
			t.Errorf("%s was not read from the archive", id)
		}
	}
	for _, p := range []string{filepath.Join(dir, "..", "escape.json"),
		filepath.Join(root, "..", "escape.json"), "escape.json"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("an archive entry was written to %s", p)
		}
	}
}

// Two databases publish the same CVE under their own names. It is one
// vulnerability: one row, named by the CVE, with the ranges of both.
func TestTheSameCVEFromTwoDatabasesIsOneRow(t *testing.T) {
	root, dir := importSite(t)
	bill := put(t, filepath.Join(dir, "bom.json"), billOfStorefront)
	osv := filepath.Join(dir, "osv")
	put(t, filepath.Join(osv, "GHSA-1.json"), osvRecord("GHSA-1", "npm",
		"express", `{"introduced":"0"},{"fixed":"4.21.3"}`, `,"aliases":["CVE-2026-4410"]`))
	put(t, filepath.Join(osv, "OTHER-7.json"), osvRecord("OTHER-7", "npm",
		"qs", `{"introduced":"0"},{"fixed":"6.9.0"}`, `,"aliases":["CVE-2026-4410","GHSA-1"]`))
	for i := 0; i < 2; i++ {
		// Twice: a refresh neither doubles the ranges nor loses one.
		if err := cmdVuln(root, []string{"import", "--bom", bill, "--where",
			"repo:storefront", "--osv", osv}); err != nil {
			t.Fatal(err)
		}
		all, _ := loadAdvisories(storedAdvisories(root))
		if len(all) != 1 || all[0].ID != "CVE-2026-4410" {
			t.Fatalf("stored: %+v", all)
		}
		if len(all[0].Affects) != 2 {
			t.Errorf("pass %d: %d ranges; express from one database and "+
				"qs from the other", i, len(all[0].Affects))
		}
		names := map[string]bool{}
		for _, id := range all[0].Aliases {
			names[id] = true
		}
		if !names["GHSA-1"] || !names["OTHER-7"] || names["CVE-2026-4410"] {
			t.Errorf("aliases: %v", all[0].Aliases)
		}
	}
	v, _ := loadVulnView(root, time.Now().UTC())
	if got := len(vuln.Groups(v.Live())); got != 1 {
		t.Errorf("%d vulnerabilities in the queue for one CVE", got)
	}
	// One database withdraws its record; the other still stands behind it.
	put(t, filepath.Join(osv, "OTHER-7.json"), osvRecord("OTHER-7", "npm",
		"qs", `{"introduced":"0"},{"fixed":"6.9.0"}`,
		`,"aliases":["CVE-2026-4410"],"withdrawn":"2026-09-01T00:00:00Z"`))
	if err := cmdVuln(root, []string{"import", "--osv", osv}); err != nil {
		t.Fatal(err)
	}
	all, _ := loadAdvisories(storedAdvisories(root))
	if len(all) != 1 || len(all[0].Affects) != 1 ||
		all[0].Affects[0].Package != "express" {
		t.Errorf("after one database withdrew: %+v", all)
	}
}
