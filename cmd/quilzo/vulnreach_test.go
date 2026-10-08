// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/vuln"
)

const billOfProxy = `{"bomFormat":"CycloneDX","specVersion":"1.5",
 "metadata":{"component":{"bom-ref":"app","name":"edge-proxy","version":"1.0.0"}},
 "components":[
  {"bom-ref":"a","name":"net","version":"v0.38.0","purl":"pkg:golang/golang.org/x/net@v0.38.0"},
  {"bom-ref":"b","name":"express","version":"4.18.0","purl":"pkg:npm/express@4.18.0"}],
 "dependencies":[{"ref":"app","dependsOn":["a","b"]}]}`

func goAdvisory(id, path, symbols string) string {
	specific := ""
	if path != "" {
		specific = `,"ecosystem_specific":{"imports":[{"path":"` + path +
			`","symbols":[` + symbols + `]}]}`
	}
	return `{"id":"` + id + `","summary":"something is wrong",` +
		`"affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},` +
		`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.41.0"}]}]` +
		specific + `}]}`
}

// reachSite is an asset with a Go dependency, five advisories across it,
// and source that uses the symbol one of them names.
func reachSite(t *testing.T) (root, src string) {
	t.Helper()
	root, dir := importSite(t)
	bill := put(t, filepath.Join(dir, "bom.json"), billOfProxy)
	osv := filepath.Join(dir, "osv")
	put(t, filepath.Join(osv, "GO-USED.json"), goAdvisory("GO-USED",
		"golang.org/x/net/html", `"Parse"`))
	put(t, filepath.Join(osv, "GO-UNUSED.json"), goAdvisory("GO-UNUSED",
		"golang.org/x/net/http2", `"Server.ServeConn"`))
	put(t, filepath.Join(osv, "GO-NOSYM.json"), goAdvisory("GO-NOSYM", "", ""))
	// An ecosystem whose advisories never name symbols, carrying a field
	// of the same name that means something else.
	put(t, filepath.Join(osv, "NPM-1.json"), `{"id":"NPM-1","summary":"x",`+
		`"affected":[{"package":{"ecosystem":"npm","name":"express"},`+
		`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.21.3"}]}],`+
		`"ecosystem_specific":{"imports":"see the advisory text"}}]}`)
	// And one that does name a symbol, in a language this does not read.
	// Go source cannot say whether JavaScript calls it.
	put(t, filepath.Join(osv, "NPM-2.json"), `{"id":"NPM-2","summary":"x",`+
		`"affected":[{"package":{"ecosystem":"npm","name":"express"},`+
		`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.21.3"}]}],`+
		`"ecosystem_specific":{"imports":[{"path":"express/lib/response","symbols":["redirect"]}]}}]}`)
	if err := cmdVuln(root, []string{"import", "--bom", bill, "--where",
		"repo:edge-proxy", "--osv", osv}); err != nil {
		t.Fatal(err)
	}
	src = filepath.Join(dir, "src")
	put(t, filepath.Join(src, "main.go"), `package main

import (
	"strings"

	"golang.org/x/net/html"
)

func main() { html.Parse(strings.NewReader("<p>")) }
`)
	return root, src
}

func reachOf(t *testing.T, root string) map[string]*vuln.Reach {
	t.Helper()
	v, err := loadVulnView(root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*vuln.Reach{}
	for _, e := range v.Matched {
		out[e.Advisory.ID] = e.Reach
	}
	if len(out) != 5 {
		t.Fatalf("%d advisories in the queue, not the five imported", len(out))
	}
	return out
}

func TestReachIsPerAdvisoryAndSaysNothingWhereThereIsNothingToLookFor(t *testing.T) {
	root, src := reachSite(t)
	if err := cmdVuln(root, []string{"reach", "--source", src}); err == nil {
		t.Error("source was read for no asset in particular")
	}
	if err := cmdVuln(root, []string{"reach", "--source", src, "--where",
		"repo:somewhere-else"}); err == nil {
		t.Error("a misspelt asset was reported as having nothing reachable")
	}
	if err := cmdVuln(root, []string{"reach", "--source", src, "--where",
		"repo:edge-proxy"}); err != nil {
		t.Fatal(err)
	}
	r := reachOf(t, root)
	// True positive: the source calls the symbol.
	if r["GO-USED"] == nil || !r["GO-USED"].Referenced ||
		len(r["GO-USED"].Files) == 0 {
		t.Errorf("html.Parse is called and was not found: %+v", r["GO-USED"])
	}
	// True negative: same library, a function this source never names.
	if r["GO-UNUSED"] == nil || r["GO-UNUSED"].Referenced {
		t.Errorf("http2.Server.ServeConn is not used: %+v", r["GO-UNUSED"])
	}
	// Nothing to look for is not a result, in either direction.
	if r["GO-NOSYM"] != nil || r["NPM-1"] != nil {
		t.Errorf("a verdict where no symbol was named: %+v %+v",
			r["GO-NOSYM"], r["NPM-1"])
	}
	// Nor is Go source evidence about what JavaScript calls.
	if r["NPM-2"] != nil {
		t.Errorf("an npm symbol was looked for in Go source and reported "+
			"as unused: %+v", r["NPM-2"])
	}

	// It moves the rank, in both directions, and removes nothing.
	now := time.Now().UTC()
	v, _ := loadVulnView(root, now)
	weight := map[string]float64{}
	for _, e := range v.Matched {
		if e.Silenced {
			t.Errorf("%s left the queue on a reading of source", e.Advisory.ID)
		}
		weight[e.Advisory.ID] = e.Weight(now)
	}
	if !(weight["GO-USED"] > weight["GO-NOSYM"] &&
		weight["GO-NOSYM"] > weight["GO-UNUSED"] && weight["GO-UNUSED"] > 0) {
		t.Errorf("weights %v: used above unknown above unused, and none "+
			"at nothing", weight)
	}
}

// A new bill is new code: what was read in the old is not carried over.
func TestANewBillDiscardsWhatWasReadOfTheOldCode(t *testing.T) {
	root, src := reachSite(t)
	if err := cmdVuln(root, []string{"reach", "--source", src, "--where",
		"repo:edge-proxy"}); err != nil {
		t.Fatal(err)
	}
	// Another asset's results stay.
	other, _ := loadReach(root)
	other = append(other, vuln.Reach{Advisory: "GO-USED",
		Component: "go:golang.org/x/net", Where: "repo:other", Symbols: 1})
	if err := writeJSONL(reachPath(root), other); err != nil {
		t.Fatal(err)
	}
	bill := put(t, filepath.Join(t.TempDir(), "bom.json"), billOfProxy)
	if err := cmdVuln(root, []string{"import", "--bom", bill, "--where",
		"repo:edge-proxy"}); err != nil {
		t.Fatal(err)
	}
	left, _ := loadReach(root)
	if len(left) != 1 || left[0].Where != "repo:other" {
		t.Errorf("after a new bill: %+v", left)
	}
	if r := reachOf(t, root); r["GO-USED"] != nil {
		t.Error("a result about the old code is still ranking the new")
	}
}
