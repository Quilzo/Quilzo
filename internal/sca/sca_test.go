// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sca

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

var t0 = time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)

// TestCVSSAgreesWithThePublishedScores.
//
// Foreign vectors with scores everybody publishes, because an
// implementation checked only against itself proves it is self-consistent,
// which is the one property that does not matter.
func TestCVSSAgreesWithThePublishedScores(t *testing.T) {
	for _, c := range []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	} {
		got, ok := BaseScore(c.vector)
		if !ok {
			t.Errorf("%s: not scored", c.vector)
			continue
		}
		if got != c.want {
			t.Errorf("%s = %.1f, want %.1f", c.vector, got, c.want)
		}
	}
	// A 4.0 vector uses different metrics and a different formula, so it
	// is refused rather than scored with the wrong arithmetic.
	if _, ok := BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H"); ok {
		t.Fatal("a 4.0 vector was scored with the 3.1 formula")
	}
	if _, ok := BaseScore("not a vector"); ok {
		t.Fatal("nonsense was scored")
	}
}

// TestRoundupIsTheSpecificationsNotOrdinaryRounding.
func TestRoundupIsTheSpecificationsNotOrdinaryRounding(t *testing.T) {
	if got := roundup(4.02); got != 4.1 {
		t.Fatalf("roundup(4.02) = %v, want 4.1", got)
	}
	if got := roundup(4.0); got != 4.0 {
		t.Fatalf("roundup(4.0) = %v, want 4.0", got)
	}
}

const osvRecord = `{
  "id": "GHSA-xxxx-yyyy-zzzz",
  "modified": "2026-08-01T00:00:00Z",
  "published": "2026-07-15T00:00:00Z",
  "aliases": ["CVE-2026-1111"],
  "summary": "Path traversal in the archive reader",
  "severity": [{"type": "CVSS_V3",
    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected": [{
    "package": {"ecosystem": "Go", "name": "github.com/acme/archive",
                "purl": "pkg:golang/github.com/acme/archive"},
    "ranges": [{"type": "SEMVER",
      "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.2"}]}]
  }],
  "references": [{"type": "ADVISORY", "url": "https://example.invalid/a"}]
}`

func TestReadsAnOSVRecordAndScoresIt(t *testing.T) {
	rs, err := ReadOSV([]byte(osvRecord))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 {
		t.Fatalf("%d record(s)", len(rs))
	}
	a := rs[0].Advisory(t0)
	if a.ID != "GHSA-xxxx-yyyy-zzzz" || len(a.Aliases) != 1 {
		t.Fatalf("%+v", a)
	}
	if a.CVSS != 9.8 || a.Severity != telemetry.SeverityCritical {
		t.Fatalf("cvss %v severity %v", a.CVSS, a.Severity)
	}
	if !a.Known.Equal(t0) {
		t.Fatal("the known date is not the caller's")
	}
	if len(a.Affects) != 1 {
		t.Fatalf("%d range(s)", len(a.Affects))
	}
	if a.Affects[0].Introduced != "1.0.0" || a.Affects[0].Fixed != "1.4.2" {
		t.Fatalf("range = %+v", a.Affects[0])
	}
	if a.FixedIn["go:github.com/acme/archive"] != "1.4.2" {
		t.Fatalf("fixedIn = %v", a.FixedIn)
	}
	// An array is read too, because every aggregator republishes them
	// that way.
	many, err := ReadOSV([]byte("[" + osvRecord + "," + osvRecord + "]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(many) != 2 {
		t.Fatalf("%d from an array", len(many))
	}
}

// TestAnOpenRangeMeansNoFixExists.
func TestAnOpenRangeMeansNoFixExists(t *testing.T) {
	src := `{"id":"OSV-1","affected":[{"package":{"ecosystem":"npm",
		"name":"left-pad"},"ranges":[{"type":"SEMVER",
		"events":[{"introduced":"0"}]}]}]}`
	rs, err := ReadOSV([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	a := rs[0].Advisory(t0)
	if len(a.Affects) != 1 || a.Affects[0].Fixed != "" {
		t.Fatalf("affects = %+v", a.Affects)
	}
	if _, ok := a.FixedIn["npm:left-pad"]; ok {
		t.Fatal("an open range produced a fixed version")
	}
	if !affected(a, "npm", "left-pad", "0.0.1") ||
		!affected(a, "npm", "left-pad", "99.0.0") {
		t.Fatal("an open range should affect every version")
	}
}

func TestAWithdrawnAdvisoryIsNotScanned(t *testing.T) {
	src := `{"id":"OSV-2","withdrawn":"2026-08-01T00:00:00Z",
		"affected":[{"package":{"ecosystem":"npm","name":"x"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
	rs, err := ReadOSV([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if rs[0].Live() {
		t.Fatal("a withdrawn advisory reported as live")
	}
	b := mustBOM(t, bomWithGraph)
	rep := Scan(b, rs, "prod", t0)
	if len(rep.Hits) != 0 {
		t.Fatal("a withdrawn advisory produced findings")
	}
}

func TestPURLParsing(t *testing.T) {
	for _, c := range []struct{ in, eco, name string }{
		{"pkg:golang/github.com/acme/archive@v1.2.3", "Go",
			"github.com/acme/archive"},
		{"pkg:npm/%40scope/thing@1.0.0", "npm", "@scope/thing"},
		{"pkg:pypi/requests@2.31.0", "PyPI", "requests"},
		{"pkg:cargo/serde@1.0", "crates.io", "serde"},
		{"pkg:maven/org.apache/commons@1.0", "Maven", "org.apache/commons"},
		{"pkg:golang/x/y@v1?type=module#sub", "Go", "x/y"},
	} {
		eco, name, ok := ParsePURL(c.in)
		if !ok {
			t.Errorf("%s: not parsed", c.in)
			continue
		}
		if eco != c.eco || name != c.name {
			t.Errorf("%s = %q/%q, want %q/%q", c.in, eco, name, c.eco,
				c.name)
		}
	}
	for _, bad := range []string{"", "github.com/x/y", "pkg:", "pkg:golang"} {
		if _, _, ok := ParsePURL(bad); ok {
			t.Errorf("%q was parsed", bad)
		}
	}
}

// bomWithGraph: the app depends on a server, which depends on the
// vulnerable archive library four levels down.
const bomWithGraph = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {"component": {"bom-ref": "root", "type": "application",
                             "name": "api", "version": "1.0.0"}},
  "components": [
    {"bom-ref": "srv", "type": "library", "name": "server",
     "version": "3.0.0", "purl": "pkg:golang/github.com/acme/server@v3.0.0"},
    {"bom-ref": "mw", "type": "library", "name": "middleware",
     "version": "2.0.0", "purl": "pkg:golang/github.com/acme/middleware@v2.0.0"},
    {"bom-ref": "arc", "type": "library", "name": "archive",
     "version": "1.2.0", "purl": "pkg:golang/github.com/acme/archive@v1.2.0"},
    {"bom-ref": "direct", "type": "library", "name": "parser",
     "version": "0.9.0", "purl": "pkg:golang/github.com/acme/parser@v0.9.0"}
  ],
  "dependencies": [
    {"ref": "root", "dependsOn": ["srv", "direct"]},
    {"ref": "srv", "dependsOn": ["mw"]},
    {"ref": "mw", "dependsOn": ["arc"]},
    {"ref": "direct", "dependsOn": []}
  ]
}`

func mustBOM(t *testing.T, src string) BOM {
	t.Helper()
	b, err := ReadBOM([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReadsABillAndItsGraph(t *testing.T) {
	b := mustBOM(t, bomWithGraph)
	if len(b.Flat()) != 4 {
		t.Fatalf("%d component(s)", len(b.Flat()))
	}
	tree := b.Graph()
	if !tree.Known() {
		t.Fatal("the graph was not built")
	}
	if got := tree.Depth("direct"); got != 1 {
		t.Fatalf("a direct dependency is at depth %d", got)
	}
	if got := tree.Depth("arc"); got != 3 {
		t.Fatalf("the archive library is at depth %d", got)
	}
	path := tree.Path("arc")
	if len(path) != 4 || path[0] != "root" || path[3] != "arc" {
		t.Fatalf("path = %v", path)
	}
	// The blocker is the direct dependency, not the immediate parent.
	bl, ok := tree.Blocker("arc")
	if !ok || bl.Name != "server" {
		t.Fatalf("blocker = %+v, %v", bl, ok)
	}
	// A direct dependency is its own blocker: the team can move it.
	bd, ok := tree.Blocker("direct")
	if !ok || bd.Name != "parser" {
		t.Fatalf("direct blocker = %+v", bd)
	}
}

func TestRefusesWhatIsNotCycloneDX(t *testing.T) {
	for _, c := range []struct{ name, src, says string }{
		{"not json", "{", "not JSON"},
		{"spdx", `{"bomFormat":"SPDX","specVersion":"1.6"}`, "CycloneDX"},
		{"no spec version", `{"bomFormat":"CycloneDX"}`, "specVersion"},
		{"empty", `{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
			"lists nothing"},
	} {
		if _, err := ReadBOM([]byte(c.src)); err == nil {
			t.Errorf("%s: accepted", c.name)
		} else if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestTheWorkIsBumpOrConversation is the point of the package.
func TestTheWorkIsBumpOrConversation(t *testing.T) {
	// Two advisories: one against the transitive archive library, one
	// against the direct parser.
	records := []Record{}
	for _, src := range []string{osvRecord, `{
      "id": "GHSA-direct",
      "severity": [{"type":"CVSS_V3",
        "score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
      "affected": [{"package": {"ecosystem":"Go",
        "name":"github.com/acme/parser"},
        "ranges":[{"type":"SEMVER",
          "events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]}`} {
		rs, err := ReadOSV([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, rs...)
	}

	rep := Scan(mustBOM(t, bomWithGraph), records, "prod", t0)
	if len(rep.Hits) != 2 {
		t.Fatalf("%d hit(s): %+v", len(rep.Hits), rep.Hits)
	}
	// Actionable work sorts first.
	if !rep.Hits[0].Work.Actionable() {
		t.Fatalf("the first hit is %s", rep.Hits[0].Work)
	}
	byID := map[string]Hit{}
	for _, h := range rep.Hits {
		byID[h.Exposure.Advisory.ID] = h
	}

	direct := byID["GHSA-direct"]
	if direct.Work != Bump || direct.Depth != 1 {
		t.Fatalf("direct = %s at depth %d", direct.Work, direct.Depth)
	}
	if direct.Fixed != "1.0.0" {
		t.Fatalf("fixed = %q", direct.Fixed)
	}
	if !direct.Exposure.Component.Direct {
		t.Fatal("a depth-1 component is not marked direct")
	}

	deep := byID["GHSA-xxxx-yyyy-zzzz"]
	if deep.Work != Wait {
		t.Fatalf("a transitive fix is %s", deep.Work)
	}
	if deep.Depth != 3 {
		t.Fatalf("depth = %d", deep.Depth)
	}
	// The declared version, not the one in the purl: a bill that
	// disagrees with itself is telling you something, and the version
	// field is what a resolver wrote.
	if deep.Blocker != "github.com/acme/server@3.0.0" {
		t.Fatalf("blocker = %q", deep.Blocker)
	}
	if len(deep.Path) != 4 {
		t.Fatalf("path = %v", deep.Path)
	}
	if !strings.Contains(deep.Work.Why(), "asking rather than upgrading") {
		t.Fatalf("why = %q", deep.Work.Why())
	}

	blocked := rep.Blocked()
	if len(blocked["github.com/acme/server@3.0.0"]) != 1 {
		t.Fatalf("blocked = %v", blocked)
	}
	if b, n := rep.Worst(); n != 1 || !strings.Contains(b, "server") {
		t.Fatalf("worst = %q %d", b, n)
	}
	if len(rep.Actionable()) != 1 {
		t.Fatalf("%d actionable", len(rep.Actionable()))
	}
	why := rep.Why()
	for _, want := range []string{"1 can be upgraded today", "waiting on"} {
		if !strings.Contains(why, want) {
			t.Fatalf("why = %q", why)
		}
	}
}

// TestNoFixAnywhereIsNotATicket.
func TestNoFixAnywhereIsNotATicket(t *testing.T) {
	rs, err := ReadOSV([]byte(`{"id":"OSV-open","affected":[{
		"package":{"ecosystem":"Go","name":"github.com/acme/parser"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rep := Scan(mustBOM(t, bomWithGraph), rs, "prod", t0)
	if len(rep.Hits) != 1 {
		t.Fatalf("%d hit(s)", len(rep.Hits))
	}
	if rep.Hits[0].Work != Nothing {
		t.Fatalf("work = %s", rep.Hits[0].Work)
	}
	if rep.Hits[0].Work.Actionable() {
		t.Fatal("something with no fix was called actionable")
	}
	if !strings.Contains(rep.Hits[0].Work.Why(), "decisions rather than") {
		t.Fatalf("why = %q", rep.Hits[0].Work.Why())
	}
}

// TestABillWithNoGraphSaysSoRatherThanGuessing.
func TestABillWithNoGraphSaysSoRatherThanGuessing(t *testing.T) {
	flat := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
		{"bom-ref":"arc","name":"archive","version":"1.2.0",
		 "purl":"pkg:golang/github.com/acme/archive@v1.2.0"}]}`
	rs, err := ReadOSV([]byte(osvRecord))
	if err != nil {
		t.Fatal(err)
	}
	rep := Scan(mustBOM(t, flat), rs, "prod", t0)
	if !rep.Graphless {
		t.Fatal("a bill with no dependencies block was not reported as such")
	}
	if len(rep.Hits) != 1 {
		t.Fatalf("%d hit(s)", len(rep.Hits))
	}
	h := rep.Hits[0]
	if h.Work != Unknown {
		t.Fatalf("work = %s; guessing direct would send somebody to bump "+
			"a version they may not control", h.Work)
	}
	if h.Depth != -1 {
		t.Fatalf("depth = %d", h.Depth)
	}
	if !strings.Contains(rep.Why(), "no dependency graph") {
		t.Fatalf("why = %q", rep.Why())
	}
}

// TestVersionRangesAreEvaluatedNotGuessed.
func TestVersionRangesAreEvaluatedNotGuessed(t *testing.T) {
	rs, err := ReadOSV([]byte(osvRecord)) // 1.0.0 <= v < 1.4.2
	if err != nil {
		t.Fatal(err)
	}
	a := rs[0].Advisory(t0)
	for _, c := range []struct {
		version string
		want    bool
	}{
		{"1.2.0", true},
		{"1.0.0", true},
		{"1.4.1", true},
		{"1.4.2", false},
		{"2.0.0", false},
		{"0.9.0", false},
	} {
		if got := affected(a, "Go", "github.com/acme/archive",
			c.version); got != c.want {
			t.Errorf("%s affected = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestAComponentWithNoVersionCannotBeMatched(t *testing.T) {
	src := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
		{"bom-ref":"arc","name":"archive",
		 "purl":"pkg:golang/github.com/acme/archive"}]}`
	rs, err := ReadOSV([]byte(osvRecord))
	if err != nil {
		t.Fatal(err)
	}
	rep := Scan(mustBOM(t, src), rs, "prod", t0)
	if rep.Unversioned != 1 {
		t.Fatalf("unversioned = %d", rep.Unversioned)
	}
	if len(rep.Hits) != 0 {
		t.Fatal("a component with no version was matched against a range")
	}
	if !strings.Contains(rep.Why(), "no version") {
		t.Fatalf("why = %q", rep.Why())
	}
}
