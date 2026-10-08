// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package selfvuln

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/sca"
)

var t0 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// record is an advisory for the standard library, affecting [intro, fixed)
// in pkg's symbols.
func record(id, intro, fixed, pkg string, symbols ...string) sca.Record {
	spec, _ := json.Marshal(map[string]any{"imports": []map[string]any{{"path": pkg, "symbols": symbols}}})
	events := []sca.Event{{Introduced: intro}}
	if fixed != "" {
		events = append(events, sca.Event{Fixed: fixed})
	}
	return sca.Record{ID: id, Aliases: []string{"CVE-" + id}, Summary: "a flaw in " + pkg,
		Affected: []sca.Affected{{Package: sca.Package{Ecosystem: "Go", Name: "stdlib"},
			Ranges: []sca.VRange{{Type: "SEMVER", Events: events}}, Specific: spec}}}
}

func TestEachFlawIsDecidedByWhatIsLinkedAndWhoUsesIt(t *testing.T) {
	snap := Snapshot{Records: []sca.Record{
		record("GO-1", "0", "1.27.1", "image/jpeg", "Decode"),       // uploads only
		record("GO-2", "0", "1.27.1", "image/jpeg", "DecodeConfig"), // not linked
		record("GO-3", "0", "1.27.1", "net/http", "Server.Serve"),   // every server
		record("GO-4", "0", "1.26.5", "net/http", "Server.Serve"),   // fixed before ours
		record("GO-5", "1.27.0", "", "image/gif", "Decode"),         // no fix yet
	}}
	linked := Linked{"image/jpeg": {"Decode": true}, "net/http": {"Server.Serve": true}, "image/gif": {"Decode": true}}
	fm := FeatureMap{Packages: map[string][]string{"image/jpeg": {"uploads"}, "image/gif": {"uploads"}, "net/http": {"*", "api"}}}
	exploited := func(ids []string) bool { return ids[0] == "GO-1" }
	rep := Assess(snap, "go1.27.0", linked, fm, exploited, t0)
	got := map[string]Finding{}
	for _, f := range rep.Findings {
		got[f.ID] = f
	}
	if _, ok := got["GO-4"]; ok {
		t.Fatal("a flaw fixed before this Go was reported")
	}
	want := map[string]Decision{"GO-1": Contain, "GO-2": Clear, "GO-3": Tell, "GO-5": Tell}
	for id, d := range want {
		if got[id].Decision != d {
			t.Errorf("%s: %s (%s), want %s", id, got[id].Decision, got[id].Why, d)
		}
	}
	if got["GO-1"].Fixed != "1.27.1" || !reflect.DeepEqual(got["GO-1"].Features, []string{"uploads"}) ||
		!reflect.DeepEqual(got["GO-1"].Linked, []string{"image/jpeg.Decode"}) {
		t.Fatalf("%+v", got["GO-1"])
	}
	// Not known to be exploited: a person decides, even when it could be
	// contained.
	if got["GO-5"].Exploited || got["GO-5"].Fixed != "" {
		t.Fatalf("%+v", got["GO-5"])
	}
	// Contained first, then told, then cleared.
	if rep.Findings[0].ID != "GO-1" || rep.Findings[len(rep.Findings)-1].Decision != Clear {
		t.Fatalf("order %+v", rep.Findings)
	}
	// What is linked could not be read: nothing is cleared on that basis.
	rep = Assess(snap, "go1.27.0", nil, fm, exploited, t0)
	for _, f := range rep.Findings {
		if f.Decision == Clear || !f.Unanalysed {
			t.Errorf("%s decided %s without knowing what is linked", f.ID, f.Decision)
		}
	}
}

func TestRangesAreReadAsTheDatabaseWritesThem(t *testing.T) {
	cases := []struct {
		events []sca.Event
		v      string
		in     bool
	}{
		{[]sca.Event{{Introduced: "0"}, {Fixed: "1.26.5"}, {Introduced: "1.27.0-0"}, {Fixed: "1.27.2"}}, "1.27.0", true},
		{[]sca.Event{{Introduced: "0"}, {Fixed: "1.26.5"}, {Introduced: "1.27.0-0"}, {Fixed: "1.27.2"}}, "1.26.7", false},
		{[]sca.Event{{Introduced: "1.27.0"}, {LastAffected: "1.27.0"}}, "1.27.0", true},
		{[]sca.Event{{Introduced: "1.27.0"}, {LastAffected: "1.27.0"}}, "1.27.1", false},
		{[]sca.Event{{Introduced: "1.20.0"}}, "1.27.0", true},
		{[]sca.Event{{Introduced: "1.28.0"}}, "1.27.0", false},
	}
	for i, c := range cases {
		if in, _ := within(sca.VRange{Type: "SEMVER", Events: c.events}, c.v); in != c.in {
			t.Errorf("%d: %s in %+v is %v", i, c.v, c.events, in)
		}
	}
}

func TestLinkerNamesBecomeTheDatabasesSymbols(t *testing.T) {
	cases := map[string][2]string{
		"net/http.(*Server).Serve":                           {"net/http", "Server.Serve"},
		"crypto/x509.ParseCertificate":                       {"crypto/x509", "ParseCertificate"},
		"net/http.(*conn).serve.func1":                       {"net/http", "conn.serve"},
		"encoding/json.(*decodeState).object":                {"encoding/json", "decodeState.object"},
		"slices.SortFunc[go.shape.[]string,go.shape.string]": {"slices", "SortFunc"},
		"main.main":                {"main", "main"},
		"type:.eq.[2]interface {}": {"", ""},
	}
	for in, want := range cases {
		if p, s := split(in); p != want[0] || s != want[1] {
			t.Errorf("%s: %s %s", in, p, s)
		}
	}
}

func TestThisTestBinarysOwnFunctionsCanBeRead(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("ELF and Mach-O only")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	l, err := ReadLinked(exe)
	if err != nil {
		t.Fatal(err)
	}
	if ok, found := l.Has("testing", []string{"T.Run"}); !ok || len(found) != 1 {
		t.Fatal("the test binary does not link testing.T.Run, it seems")
	}
	if ok, _ := l.Has("net/smtp", []string{"SendMail"}); ok {
		t.Fatal("found a function nothing here calls")
	}
	if _, err := ReadLinked(filepath.Join(t.TempDir(), "nothing")); err == nil {
		t.Fatal("read a file that is not there")
	}
}

func TestTheEmbeddedMapIsTheSourcesOwn(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skip("not in the source tree")
	}
	now, err := Map(root)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := Features()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(now, kept) {
		t.Fatal("internal/selfvuln/features.json is out of date: run go run ./internal/selfvuln/gen")
	}
}

func TestTheSnapshotLoadsAndANewerOneInTheStoreWins(t *testing.T) {
	in, err := Load("")
	if err != nil || len(in.Records) < 100 || in.Modified.IsZero() || in.Source != "embedded at release" {
		t.Fatalf("%d records, %v, %v", len(in.Records), in.Modified, err)
	}
	root := t.TempDir()
	if got, _ := Load(root); got.Source != "embedded at release" {
		t.Fatal(got.Source)
	}
	newer := Snapshot{Modified: in.Modified.Add(24 * time.Hour), Records: in.Records[:3]}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	json.NewEncoder(gz).Encode(newer)
	gz.Close()
	os.MkdirAll(filepath.Dir(Path(root)), 0o700)
	os.WriteFile(Path(root), buf.Bytes(), 0o600)
	if got, _ := Load(root); got.Source != Path(root) || len(got.Records) != 3 {
		t.Fatalf("%s %d", got.Source, len(got.Records))
	}
}

func TestGoVersionsAreOrderedWithTheirPreReleases(t *testing.T) {
	for _, c := range [][2]string{{"1.26.7", "1.27.0-0"}, {"1.27.0-0", "1.27.0"}, {"1.27rc1", "1.27.0"}, {"1.27.0", "1.27.1"},
		{"1.9.0", "1.10.0"}, {"1.27", "1.27.1"}} {
		if !less(c[0], c[1]) || less(c[1], c[0]) {
			t.Errorf("%s < %s", c[0], c[1])
		}
	}
	if less("1.27.0", "1.27.0") {
		t.Error("a version before itself")
	}
}

func TestTheBinaryIsTheOneItSaysItIs(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(t.TempDir(), "quilzo")
	os.WriteFile(bin, []byte("version one"), 0o755)
	first, err := Verify(root, bin, "v1", "", t0)
	if err != nil || first.Suspicious() || first.SHA256 == "" {
		t.Fatalf("%+v %v", first, err)
	}
	// Replaced on disk while running.
	os.WriteFile(bin, []byte("something else"), 0o755)
	v, _ := Verify(root, bin, "v1", first.SHA256, t0)
	if !v.Changed || !v.Suspicious() {
		t.Fatalf("a replaced binary: %+v", v)
	}
	// Run again later with the same version: rebuilt or patched in place.
	v, _ = Verify(root, bin, "v1", "", t0.Add(time.Hour))
	if !v.Rebuilt || !strings.Contains(v.Says, "same version") {
		t.Fatalf("a rebuilt binary: %+v", v)
	}
	// Against the release's checksums.
	os.WriteFile(SumsPath(root), []byte("0000  quilzo_linux_amd64\n"), 0o600)
	if v, _ := Verify(root, bin, "v2", "", t0); v.Released != "differs" || !v.Suspicious() {
		t.Fatalf("%+v", v)
	}
	sum, _ := Hash(bin)
	os.WriteFile(SumsPath(root), []byte(sum+"  quilzo_linux_amd64\n"), 0o600)
	if v, _ := Verify(root, bin, "v3", "", t0); v.Released != "matches" || v.Suspicious() {
		t.Fatalf("%+v", v)
	}
}

func TestADatabaseZipIsReadForTheStandardLibraryOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulndb.zip")
	f, _ := os.Create(path)
	z := zip.NewWriter(f)
	add := func(name, body string) { w, _ := z.Create(name); w.Write([]byte(body)) }
	add("index/db.json", `{"modified":"2026-10-04T00:00:00Z"}`)
	add("ID/GO-2026-1.json", `{"id":"GO-2026-1","details":"long","affected":[{"package":{"name":"stdlib","ecosystem":"Go"}}]}`)
	add("ID/GO-2026-2.json", `{"id":"GO-2026-2","affected":[{"package":{"name":"github.com/x/y","ecosystem":"Go"}}]}`)
	z.Close()
	f.Close()
	gz, snap, err := FromZip(path)
	if err != nil || len(snap.Records) != 1 || snap.Records[0].ID != "GO-2026-1" || snap.Records[0].Details != "" || len(gz) == 0 {
		t.Fatalf("%+v %v", snap, err)
	}
	if _, _, err := FromZip(filepath.Join(t.TempDir(), "x.zip")); err == nil {
		t.Fatal("read nothing")
	}
}
