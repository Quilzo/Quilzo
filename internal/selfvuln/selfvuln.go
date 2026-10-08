// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package selfvuln is Quilzo checking itself for known flaws: what is in
// this binary, against what is known to be wrong with it, decided as far
// as it can be decided here.
//
// This program has no third-party dependencies, so every flaw that can
// reach it is in the Go standard library it was built with. The Go
// vulnerability database names, for each, the versions affected and the
// functions that are wrong. Three questions settle each one:
//
//   - Does it apply to the Go this was built with? Usually not.
//   - Is a function it names linked into this binary (ReadLinked)? The
//     linker drops what nothing calls, so a function that is not there
//     cannot be reached by anybody.
//   - Which features use the package (FeatureMap)? A flaw only reachable
//     through features that can be turned off for a day (uploads, the
//     content API, import) can be contained by turning them off; a flaw in
//     what every server runs cannot, and a person upgrades Go.
//
// The decision is Clear (nothing to do, and a VEX statement says why),
// Contain (the shield turns those features off, automatically only for a
// flaw known to be exploited) or Tell (a person is told and a case opened).
//
// The database is embedded as a snapshot taken at release, read offline;
// an operator gives a newer one with `quilzo self update vulndb.zip`. The
// screen says how old it is, because a snapshot nobody refreshes is a
// clean bill of health that stopped being true.
package selfvuln

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/sca"
	"github.com/quilzo/quilzo/internal/vuln"
)

//go:embed stdlib.json.gz
var embedded []byte

//go:embed features.json
var embeddedMap []byte

// Snapshot is the database's standard-library records.
type Snapshot struct {
	Modified time.Time    `json:"modified"`
	Records  []sca.Record `json:"records"`
	// Source says where it came from: "embedded at release" or a file.
	Source string `json:"source"`
}

// Path is where an operator's newer snapshot is kept in a store.
func Path(root string) string { return filepath.Join(root, "self", "stdlib.json.gz") }

// Load is the newer of the embedded snapshot and one kept in the store.
func Load(root string) (Snapshot, error) {
	in, err := read(embedded)
	if err != nil {
		return Snapshot{}, fmt.Errorf("the embedded snapshot: %w", err)
	}
	in.Source = "embedded at release"
	if root == "" {
		return in, nil
	}
	b, err := os.ReadFile(Path(root))
	if os.IsNotExist(err) {
		return in, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	kept, err := read(b)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%s: %w", Path(root), err)
	}
	if kept.Modified.After(in.Modified) {
		kept.Source = Path(root)
		return kept, nil
	}
	return in, nil
}

func read(gz []byte) (Snapshot, error) {
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return Snapshot{}, err
	}
	b, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// Embedded map of features, by standard library package.
func Features() (FeatureMap, error) {
	var m FeatureMap
	return m, json.Unmarshal(embeddedMap, &m)
}

// Decision is what to do about one flaw.
type Decision string

const (
	// Clear: it does not apply, or what it names is not in this binary.
	Clear Decision = "clear"
	// Contain: reachable only through features that can be turned off,
	// and known to be exploited: the shield turns them off.
	Contain Decision = "contain"
	// Tell: a person must act, by upgrading Go.
	Tell Decision = "tell"
)

// Finding is one advisory, assessed against this binary.
type Finding struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
	Summary string   `json:"summary"`
	// Applies says the Go this was built with is in an affected range.
	Applies bool `json:"applies"`
	// Fixed is the first Go release with the fix, after this one.
	Fixed string `json:"fixed,omitempty"`
	// Packages are the standard library packages named; Linked the
	// functions of theirs found in this binary; Unanalysed that nothing
	// could be said about what is linked.
	Packages   []string `json:"packages,omitempty"`
	Linked     []string `json:"linked,omitempty"`
	Unanalysed bool     `json:"unanalysed,omitempty"`
	// Features are what use the packages ("*" for every server).
	Features []string `json:"features,omitempty"`
	// Exploited says a feed this store loaded (CISA KEV) attests it.
	Exploited bool     `json:"exploited,omitempty"`
	Decision  Decision `json:"decision"`
	Why       string   `json:"why"`
}

// Containable are features the shield can turn off for a day: public
// surfaces a site can do without, the same list it may name.
var Containable = map[string]bool{"chatbots": true, "search-answers": true, "forms": true, "boards": true,
	"signup": true, "uploads": true, "import": true, "feeds": true, "scim": true, "api": true, "mcp": true}

// Report is every advisory that applies, decided.
type Report struct {
	Go       string    `json:"go"`
	Database time.Time `json:"database"`
	Source   string    `json:"source"`
	Checked  time.Time `json:"checked"`
	// Records is how many standard-library advisories were read; Applies
	// how many concern this Go.
	Records  int       `json:"records"`
	Findings []Finding `json:"findings"`
}

// Assess decides each advisory for a binary built with goVersion (as
// runtime.Version gives it), whose linked functions are linked (nil when
// they could not be read), given which ids feeds attest as exploited.
func Assess(snap Snapshot, goVersion string, linked Linked, fm FeatureMap, exploited func(ids []string) bool, now time.Time) Report {
	rep := Report{Go: goVersion, Database: snap.Modified, Source: snap.Source, Checked: now, Records: len(snap.Records)}
	version := strings.TrimPrefix(goVersion, "go")
	if i := strings.IndexAny(version, " -+"); i >= 0 {
		version = version[:i]
	}
	for _, rec := range snap.Records {
		if !rec.Live() {
			continue
		}
		f := Finding{ID: rec.ID, Aliases: rec.Aliases, Summary: rec.Summary}
		var imports []string
		symbols := map[string][]string{}
		for _, a := range rec.Affected {
			if a.Package.Name != "stdlib" {
				continue
			}
			for _, rg := range a.Ranges {
				if in, fixed := within(rg, version); in {
					f.Applies = true
					if fixed != "" && (f.Fixed == "" || less(fixed, f.Fixed)) {
						f.Fixed = fixed
					}
				}
			}
			var spec sca.Specific
			if len(a.Specific) > 0 && json.Unmarshal(a.Specific, &spec) == nil {
				for _, im := range spec.Imports {
					imports = append(imports, im.Path)
					symbols[im.Path] = append(symbols[im.Path], im.Symbols...)
				}
			}
		}
		if !f.Applies {
			continue
		}
		sort.Strings(imports)
		f.Packages = imports
		if exploited != nil {
			f.Exploited = exploited(append([]string{rec.ID}, rec.Aliases...))
		}
		decide(&f, imports, symbols, linked, fm)
		rep.Findings = append(rep.Findings, f)
	}
	sort.Slice(rep.Findings, func(i, j int) bool {
		if order[rep.Findings[i].Decision] != order[rep.Findings[j].Decision] {
			return order[rep.Findings[i].Decision] < order[rep.Findings[j].Decision]
		}
		return rep.Findings[i].ID < rep.Findings[j].ID
	})
	return rep
}

var order = map[Decision]int{Contain: 0, Tell: 1, Clear: 2}

func decide(f *Finding, imports []string, symbols map[string][]string, linked Linked, fm FeatureMap) {
	if len(imports) == 0 {
		// The database names no package: nothing narrows it.
		f.Decision, f.Why = Tell, "the advisory names no package, so upgrading Go is the answer"
		return
	}
	if linked == nil {
		f.Unanalysed = true
	}
	features := map[string]bool{}
	reached := false
	for _, pkg := range imports {
		if linked != nil {
			has, found := linked.Has(pkg, symbols[pkg])
			if !has {
				continue
			}
			for _, s := range found {
				f.Linked = append(f.Linked, pkg+"."+s)
			}
			if len(found) == 0 {
				f.Linked = append(f.Linked, pkg)
			}
		}
		reached = true
		for _, ft := range fm.Features(pkg) {
			features[ft] = true
		}
	}
	for ft := range features {
		f.Features = append(f.Features, ft)
	}
	sort.Strings(f.Features)
	switch {
	case !reached:
		f.Decision = Clear
		f.Why = "what it names is not linked into this binary, so nothing can reach it"
	case features[Core]:
		f.Decision = Tell
		f.Why = "what every server runs uses it, so it cannot be turned off; upgrade Go"
		if f.Unanalysed {
			f.Why = "what is linked into this binary could not be read, so it is taken as reachable; upgrade Go"
		}
	case !f.Exploited:
		f.Decision = Tell
		f.Why = "only " + strings.Join(f.Features, ", ") + " use it and could be turned off, but it is not known to be exploited, so a person decides; upgrade Go"
	default:
		f.Decision = Contain
		f.Why = "known to be exploited and reachable only through " + strings.Join(f.Features, ", ") + ", which the shield turns off until Go is upgraded"
		for _, ft := range f.Features {
			if !Containable[ft] {
				f.Decision = Tell
				f.Why = strings.Join(f.Features, ", ") + " use it, and " + ft + " cannot be turned off; upgrade Go"
			}
		}
	}
}

// within reports whether version is in an OSV range, and the fix that ends
// that part of it.
func within(rg sca.VRange, version string) (bool, string) {
	intro := ""
	open := false
	for _, e := range rg.Events {
		switch {
		case e.Introduced != "":
			intro, open = e.Introduced, true
		case e.Fixed != "" && open:
			if atLeast(version, intro) && less(version, e.Fixed) {
				return true, e.Fixed
			}
			open = false
		case e.LastAffected != "" && open:
			if atLeast(version, intro) && !less(e.LastAffected, version) {
				return true, ""
			}
			open = false
		}
	}
	if open && atLeast(version, intro) {
		return true, ""
	}
	return false, ""
}

func atLeast(v, floor string) bool { return floor == "" || floor == "0" || !less(v, floor) }

// less orders Go release versions as the vulnerability database writes
// them: 1.27.0-0 is "every pre-release of 1.27", before 1.27.0 and after
// every 1.26. A version it cannot read is ordered as unknown and taken the
// way that reports a flaw rather than hides one, by the callers.
func less(a, b string) bool {
	x, okx := goVersion(a)
	y, oky := goVersion(b)
	if !okx || !oky {
		c, ok := vuln.Compare(a, b)
		return ok && c < 0
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}

// goVersion reads "1.27.0", "1.27", "1.27rc1", "1.27.0-0" as major, minor,
// patch and a fourth part that puts a pre-release before its release.
func goVersion(v string) ([4]int, bool) {
	var out [4]int
	out[3] = 1 // a release
	v = strings.TrimPrefix(v, "go")
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v, out[3] = v[:i], 0
	}
	for _, pre := range []string{"rc", "beta"} {
		if i := strings.Index(v, pre); i >= 0 {
			v, out[3] = v[:i], 0
		}
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n := 0
		if p == "" {
			return out, false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return out, false
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out, true
}

// GoVersion is the Go this binary was built with.
func GoVersion() string { return runtime.Version() }
