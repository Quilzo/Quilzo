// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/store"
)

// The scale the register is designed to, measured.
//
// One instance is meant to hold ten thousand observations, a thousand
// controls and a hundred and fifty thousand test runs and pieces of
// evidence, and the two promises made of the index at that size are that
// counting how the thousand controls stand takes under a second once the
// index is in memory, and that the index takes under 15 MB for every
// hundred and fifty thousand rows. Both are held here with room to spare,
// so a slow machine does not fail them and a design that has stopped
// meeting them does.
//
// Measured on the machine this was written on (four shared cores), with the
// numbers the tests and benchmarks below print:
//
//	typed index, 162,004 rows        12.4 MB in memory, 11.7 MB on disk
//	read back from its file          22 ms, digest checked
//	the same records as decoded maps about 93 MB of heap
//	coverage over 1,000 controls     1.4 ms from the typed index
//	                                 29 ms from the maps
//
// The index is made here from the generator's records by the function the
// store's index uses for each row, and a test holds the two to the same
// rows. Writing the whole probe through the store is left to
// QUILZO_PROBE=store, because the store makes every object durable before
// the commit that reaches it, and a hundred and sixty thousand records are
// some three hundred thousand files: written in eight batches it took 2 min
// 38 s here, and the cold index over it 5.3 s.

// indexOf is the index of a set of records as the store would index them
// once written at a moment, without the store.
func indexOf(t testing.TB, recs []Record, at time.Time) *Index {
	t.Helper()
	ix := &Index{kinds: map[Kind]*kindRows{}}
	for _, rec := range recs {
		id, err := IDOf(rec)
		if err != nil {
			t.Fatal(err)
		}
		fields, err := canonicalFields(rec)
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(stored{ID: string(id), Fields: fields, Created: at.Unix(), Updated: at.Unix()})
		kr := ix.kinds[rec.Kind()]
		if kr == nil {
			kr = &kindRows{shards: map[string]string{}}
			ix.kinds[rec.Kind()] = kr
		}
		kr.rows = append(kr.rows, rowOf(rec, id, store.ObjectID(store.KindBlob, payload)))
	}
	for _, kr := range ix.kinds {
		sort.Slice(kr.rows, func(i, j int) bool { return bytes.Compare(kr.rows[i].ID[:], kr.rows[j].ID[:]) < 0 })
	}
	return ix
}

// fullProbe is the probe at full size and its index, made once for the
// tests and benchmarks that want it.
var fullProbe struct {
	recs []Record
	ix   *Index
}

func full(t testing.TB) ([]Record, *Index) {
	t.Helper()
	if fullProbe.ix == nil {
		recs, err := FullProbe.Records()
		if err != nil {
			t.Fatal(err)
		}
		fullProbe.recs, fullProbe.ix = recs, indexOf(t, recs, time.Unix(1_790_000_000, 0))
	}
	return fullProbe.recs, fullProbe.ix
}

// The generator makes the same register every time.
func TestProbeGeneratorDeterministic(t *testing.T) {
	sum := func(p Probe) (string, int) {
		recs, err := p.Records()
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		for _, rec := range recs {
			if err := validate(rec); err != nil {
				t.Fatalf("the generator made a record the register refuses: %v", err)
			}
			id, _ := IDOf(rec)
			fields, _ := canonicalFields(rec)
			h.Write([]byte(id))
			h.Write(fields)
		}
		return hex.EncodeToString(h.Sum(nil)), len(recs)
	}
	small := Probe{Observations: 100, Controls: 20, Rows: 300}
	one, n := sum(small)
	two, _ := sum(small)
	if one != two {
		t.Fatal("two runs of the generator made two registers")
	}
	// Held to a known digest too, so a run next year, on another machine,
	// measures the register this one measured. It moved when each test's
	// approval came to be bound to that test (SurfaceOf), and with the
	// domain line that hash is made under.
	const want = "2b427e75dd56195566cece66b708d60b34a768c3ccb53e0077ff26bbc3225d37"
	if one != want {
		t.Errorf("the small probe is %s; it has always been %s", one, want)
	}
	if n != 4+100+2*20+300 {
		t.Errorf("the small probe made %d records", n)
	}
	recs, ix := full(t)
	if got := len(recs); got != 4+10_000+2*1_000+150_000 {
		t.Errorf("the full probe made %d records", got)
	}
	if len(ix.Rows(KindObservation)) != 10_000 || len(ix.Rows(KindControl)) != 1_000 ||
		len(ix.Rows(KindTestRun))+len(ix.Rows(KindEvidence)) != 150_000 {
		t.Errorf("the full probe holds %d observations, %d controls and %d runs and evidence",
			len(ix.Rows(KindObservation)), len(ix.Rows(KindControl)), len(ix.Rows(KindTestRun))+len(ix.Rows(KindEvidence)))
	}
	// Every state coverage counts is in it.
	cov := ix.Coverage()
	if cov.Controls != 1_000 || cov.NoEvidence != 100 || cov.Passing == 0 || cov.Failing == 0 || cov.NeverFailed != 0 &&
		cov.NeverFailed >= cov.Passing || cov.Passing+cov.Failing+cov.NoEvidence != cov.Controls {
		t.Errorf("the full probe's coverage is %+v", cov)
	}
}

// The index made without the store is the index the store's makes.
func TestTheProbesIndexIsTheStores(t *testing.T) {
	b := newBench(t)
	recs, _ := Probe{Observations: 200, Controls: 30, Rows: 500}.Records()
	mustPut(t, b, importer, recs...)
	fromStore, err := b.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	direct := indexOf(t, recs, b.clock.t)
	for _, s := range Kinds() {
		a, c := fromStore.Rows(s.Kind), direct.Rows(s.Kind)
		if len(a) != len(c) {
			t.Fatalf("%s: the store indexed %d rows and the probe %d", s.Kind, len(a), len(c))
		}
		for i := range a {
			if a[i] != c[i] {
				t.Fatalf("%s row %d: the store's is %+v and the probe's %+v", s.Kind, i, a[i], c[i])
			}
		}
	}
	if fromStore.Coverage() != direct.Coverage() {
		t.Errorf("coverage from the store is %+v and from the probe %+v", fromStore.Coverage(), direct.Coverage())
	}
}

// The index stays within the memory it was promised: under 15 MB for every
// 150,000 rows, in memory and in its file.
func TestIndexSizeBound(t *testing.T) {
	if testing.Short() {
		t.Skip("the full probe is 162,000 records")
	}
	_, ix := full(t)
	const bound = 15 << 20
	per150k := func(bytes int) int { return int(float64(bytes) / float64(ix.Len()) * 150_000) }
	if got := per150k(ix.Bytes()); got > bound {
		t.Errorf("the index takes %.1f MB for every 150,000 rows; the bound is 15 MB", float64(got)/(1<<20))
	}
	// What the process really holds, not what the index says of itself.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	copyOf := &Index{kinds: map[Kind]*kindRows{}}
	for k, kr := range ix.kinds {
		copyOf.kinds[k] = &kindRows{rows: append([]Row(nil), kr.rows...)}
	}
	runtime.ReadMemStats(&after)
	if got := per150k(int(after.HeapAlloc - before.HeapAlloc)); got > bound {
		t.Errorf("a copy of the index took %.1f MB of heap for every 150,000 rows", float64(got)/(1<<20))
	}
	runtime.KeepAlive(copyOf)

	// And the file a process starts from.
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := Open(s)
	if err := r.saveIndex(ix); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(r.indexPath())
	if err != nil {
		t.Fatal(err)
	}
	if got := per150k(int(info.Size())); got > bound {
		t.Errorf("the index file is %.1f MB for every 150,000 rows", float64(got)/(1<<20))
	}
	start := time.Now()
	back, why := r.loadIndex()
	took := time.Since(start)
	if back == nil || why != "" || back.Len() != ix.Len() || back.Coverage() != ix.Coverage() {
		t.Errorf("the index did not come back from its file whole: %q", why)
	}
	t.Logf("%d rows: %.1f MB in memory, %.1f MB on disk, read back and checked in %v",
		ix.Len(), float64(ix.Bytes())/(1<<20), float64(info.Size())/(1<<20), took)
}

// Counting how a thousand controls stand, with the index in memory, takes
// under a second. It takes a few thousandths of one; the bound is the
// promise, with the room a loaded machine needs.
func TestWarmCoverageWithinBound(t *testing.T) {
	if testing.Short() {
		t.Skip("the full probe is 162,000 records")
	}
	_, ix := full(t)
	want := ix.Coverage()
	slowest := time.Duration(0)
	for i := 0; i < 5; i++ {
		start := time.Now()
		got := ix.Coverage()
		if d := time.Since(start); d > slowest {
			slowest = d
		}
		if got != want {
			t.Fatalf("coverage was %+v and then %+v", want, got)
		}
	}
	if slowest > time.Second {
		t.Errorf("coverage over %d controls and %d rows of evidence took %v; the bound is one second",
			want.Controls, len(ix.Rows(KindEvidence)), slowest)
	}
	t.Logf("coverage over %d controls: %v at the slowest of five", want.Controls, slowest)
}

// mapIndex is the probe's controls and evidence as the generic record index
// would hold them: each a map of its fields.
func mapIndex(t testing.TB, recs []Record) (controls, evidence, runs []collection.Record) {
	t.Helper()
	for _, rec := range recs {
		k := rec.Kind()
		if k != KindControl && k != KindEvidence && k != KindTestRun {
			continue
		}
		id, _ := IDOf(rec)
		fields, _ := canonicalFields(rec)
		var m map[string]any
		if err := json.Unmarshal(fields, &m); err != nil {
			t.Fatal(err)
		}
		r := collection.Record{ID: string(id), Fields: m}
		switch k {
		case KindControl:
			controls = append(controls, r)
		case KindEvidence:
			evidence = append(evidence, r)
		default:
			runs = append(runs, r)
		}
	}
	return controls, evidence, runs
}

// mapCoverage is Coverage, over maps.
func mapCoverage(controls, evidence []collection.Record) Coverage {
	type standing struct {
		at          float64
		outcome     string
		seen, fails bool
	}
	by := make(map[string]*standing, len(controls))
	for _, c := range controls {
		by[c.ID] = &standing{}
	}
	var cov Coverage
	for _, e := range evidence {
		c, _ := e.Fields["control"].(string)
		s := by[c]
		if s == nil {
			continue
		}
		at, _ := e.Fields["at"].(float64)
		outcome, _ := e.Fields["outcome"].(string)
		if outcome == string(Fail) {
			s.fails = true
		}
		if !s.seen || at > s.at || at == s.at && outcome == string(Fail) {
			s.at, s.outcome, s.seen = at, outcome, true
		}
		if Time(at) > cov.Latest {
			cov.Latest = Time(at)
		}
	}
	cov.Controls = len(controls)
	for _, s := range by {
		switch {
		case !s.seen:
			cov.NoEvidence++
		case s.outcome == string(Pass):
			cov.Passing++
			if !s.fails {
				cov.NeverFailed++
			}
		default:
			cov.Failing++
		}
	}
	return cov
}

// The two ways of counting agree, so the benchmarks compare like with like.
func TestTheMapIndexCountsTheSame(t *testing.T) {
	if testing.Short() {
		t.Skip("the full probe is 162,000 records")
	}
	recs, ix := full(t)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	controls, evidence, runs := mapIndex(t, recs)
	runtime.GC()
	runtime.ReadMemStats(&after)
	if got, want := mapCoverage(controls, evidence), ix.Coverage(); got != want {
		t.Errorf("the maps count %+v and the rows %+v", got, want)
	}
	t.Logf("%d controls, %d test runs and %d pieces of evidence as maps: about %d MB of heap",
		len(controls), len(runs), len(evidence), (after.HeapAlloc-before.HeapAlloc)>>20)
	runtime.KeepAlive(runs)
}

// BenchmarkCoverageMapIndex is coverage counted from records held as maps,
// which is what the generic record index would hold.
func BenchmarkCoverageMapIndex(b *testing.B) {
	recs, _ := full(b)
	controls, evidence, _ := mapIndex(b, recs)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapCoverage(controls, evidence)
	}
}

// BenchmarkCoverageTypedIndex is coverage counted from the typed rows.
func BenchmarkCoverageTypedIndex(b *testing.B) {
	_, ix := full(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix.Coverage()
	}
}

// With QUILZO_PROBE=store the whole probe is written through the store and
// the cold and warm index are timed. It is not run by default: see the note
// at the top of this file.
func TestProbeThroughTheStore(t *testing.T) {
	if os.Getenv("QUILZO_PROBE") != "store" {
		t.Skip("set QUILZO_PROBE=store to write the full probe through the store; it takes minutes")
	}
	b := newBench(t)
	recs, _ := full(t)
	start := time.Now()
	for at := 0; at < len(recs); at += 20_000 {
		mustPut(t, b, importer, recs[at:min(at+20_000, len(recs))]...)
	}
	t.Logf("written in %v", time.Since(start))
	start = time.Now()
	cold, err := b.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cold index of %d rows in %v", cold.Len(), time.Since(start))
	if _, err := b.Index(); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	warm, err := Open(b.Store).Index()
	if err != nil || !warm.Equal(cold) || warm.Read != 0 {
		t.Fatalf("the index from its file is not the index rebuilt (%v, read %d)", err, warm.Read)
	}
	t.Logf("index from its file in %v", time.Since(start))
	direct := indexOf(t, recs, b.clock.t)
	if cold.Coverage() != direct.Coverage() {
		t.Errorf("coverage from the store is %+v and from the probe %+v", cold.Coverage(), direct.Coverage())
	}
}
