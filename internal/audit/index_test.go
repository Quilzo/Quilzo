// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// sameAsRead fails the test unless a look at the file reports what Read and
// Check report for it: the entries, the problems, the lines that are not
// entries among them, and a refusal.
func sameAsRead(t *testing.T, x *Index, path, when string) *Snapshot {
	t.Helper()
	want, rerr := Read(path)
	report, cerr := Check(want, rerr)
	s, err := x.Look()
	if cerr != nil || err != nil {
		if cerr == nil || err == nil {
			t.Fatalf("%s: Read says %v and a look says %v", when, rerr, err)
		}
		return nil
	}
	if s.Len() != len(want) {
		t.Fatalf("%s: a look holds %d entries and Read %d", when, s.Len(), len(want))
	}
	if rerr == nil {
		// Where every line is an entry, what Check says is what Verify says.
		if intact, problems := Verify(want); s.Intact() != intact || !reflect.DeepEqual(s.Problems(), problems) {
			t.Errorf("%s: a look says intact=%v %v, Verify %v %v", when, s.Intact(), s.Problems(), intact, problems)
		}
	}
	if s.Intact() != report.Intact || !reflect.DeepEqual(s.Problems(), report.Problems) ||
		s.Report().Unfinished != report.Unfinished || s.Report().Crashed() != report.Crashed() {
		t.Errorf("%s: a look says %+v, Check %+v", when, s.Report(), report)
	}
	all := make([]int, s.Len())
	actions := map[string]bool{}
	for i := range all {
		all[i] = i
		e := s.Entry(i)
		if e.Seq != want[i].Seq || e.Action != want[i].Action || e.Outcome != want[i].Outcome ||
			e.Principal != want[i].Principal {
			t.Errorf("%s: entry %d is %+v, Read has %+v", when, i, e, want[i])
		}
		actions[want[i].Action] = true
	}
	names := make([]string, 0, len(actions))
	for a := range actions {
		names = append(names, a)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(append([]string{}, s.Actions()...), names) {
		t.Errorf("%s: a look lists the actions %v, the log holds %v", when, s.Actions(), names)
	}
	got, err := s.Events(all)
	if err != nil {
		t.Fatalf("%s: %v", when, err)
	}
	if len(want) > 0 && !reflect.DeepEqual(got, want) {
		t.Errorf("%s: the entries read back are not the ones Read reads", when)
	}
	return s
}

func appendRecords(t *testing.T, path string, from, n int) {
	t.Helper()
	l, err := New(Options{Path: path, Key: []byte("k"), Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := from; i < from+n; i++ {
		out := Success
		if i%4 == 0 {
			out = Failure
		}
		if _, err := l.Append(Record{Action: fmt.Sprintf("act.%d", i%3), Resource: fmt.Sprintf("/r/%d", i),
			Outcome: out, Principal: fmt.Sprintf("p%d", i%5), Kind: KindHuman, Verified: true,
			Detail: map[string]string{"n": fmt.Sprint(i)}}); err != nil {
			t.Fatal(err)
		}
	}
}

func rewrite(t *testing.T, path string, change func([]byte) []byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, change(b), 0o600); err != nil {
		t.Fatal(err)
	}
}

// An index is read once and then only as the file grows, and it is never
// believed because it was read before: whatever happens to the file, a look
// reports what reading it whole would. An edit in place that keeps the
// length is the case a cache keyed on the size would miss, and a viewer
// that missed it would call an edited log intact.
func TestALookIsWhatReadingTheWholeLogSays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	x := NewIndex(path)
	if s := sameAsRead(t, x, path, "no log yet"); s == nil || s.Len() != 0 || !s.Intact() {
		t.Fatal("a log that is not there yet is not an empty, intact one")
	}

	appendRecords(t, path, 0, 30)
	sameAsRead(t, x, path, "first look")
	appendRecords(t, path, 30, 12)
	sameAsRead(t, x, path, "after it grew")

	// The same length: one character of one resource, early on.
	rewrite(t, path, func(b []byte) []byte { return bytes.Replace(b, []byte(`"/r/3"`), []byte(`"/r/X"`), 1) })
	if s := sameAsRead(t, x, path, "edited in place"); s.Intact() {
		t.Fatal("an entry edited in place, keeping the file's length, was reported intact")
	}
	rewrite(t, path, func(b []byte) []byte { return bytes.Replace(b, []byte(`"/r/X"`), []byte(`"/r/3"`), 1) })
	if s := sameAsRead(t, x, path, "edited back"); !s.Intact() {
		t.Fatal("the log put back as it was is not reported intact")
	}

	// Shortened by its last entry, then grown past where it was.
	rewrite(t, path, func(b []byte) []byte {
		b = b[:len(b)-1]
		return b[:bytes.LastIndexByte(b, '\n')+1]
	})
	sameAsRead(t, x, path, "last entry removed")
	appendRecords(t, path, 41, 3)
	sameAsRead(t, x, path, "grown again")

	// Windows line ends and blank lines are read as Read reads them.
	rewrite(t, path, func(b []byte) []byte {
		return append(bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")), []byte("\n  \n")...)
	})
	sameAsRead(t, x, path, "CRLF and blank lines")

	// A last line with no end: an entry Read takes, then one it refuses.
	b, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	last := bytes.TrimSpace(lines[len(lines)-1])
	rewrite(t, path, func(b []byte) []byte { return bytes.Join(lines[:len(lines)-1], []byte("\n")) })
	rewrite(t, path, func(b []byte) []byte { return append(append(b, '\n'), last...) })
	if s := sameAsRead(t, x, path, "an unfinished last line that is whole"); s.Len() != len(lines) {
		t.Errorf("an unfinished last line that is an entry is not shown")
	}
	rewrite(t, path, func(b []byte) []byte { return append(append(b, '\n'), `{"seq": 4`...) })
	sameAsRead(t, x, path, "an unfinished last line that is not")
	rewrite(t, path, func(b []byte) []byte { return append(b, "\nnot an entry\n"...) })
	sameAsRead(t, x, path, "a line that is not an entry")
}

// A line is shown only as the line that verified. A file edited between a
// look and the reading of its page is ErrChanged, and the next look sees the
// edit.
func TestAnEntryChangedAfterTheLookIsNotShown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	appendRecords(t, path, 0, 5)
	x := NewIndex(path)
	s, err := x.Look()
	if err != nil {
		t.Fatal(err)
	}
	rewrite(t, path, func(b []byte) []byte { return bytes.Replace(b, []byte(`"/r/2"`), []byte(`"/r/Z"`), 1) })
	if _, err := s.Events([]int{2}); !errors.Is(err, ErrChanged) {
		t.Errorf("an entry edited after the look was read back: %v", err)
	}
	if _, err := s.Events([]int{4}); err != nil {
		t.Errorf("an entry nobody touched: %v", err)
	}
	if s, err := x.Look(); err != nil || s.Intact() {
		t.Errorf("the next look did not see the edit: %v", err)
	}
}

// Looks taken at once agree with each other and with the file, as the race
// detector sees them: a page of the log read by several administrators at
// the moment it is written to.
func TestLooksTakenAtOnceAgree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	appendRecords(t, path, 0, 20)
	x := NewIndex(path)
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				s, err := x.Look()
				if err != nil {
					t.Error(err)
					return
				}
				if !s.Intact() {
					t.Error("a look found a growing log broken")
				}
				if _, err := s.Events([]int{0, s.Len() - 1}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	appendRecords(t, path, 20, 20)
	wg.Wait()
	sameAsRead(t, x, path, "after the looks")
}

// halfWritten writes the first half of the record the next Append to the
// log at path would write, as a reader sees a write still in progress, and
// returns what writes the rest. With locked, it holds the lock every writer
// takes until then, as a writer does.
func halfWritten(t *testing.T, path string, locked bool) (rest func()) {
	t.Helper()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(cp, before, 0o600); err != nil {
		t.Fatal(err)
	}
	appendRecords(t, cp, 100, 1)
	after, err := os.ReadFile(cp)
	if err != nil {
		t.Fatal(err)
	}
	line := after[len(before):]
	unlock := func() {}
	if locked {
		if unlock, err = atomicfile.Lock(path + ".lock"); err != nil {
			t.Fatal(err)
		}
	}
	add := func(b []byte) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	add(line[:len(line)/2])
	return func() {
		add(line[len(line)/2:])
		unlock()
	}
}

// A record still being written as the log is read is not a write a crash
// left unfinished. The kernel makes the file longer a page at a time as it
// copies a write in, so a reader can find the first part of a record as
// the last line, and every reader took it for a crash: the admin's log page
// and `auditlog verify` called a live, healthy log not intact, and
// TestLooksTakenAtOnceAgree failed about one run in ten. A last line with
// no end is judged only once nobody can still be writing it: when the lock
// every writer takes is free, or, for a reader that may not take it, as in
// a separated deployment, when it has not ended within writeGrace. A line
// a crash left is still reported as one, by either.
func TestARecordBeingWrittenIsNotACrash(t *testing.T) {
	type found struct {
		n      int
		report Report
		err    error
	}
	readers := []struct {
		name string
		read func(x *Index, path string) found
	}{
		{"a look", func(x *Index, path string) found {
			s, err := x.Look()
			if err != nil {
				return found{err: err}
			}
			return found{s.Len(), s.Report(), nil}
		}},
		{"Read", func(x *Index, path string) found {
			events, err := Read(path)
			r, err := Check(events, err)
			return found{len(events), r, err}
		}},
	}
	for _, mayLock := range []bool{true, false} {
		for _, reader := range readers {
			name := fmt.Sprintf("%s that may take the lock", reader.name)
			if !mayLock {
				name = fmt.Sprintf("%s that may not", reader.name)
			}
			t.Run(name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "audit.jsonl")
				appendRecords(t, path, 0, 3)
				x := NewIndex(path)
				if _, err := x.Look(); err != nil {
					t.Fatal(err)
				}
				old := writeGrace
				t.Cleanup(func() { writeGrace = old })
				if !mayLock {
					// A lock this reader cannot open, as the writer's own is
					// to the account that reads the log beside it.
					if err := os.Remove(path + ".lock"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Base(path)+".lock", path+".lock"); err != nil {
						t.Skipf("no symbolic link to stand for a lock that cannot be opened: %v", err)
					}
					writeGrace = time.Minute
				}

				rest := halfWritten(t, path, mayLock)
				got := make(chan found, 1)
				go func() { got <- reader.read(x, path) }()
				var f found
				select {
				case f = <-got:
					rest()
				case <-time.After(200 * time.Millisecond):
					rest()
					f = <-got
				}
				if f.err != nil || f.n != 4 || !f.report.Intact {
					t.Errorf("a record being written was read as %d entries and %+v: %v", f.n, f.report, f.err)
				}

				// A line a crash left, which nobody goes on to finish.
				writeGrace = 10 * time.Millisecond
				fl, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				fl.WriteString(`{"seq":5,"at":"2026-10`)
				fl.Close()
				if f := reader.read(x, path); f.err != nil || f.n != 4 || !f.report.Crashed() {
					t.Errorf("a line a crash left is read as %d entries and %+v: %v", f.n, f.report, f.err)
				}
			})
		}
	}
}

// A reader makes no lock. The lock is the writers' alone, and a reader
// waits at it only where one is: a log copied somewhere to be checked, or
// put back from a backup, has none beside it, and a last line cut short in
// it is the crash it looks like. What a store holds beside a log is also
// how verify-head tells a log removed whole from one that was never there
// (logWasHere, in cmd/quilzo), so a reader that made the lock to look at a
// line with no end would leave that mark wherever it had read.
func TestAReaderMakesNoLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	appendRecords(t, path, 0, 3)
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"seq":4,"at":"2026-10`)
	f.Close()

	s := sameAsRead(t, NewIndex(path), path, "a line a crash left, and no lock beside the log")
	if s == nil || s.Len() != 3 || !s.Report().Crashed() {
		t.Errorf("a line a crash left in a log with no lock beside it is not read as one")
	}
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Errorf("reading the log made the writers' lock beside it (%v)", err)
	}
}

// A look refuses a line where Read refuses it, to the byte. Read takes a
// line of up to four megabytes with its line end, and a last line without
// one if it is shorter than that; a look took up to the next 64 KB past
// either, so the admin's log page called intact a log that `auditlog
// verify`, `show` and the exports could not read at all.
func TestALookRefusesALineWhereReadDoes(t *testing.T) {
	head := `{"seq":1,"resource":"`
	for _, c := range []struct {
		size int
		end  string
	}{
		{maxEntryLine, "\n"}, {maxEntryLine + 1, "\n"}, {maxEntryLine + 1, "\r\n"},
		{maxEntryLine - 1, ""}, {maxEntryLine, ""}, {maxEntryLine + 1000, "\n"},
	} {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		pad := c.size - len(head) - len(`"}`) - len(c.end)
		line := head + string(bytes.Repeat([]byte("r"), pad)) + `"}` + c.end
		if err := os.WriteFile(path, []byte(`{"seq":0}`+"\n"+line), 0o600); err != nil {
			t.Fatal(err)
		}
		sameAsRead(t, NewIndex(path), path, fmt.Sprintf("a line of %d bytes ending %q", c.size, c.end))
	}
}

// A look reads past a line that is not an entry, as Read does, and reports
// it where it is: a write a crash left unfinished, in the middle of the log
// or last, as zeros, closed off by the next write or not, and a line nothing
// cut short. A look that stopped at one would blank the audit log screen for
// good after one crash, with every record written after it.
func TestALookReadsPastALineThatIsNotAnEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	x := NewIndex(path)
	appendRecords(t, path, 0, 3)
	sameAsRead(t, x, path, "before the crash")

	add := func(s string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	add(`{"seq":4,"at":"2026-10`)
	if s := sameAsRead(t, x, path, "a torn last line"); s == nil || s.Len() != 3 || !s.Report().Crashed() {
		t.Fatalf("a torn last line is not reported as a crash after the entries before it")
	}
	appendRecords(t, path, 3, 2)
	if s := sameAsRead(t, x, path, "written past the torn line"); s == nil || s.Len() != 5 || !s.Report().Crashed() {
		t.Fatalf("the entries after a torn line are not read, or it is not a crash")
	}
	add("\x00\x00\x00\x00")
	if s := sameAsRead(t, x, path, "zeros last"); s == nil || s.Report().Unfinished != 2 {
		t.Fatalf("zeros a crash left last are not a write left unfinished")
	}
	appendRecords(t, path, 5, 1)
	sameAsRead(t, x, path, "zeros closed off")

	// A line nothing cut short, which no writer carries on past, and lines
	// after it all the same.
	add("{not json\n")
	if s := sameAsRead(t, x, path, "a line nothing cut short"); s == nil || s.Report().Crashed() || s.Intact() {
		t.Fatalf("a line nothing cut short is reported as a crash, or not at all")
	}
	b, _ := os.ReadFile(path)
	lines := bytes.SplitAfter(b, []byte("\n"))
	add(string(lines[0]) + string(lines[1]))
	if s := sameAsRead(t, x, path, "entries after it"); s == nil || s.Len() != 8 {
		t.Fatalf("the entries after a line that is not one are not read")
	}

	// An edit before what is indexed reads the whole file again, bad lines
	// and all, and numbers them as Read does.
	rewrite(t, path, func(b []byte) []byte { return append([]byte("\n\n"), b...) })
	sameAsRead(t, x, path, "two blank lines put first")
	sameAsRead(t, NewIndex(path), path, "a fresh index")
}

// A look checks the log against the heads saved beside it as the entries
// Read reads are checked (AgainstHeads), at every size, with the roots it
// keeps between looks never standing for entries that are no longer the
// ones they were made from.
func TestALookIsCheckedAgainstHeadsAsTheEntriesAre(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	appendRecords(t, path, 0, 20)
	events, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	var heads []Head
	for n := 0; n <= len(events); n++ {
		h, err := TreeHead(events[:n], time.Now())
		if err != nil {
			t.Fatal(err)
		}
		heads = append(heads, h)
	}
	x := NewIndex(path)
	same := func(when string, heads []Head) *Problem {
		t.Helper()
		want, rerr := Read(path)
		want, _ = Entries(want, rerr)
		s, err := x.Look()
		if err != nil {
			t.Fatalf("%s: %v", when, err)
		}
		got, exp := s.AgainstHeads(heads), AgainstHeads(want, heads)
		if !reflect.DeepEqual(got, exp) {
			t.Fatalf("%s: a look says %+v against the heads, the entries %+v", when, got, exp)
		}
		return got
	}
	for i := 0; i < 2; i++ {
		if p := same(fmt.Sprint("every head, look ", i), heads); p != nil {
			t.Fatalf("a log does not extend its own heads: %v", p.Reason)
		}
	}
	for n := 1; n <= len(events); n++ {
		wrong := heads[n]
		wrong.Root = heads[n-1].Root
		if p := same(fmt.Sprint("a wrong root at ", n), []Head{heads[n], wrong}); p == nil || p.Seq != int64(n) {
			t.Fatalf("a head at %d whose root is not the log's: %+v", n, p)
		}
	}

	// Edited in place, keeping the length: the roots kept are not the log's.
	rewrite(t, path, func(b []byte) []byte { return bytes.Replace(b, []byte(`"/r/3"`), []byte(`"/r/X"`), 1) })
	if p := same("edited in place", heads); p == nil {
		t.Fatal("a log edited in place still extends the heads taken before")
	}
	rewrite(t, path, func(b []byte) []byte { return bytes.Replace(b, []byte(`"/r/X"`), []byte(`"/r/3"`), 1) })
	same("edited back", heads)

	// Cut back, and grown again past every head with a torn line in it.
	rewrite(t, path, func(b []byte) []byte {
		lines := bytes.SplitAfter(b, []byte("\n"))
		return bytes.Join(lines[:12], nil)
	})
	if p := same("cut back", heads); p == nil || !strings.Contains(p.Reason, "shrunk") {
		t.Fatalf("a log cut back behind its heads: %+v", p)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"seq":13,"at":"2026-10`)
	f.Close()
	appendRecords(t, path, 100, 12)
	if p := same("grown again", heads); p == nil || p.Seq != 13 {
		t.Fatalf("a log cut back and grown again past its heads: %+v", p)
	}
	// An unfinished last line that is a whole entry is a leaf, as it is to
	// Read, and is not kept as one.
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.TrimSuffix(b, []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	now, _ := Read(path)
	now, _ = Entries(now, nil)
	last, _ := TreeHead(now, time.Now())
	if p := same("an unfinished last entry", []Head{last}); p != nil {
		t.Fatalf("the log does not extend its own head over an unfinished last entry: %v", p.Reason)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	same("finished", []Head{last})
}

// A snapshot of entries in memory is checked against heads as those entries
// are, an empty log among them, which has no index to keep roots in.
func TestASnapshotOfEntriesIsCheckedAgainstHeadsAsTheyAre(t *testing.T) {
	events := logOf(t, 6)
	five, _ := TreeHead(events[:5], time.Now())
	empty, _ := TreeHead(nil, time.Now())
	for _, c := range [][]Event{nil, {}, events[:3], events} {
		for _, heads := range [][]Head{nil, {empty}, {five}, {empty, five}} {
			if got, want := SnapshotOf(c).AgainstHeads(heads), AgainstHeads(c, heads); !reflect.DeepEqual(got, want) {
				t.Errorf("%d entries against %d heads: a snapshot says %+v, the entries %+v", len(c), len(heads), got, want)
			}
		}
	}
}

// Where every line is an entry, a look and Check report the problems Verify
// reports, in the order Verify reports them, the order of the file, though
// the entries are not in the order of their numbers. Lines moved within a
// log, or an entry's number edited, are what puts them out of it, and the
// look and Check put the problems in the order of the numbers instead,
// unlike Verify, which the look is held to wherever the log can be read.
func TestALookOfEntriesOutOfOrderSaysWhatVerifySays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	appendRecords(t, path, 0, 5)
	rewrite(t, path, func(b []byte) []byte {
		lines := bytes.SplitAfter(b, []byte("\n"))
		lines[1], lines[3] = lines[3], lines[1]
		return bytes.Join(lines, nil)
	})
	events, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	_, want := Verify(events)
	if r, err := Check(events, nil); err != nil || !reflect.DeepEqual(r.Problems, want) {
		t.Errorf("Check says %+v, Verify %+v", r.Problems, want)
	}
	sameAsRead(t, NewIndex(path), path, "two lines swapped")
}
