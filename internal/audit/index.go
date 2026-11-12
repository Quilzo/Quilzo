// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

// An index of a log, for a reader that shows it a page at a time.
//
// # What this is for
//
// The admin's log page read the whole file on every view: every entry parsed
// into memory, the chain verified, and a row built for each, before two
// hundred of them were shown. A year of logging is a hundred megabytes and
// more, and one view of it took seconds and hundreds of megabytes; six at
// once took the server past two gigabytes. The cost grew with the log, and
// visitors are among those who add to it.
//
// An Index reads the file once and after that only what has been appended,
// keeping for each entry the little a filter needs and where its line is.
// The entries a page shows are read back from the file by position.
//
// # What it must not give up
//
// The page says whether the whole chain verifies, and a cache is exactly how
// a viewer comes to report an edited log as intact. So nothing is trusted
// because it was read before. Each look hashes every byte already indexed
// and compares the digest with the one taken when they were read, and any
// difference, whether an edit in place that keeps the length, a truncation or
// a rewrite, discards the index and verifies the file again from its first
// line. That is one pass of SHA-256 over the file, a small part of what
// parsing and re-hashing every entry costs. Each line shown is checked
// against the digest of the line that was verified, so a file edited between
// the look and the read is not shown as the file that verified.
//
// A look reports what Read and Check would report for the same bytes: the
// same entries, the same problems, among them each line that is not an
// entry, as Read reports it (Unreadable), and the same refusal of a line
// too long to be read.
//
// # The heads saved beside it
//
// A view checks the log against every head saved from it, as `auditlog
// verify` does (AgainstHeads), and that needs the tree's root over the
// first n entries for each head of n. So the index keeps each entry's leaf,
// and the roots it has made, for as long as what it has indexed stands: a
// view after the first costs a lookup for each head it has seen before.

// ErrChanged is a line that is no longer the line that was verified.
var ErrChanged = errors.New("the audit log changed while it was being read")

// maxEntryLine is the longest line Read accepts as an entry.
const maxEntryLine = 4 << 20

// Entry is what an index keeps of one entry: what a filter needs, and where
// its line is.
type Entry struct {
	Seq       int64
	Action    string
	Outcome   Outcome
	Principal string

	off int64
	n   int
	// sum is the start of the SHA-256 of the line as it was verified.
	sum [16]byte
	// leaf is the entry's leaf in the tree (LeafHash), when hashed says it
	// could be made.
	leaf   [32]byte
	hashed bool
}

// Index is one log file, read once and then as it grows.
type Index struct {
	path string

	mu sync.Mutex
	// size is how much of the file is indexed, always whole lines, and
	// digest is the SHA-256 of those bytes.
	size     int64
	digest   []byte
	entries  []Entry
	problems []Problem
	chain    link
	actions  map[string]bool
	strs     map[string]string
	// lines is how many lines of the file are indexed, blank ones and those
	// that are not entries among them, and bad is the lines that are not
	// entries (BadLine), numbered as Read numbers them.
	lines int
	bad   []BadLine
	// gen counts the times the index was discarded and read again: what a
	// look of one generation holds of the file, the next look of the same
	// generation holds too, unchanged.
	gen uint64

	// last is the most recent look, and began is when it started reading.
	last  *Snapshot
	began time.Time

	// roots are the tree's roots at the sizes asked for so far, over the
	// entries of generation rootsGen (Snapshot.AgainstHeads), apart from the
	// lock a look holds while it reads.
	rootsMu  sync.Mutex
	roots    map[int][]byte
	rootsGen uint64
}

// NewIndex indexes the log at path. Nothing is read until the first look.
func NewIndex(path string) *Index { return &Index{path: path} }

func (x *Index) reset() {
	x.size, x.digest = 0, nil
	x.entries, x.problems, x.chain = nil, nil, link{}
	x.actions, x.strs = map[string]bool{}, map[string]string{}
	x.lines, x.bad = 0, nil
	x.gen++
}

// intern keeps one copy of a string that thousands of entries share: an
// action, an outcome, a person's handle.
func (x *Index) intern(s string) string {
	if v, ok := x.strs[s]; ok {
		return v
	}
	x.strs[s] = s
	return s
}

// Look brings the index up to date with the file and returns what it holds.
//
// A look that waited while another was reading takes that one's result when
// it began after this one was asked for, so a burst of views reads the file
// once or twice rather than once each.
func (x *Index) Look() (*Snapshot, error) {
	asked := time.Now()
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.last != nil && x.began.After(asked) {
		return x.last, nil
	}
	began := time.Now()
	s, err := x.refresh()
	if err != nil {
		x.last = nil
		return nil, err
	}
	x.last, x.began = s, began
	return s, nil
}

func (x *Index) refresh() (*Snapshot, error) {
	if x.actions == nil {
		x.reset()
	}
	f, err := os.Open(x.path)
	if os.IsNotExist(err) {
		x.reset()
		return x.snapshot(nil, nil, x.problems), nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()

	// What was read before is read again, as bytes, and believed only if
	// it is the same bytes.
	h := sha256.New()
	if size < x.size {
		x.reset()
	} else if x.size > 0 {
		if _, err := io.CopyN(h, f, x.size); err != nil {
			return nil, err
		}
		if !bytes.Equal(h.Sum(nil), x.digest) {
			x.reset()
			h.Reset()
		}
	}
	if _, err := f.Seek(x.size, io.SeekStart); err != nil {
		return nil, err
	}
	// Up to the size the file had when this look began: what is appended
	// meanwhile is the next look's.
	r := bufio.NewReaderSize(io.LimitReader(f, size-x.size), 64<<10)
	off := x.size
	defer func() { x.digest = h.Sum(nil) }()
	for {
		line, err := readLine(r)
		if err != nil && err != io.EOF {
			if errors.Is(err, errLineTooLong) {
				return nil, fmt.Errorf("entry %d is longer than an entry may be", len(x.entries)+1)
			}
			return nil, err
		}
		if n := len(line); n > 0 && line[n-1] == '\n' {
			x.lines++
			e, bad, problems := x.read(line, off, x.lines, &x.chain, x.problems)
			x.problems = problems
			if e != nil {
				x.entries = append(x.entries, *e)
				x.actions[e.Action] = true
			}
			if bad != nil {
				x.bad = append(x.bad, *bad)
			}
			h.Write(line)
			off += int64(n)
			x.size = off
			continue
		}
		// A last line with no end yet. Read takes it as an entry, or as a
		// line that is not one, so this does too, without keeping it: the
		// next look reads it again, by when it may have been finished, and
		// only whole lines are indexed.
		var extra *Entry
		var extraBad *BadLine
		problems := x.problems[:len(x.problems):len(x.problems)]
		if len(line) > 0 {
			c := x.chain
			extra, extraBad, problems = x.read(line, off, x.lines+1, &c, problems)
		}
		return x.snapshot(extra, extraBad, problems), nil
	}
}

// read takes one line, the file's line number no, as Read does: a blank one
// is skipped, and one that is not an entry is a BadLine, after the last
// entry before it, and read past.
func (x *Index) read(line []byte, off int64, no int, chain *link, problems []Problem) (*Entry, *BadLine, []Problem) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil, nil, problems
	}
	var e Event
	if err := json.Unmarshal(trimmed, &e); err != nil {
		b := &BadLine{Line: no, Torn: unfinished(string(trimmed)), Err: err}
		if n := len(x.entries); n > 0 {
			b.After = x.entries[n-1].Seq
		}
		return nil, b, problems
	}
	want, herr := e.computeHash()
	problems = chain.checkHashed(&e, want, herr, problems)
	sum := sha256.Sum256(line)
	ent := &Entry{Seq: e.Seq, Action: x.intern(e.Action), Outcome: Outcome(x.intern(string(e.Outcome))),
		Principal: x.intern(e.Principal), off: off, n: len(line)}
	copy(ent.sum[:], sum[:])
	if leaf, err := leafOf(&e, want, herr); err == nil && len(leaf) == len(ent.leaf) {
		copy(ent.leaf[:], leaf)
		ent.hashed = true
	}
	return ent, nil, problems
}

var errLineTooLong = errors.New("line too long")

// readLine is the next line with its newline, or what is left at the end.
//
// A line Read refuses is refused here, to the byte: one longer than
// maxEntryLine with its newline, or a last line without one that is
// maxEntryLine long or more, because Read's scanner has to hold a line whole
// and still have room to see that it ended. The length was looked at only
// between reads, so a line up to a buffer's worth past the limit was taken,
// and the log page called intact a log that `auditlog verify` could not read.
func readLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		long := append([]byte(nil), line...)
		for err == bufio.ErrBufferFull {
			if len(long) > maxEntryLine {
				return nil, errLineTooLong
			}
			line, err = r.ReadSlice('\n')
			long = append(long, line...)
		}
		line = long
	}
	if n := len(line); n > maxEntryLine || n == maxEntryLine && line[n-1] != '\n' {
		return nil, errLineTooLong
	}
	return line, err
}

func (x *Index) snapshot(extra *Entry, extraBad *BadLine, problems []Problem) *Snapshot {
	names := make([]string, 0, len(x.actions)+1)
	for a := range x.actions {
		names = append(names, a)
	}
	if extra != nil && !x.actions[extra.Action] {
		names = append(names, extra.Action)
	}
	sort.Strings(names)
	bad := x.bad[:len(x.bad):len(x.bad)]
	if extraBad != nil {
		bad = append(bad, *extraBad)
	}
	// Capped, so that what is appended to the index later lands beyond what
	// this look can see rather than in it.
	return &Snapshot{path: x.path, entries: x.entries[:len(x.entries):len(x.entries)],
		extra: extra, report: reportOf(problems[:len(problems):len(problems)], bad), actions: names,
		index: x, gen: x.gen}
}

// Snapshot is a log as one look found it. It does not change, and is safe
// to read from several goroutines at once.
type Snapshot struct {
	path    string
	entries []Entry
	extra   *Entry
	// report is what the look found wrong: breaks in the chain, and lines
	// that are not entries (Check).
	report  Report
	actions []string
	// events, for a snapshot of events already in memory (SnapshotOf).
	events []Event
	// index and gen are the index this look is of and its generation, for
	// the roots it keeps (AgainstHeads).
	index *Index
	gen   uint64
}

// SnapshotOf is a snapshot of events already in memory, for a caller that
// has them rather than a file.
func SnapshotOf(events []Event) *Snapshot {
	s, _ := SnapshotOfRead(events, nil)
	return s
}

// SnapshotOfRead is a snapshot of what Read or Events returned, for a caller
// that has that rather than a file: its lines that are not entries among
// what it found, as Check has them. Any other error reading the log is
// returned, since then nothing can be said.
func SnapshotOfRead(events []Event, readErr error) (*Snapshot, error) {
	report, err := Check(events, readErr)
	if err != nil {
		return nil, err
	}
	s := &Snapshot{events: events, entries: make([]Entry, len(events)), report: report}
	seen := map[string]bool{}
	for i, e := range events {
		s.entries[i] = Entry{Seq: e.Seq, Action: e.Action, Outcome: e.Outcome, Principal: e.Principal}
		if !seen[e.Action] {
			seen[e.Action] = true
			s.actions = append(s.actions, e.Action)
		}
	}
	sort.Strings(s.actions)
	return s, nil
}

// Len is how many entries the log holds.
func (s *Snapshot) Len() int {
	if s.extra != nil {
		return len(s.entries) + 1
	}
	return len(s.entries)
}

// Entry is the i-th entry, in the order of the file.
func (s *Snapshot) Entry(i int) Entry {
	if i == len(s.entries) && s.extra != nil {
		return *s.extra
	}
	return s.entries[i]
}

// Intact is whether the whole chain verifies and every line is an entry.
func (s *Snapshot) Intact() bool { return s.report.Intact }

// Problems are the breaks in the chain and the lines that are not entries,
// as Check reports them.
func (s *Snapshot) Problems() []Problem { return s.Report().Problems }

// Report is what the look found, as Check reports it for the same bytes.
// Its problems are capped, so that a caller adding to them, as a view adds
// what the heads say, writes to its own copy and not to the snapshot every
// other view shares.
func (s *Snapshot) Report() Report {
	r := s.report
	r.Problems = r.Problems[:len(r.Problems):len(r.Problems)]
	return r
}

// AgainstHeads is what is wrong with the log against every head taken from
// it earlier, as AgainstHeads says it for the entries Read reads: nil when
// it still extends each one.
func (s *Snapshot) AgainstHeads(heads []Head) *Problem {
	if s.index == nil {
		// Entries in memory (SnapshotOf), none at all among them.
		return AgainstHeads(s.events, heads)
	}
	ls := leaves{s.Len(), s.leaf}
	return againstHeads(ls, heads, func(sizes map[int]bool) (map[int][]byte, error) {
		return s.index.rootsAt(s, ls, sizes)
	})
}

// leaf is the i-th entry's leaf in the tree, as LeafHash makes it.
func (s *Snapshot) leaf(i int) ([]byte, error) {
	if ent := s.Entry(i); ent.hashed {
		return ent.leaf[:], nil
	}
	// One that could not be hashed when it was read, which LeafHash says
	// why of, as it would for the whole log.
	events, err := s.Events([]int{i})
	if err != nil {
		return nil, err
	}
	return LeafHash(events[0])
}

// rootsAt is the tree's roots at these sizes over a look's leaves, kept for
// the next look of the same generation, which holds the same entries. The
// unfinished last line is not kept, nor anything of an older generation.
func (x *Index) rootsAt(s *Snapshot, ls leaves, sizes map[int]bool) (map[int][]byte, error) {
	x.rootsMu.Lock()
	defer x.rootsMu.Unlock()
	keep := s.gen >= x.rootsGen
	if s.gen > x.rootsGen || x.roots == nil {
		x.roots, x.rootsGen = map[int][]byte{}, s.gen
	}
	out := make(map[int][]byte, len(sizes))
	missing := map[int]bool{}
	for n := range sizes {
		if r, ok := x.roots[n]; ok && keep && n <= len(s.entries) {
			out[n] = r
		} else {
			missing[n] = true
		}
	}
	if len(missing) == 0 {
		return out, nil
	}
	made, err := rootsOf(ls, missing)
	if err != nil {
		return nil, err
	}
	for n, r := range made {
		out[n] = r
		if keep && n <= len(s.entries) {
			x.roots[n] = r
		}
	}
	return out, nil
}

// Actions are the actions the log holds, each once, in order.
func (s *Snapshot) Actions() []string { return s.actions }

// Events reads the entries at these positions in full. A line that is no
// longer the one that was verified is ErrChanged, and nothing is returned:
// the caller looks again, and that look sees the change.
func (s *Snapshot) Events(at []int) ([]Event, error) {
	out := make([]Event, 0, len(at))
	if s.events != nil {
		for _, i := range at {
			out = append(out, s.events[i])
		}
		return out, nil
	}
	if len(at) == 0 {
		return out, nil
	}
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return nil, ErrChanged
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	for _, i := range at {
		ent := s.Entry(i)
		line := make([]byte, ent.n)
		if _, err := f.ReadAt(line, ent.off); err != nil {
			if err == io.EOF {
				return nil, ErrChanged
			}
			return nil, err
		}
		if sum := sha256.Sum256(line); !bytes.Equal(sum[:len(ent.sum)], ent.sum[:]) {
			return nil, ErrChanged
		}
		var e Event
		if err := json.Unmarshal(bytes.TrimSpace(line), &e); err != nil {
			return nil, ErrChanged
		}
		out = append(out, e)
	}
	return out, nil
}
