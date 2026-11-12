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
// A look reports what Read and Verify would report for the same bytes: the
// same entries, the same problems, and the same refusal of an entry that
// cannot be read.

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

	// last is the most recent look, and began is when it started reading.
	last  *Snapshot
	began time.Time
}

// NewIndex indexes the log at path. Nothing is read until the first look.
func NewIndex(path string) *Index { return &Index{path: path} }

func (x *Index) reset() {
	x.size, x.digest = 0, nil
	x.entries, x.problems, x.chain = nil, nil, link{}
	x.actions, x.strs = map[string]bool{}, map[string]string{}
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
		return x.snapshot(nil, x.problems), nil
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
			e, problems, rerr := x.read(line, off, &x.chain, x.problems)
			if rerr != nil {
				return nil, rerr
			}
			x.problems = problems
			if e != nil {
				x.entries = append(x.entries, *e)
				x.actions[e.Action] = true
			}
			h.Write(line)
			off += int64(n)
			x.size = off
			continue
		}
		// A last line with no end yet. Read takes it as an entry, so this
		// does too, without keeping it: the next look reads it again, by
		// when it may have been finished, and only whole lines are indexed.
		var extra *Entry
		problems := x.problems[:len(x.problems):len(x.problems)]
		if len(line) > 0 {
			c := x.chain
			e, p, rerr := x.read(line, off, &c, problems)
			if rerr != nil {
				return nil, rerr
			}
			extra, problems = e, p
		}
		return x.snapshot(extra, problems), nil
	}
}

// read takes one line as Read does: a blank one is skipped, and one that is
// not an entry is refused, numbered as Read numbers it.
func (x *Index) read(line []byte, off int64, chain *link, problems []Problem) (*Entry, []Problem, error) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil, problems, nil
	}
	var e Event
	if err := json.Unmarshal(trimmed, &e); err != nil {
		return nil, problems, fmt.Errorf("entry %d is not readable: %w", len(x.entries)+1, err)
	}
	problems = chain.check(&e, problems)
	sum := sha256.Sum256(line)
	ent := &Entry{Seq: e.Seq, Action: x.intern(e.Action), Outcome: Outcome(x.intern(string(e.Outcome))),
		Principal: x.intern(e.Principal), off: off, n: len(line)}
	copy(ent.sum[:], sum[:])
	return ent, problems, nil
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

func (x *Index) snapshot(extra *Entry, problems []Problem) *Snapshot {
	names := make([]string, 0, len(x.actions)+1)
	for a := range x.actions {
		names = append(names, a)
	}
	if extra != nil && !x.actions[extra.Action] {
		names = append(names, extra.Action)
	}
	sort.Strings(names)
	// Capped, so that what is appended to the index later lands beyond what
	// this look can see rather than in it.
	return &Snapshot{path: x.path, entries: x.entries[:len(x.entries):len(x.entries)],
		extra: extra, problems: problems[:len(problems):len(problems)], actions: names}
}

// Snapshot is a log as one look found it. It does not change, and is safe
// to read from several goroutines at once.
type Snapshot struct {
	path     string
	entries  []Entry
	extra    *Entry
	problems []Problem
	actions  []string
	// events, for a snapshot of events already in memory (SnapshotOf).
	events []Event
}

// SnapshotOf is a snapshot of events already in memory, for a caller that
// has them rather than a file.
func SnapshotOf(events []Event) *Snapshot {
	s := &Snapshot{events: events, entries: make([]Entry, len(events))}
	_, s.problems = Verify(events)
	seen := map[string]bool{}
	for i, e := range events {
		s.entries[i] = Entry{Seq: e.Seq, Action: e.Action, Outcome: e.Outcome, Principal: e.Principal}
		if !seen[e.Action] {
			seen[e.Action] = true
			s.actions = append(s.actions, e.Action)
		}
	}
	sort.Strings(s.actions)
	return s
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

// Intact is whether the whole chain verifies.
func (s *Snapshot) Intact() bool { return len(s.problems) == 0 }

// Problems are the breaks in the chain, as Verify reports them.
func (s *Snapshot) Problems() []Problem { return s.problems }

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
