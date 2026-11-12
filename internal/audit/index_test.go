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
	"sync"
	"testing"
)

// sameAsRead fails the test unless a look at the file reports what Read and
// Verify report for it: the entries, the problems, and a refusal.
func sameAsRead(t *testing.T, x *Index, path, when string) *Snapshot {
	t.Helper()
	want, rerr := Read(path)
	s, err := x.Look()
	if rerr != nil || err != nil {
		if rerr == nil || err == nil {
			t.Fatalf("%s: Read says %v and a look says %v", when, rerr, err)
		}
		return nil
	}
	if s.Len() != len(want) {
		t.Fatalf("%s: a look holds %d entries and Read %d", when, s.Len(), len(want))
	}
	intact, problems := Verify(want)
	if s.Intact() != intact || !reflect.DeepEqual(s.Problems(), problems) {
		t.Errorf("%s: a look says intact=%v %v, Verify %v %v", when, s.Intact(), s.Problems(), intact, problems)
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
