// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func rec(n int) Record {
	return Record{Action: "test.write", Resource: "/", Outcome: Success, Principal: fmt.Sprint("p", n), Kind: KindHuman}
}

// Writers each with their own handle, as every audited action has — the
// admin's requests, the site's, the command line's — keep one chain and
// lose no record.
func TestConcurrentWritersKeepOneChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				l, err := New(Options{Path: path, Source: "test"})
				if err != nil {
					errs <- err
					return
				}
				if _, err := l.Append(rec(g*100 + i)); err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	events, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 200 {
		t.Errorf("%d of 200 records kept", len(events))
	}
	if ok, problems := Verify(events); !ok {
		t.Errorf("the chain forked: %v", problems[:min(3, len(problems))])
	}
}

// A handle that has been idle while others wrote carries on from the end of
// the file, not from where it last was.
func TestAnIdleHandlePicksTheChainUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := New(Options{Path: path, Source: "a"})
	b, _ := New(Options{Path: path, Source: "b"})
	for i := 0; i < 3; i++ {
		if _, err := a.Append(rec(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Append(rec(9)); err != nil {
		t.Fatal(err)
	}
	events, _ := Read(path)
	if ok, problems := Verify(events); !ok || events[3].Seq != 4 {
		t.Errorf("seq %d, %v", events[3].Seq, problems)
	}
}

// Opening a log reads its last entry, not the whole file: the chain resumes
// from the end, whatever the length of the line before it.
func TestOpeningReadsTheTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := New(Options{Path: path, Source: "test"})
	big := Record{Action: "test.write", Resource: "/", Outcome: Success, Principal: "p", Kind: KindHuman,
		Detail: map[string]string{"note": strings.Repeat("x", 200<<10)}}
	for i := 0; i < 3; i++ {
		if _, err := l.Append(big); err != nil {
			t.Fatal(err)
		}
	}
	last, _, torn, err := tail(path)
	events, _ := Read(path)
	if err != nil || torn || last == nil || last.Hash != events[len(events)-1].Hash {
		t.Fatalf("tail %+v torn %v: %v", last, torn, err)
	}
	m, err := New(Options{Path: path, Source: "test"})
	if err != nil || m.seq != 3 || m.last != events[2].Hash {
		t.Errorf("resumed at %d: %v", m.seq, err)
	}
}

// A line a writer died part way through does not stop later writes: it is
// closed off, stays visible as an unreadable entry, and the chain carries
// on from the last whole entry.
func TestATornLineIsClosedOffNotFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := New(Options{Path: path, Source: "test"})
	first, err := l.Append(rec(1))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString(`{"seq":2,"at":"2026-10`)
	f.Close()
	m, err := New(Options{Path: path, Source: "test"})
	if err != nil {
		t.Fatalf("a torn line stopped the log opening: %v", err)
	}
	next, err := m.Append(rec(2))
	if err != nil {
		t.Fatalf("a torn line stopped later writes: %v", err)
	}
	if next.Prev != first.Hash || next.Seq != 2 {
		t.Errorf("the chain did not carry on from the last whole entry: %+v", next)
	}
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], `{"seq":2,"at":"2026-10`) {
		t.Errorf("the torn line was not kept on a line of its own:\n%s", raw)
	}
	if _, err := Read(path); err == nil {
		t.Error("the torn line is not reported")
	}
}

// A torn line that was closed off, with nothing written after it, does not
// stop the log opening: a full disk cuts a record short, the next write
// manages the newline that closes it and not the record, and every write
// after that was refused because the last line was not an entry.
func TestATornLineClosedOffLastDoesNotStopTheLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := New(Options{Path: path, Source: "test"})
	first, err := l.Append(rec(1))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString(`{"seq":2,"at":"2026-10` + "\n")
	f.Close()
	m, err := New(Options{Path: path, Source: "test"})
	if err != nil {
		t.Fatalf("a closed-off torn line stopped the log opening: %v", err)
	}
	next, err := m.Append(rec(2))
	if err != nil || next.Prev != first.Hash || next.Seq != 2 {
		t.Fatalf("the chain did not carry on from the last whole entry: %+v %v", next, err)
	}

	// A last line that is not an entry and was not cut short still stops
	// it: the chain cannot be continued from something that is not part of
	// it, and nothing a crash leaves looks like that.
	f, _ = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString("{not json\n")
	f.Close()
	if _, err := New(Options{Path: path, Source: "test"}); err == nil {
		t.Error("a log ending in a line that is not an entry was opened")
	}
}

// A line a writer died part way through is reported where it is, and every
// entry after it is still read. Reading stopped at it, so one crash made
// every record written after it unreadable by every reader of the log, for
// good, and verifying reported it as entry 0 of a log one entry long.
func TestATornLineHidesNoEntryAfterIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := New(Options{Path: path, Source: "test"})
	if _, err := l.Append(rec(1)); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString(`{"seq":2,"at":"2026-10`)
	f.Close()
	m, _ := New(Options{Path: path, Source: "test"})
	for i := 2; i <= 3; i++ {
		if _, err := m.Append(rec(i)); err != nil {
			t.Fatal(err)
		}
	}

	events, err := Read(path)
	if err == nil {
		t.Error("the torn line is not reported")
	}
	if len(events) != 3 || events[2].Seq != 3 {
		t.Fatalf("read %d entries of 3", len(events))
	}
	n, intact, problems, err := VerifyFile(path)
	if err != nil || n != 3 || intact || len(problems) != 1 || problems[0].Seq != 1 {
		t.Errorf("verified %d entries, intact %v, %+v, %v", n, intact, problems, err)
	}

	var bad *Unreadable
	if _, err := Read(path); !errors.As(err, &bad) || len(bad.Lines) != 1 ||
		bad.Lines[0].Line != 2 || bad.Lines[0].After != 1 || !bad.Lines[0].Torn {
		t.Errorf("the torn line is reported as %+v", bad)
	}
	if whole, err := Entries(Read(path)); err != nil || len(whole) != 3 {
		t.Errorf("a reader of the entries got %d: %v", len(whole), err)
	}
	r, err := Check(Read(path))
	if err != nil || r.Intact || !r.Crashed() || !strings.Contains(r.Problems[0].Reason, "unfinished") {
		t.Errorf("checked: %+v %v", r, err)
	}

	// A line nothing cut short is not a crash's, and another reading error
	// is not a report at all.
	f, _ = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString("{not json\n")
	f.Close()
	if r, err := Check(Read(path)); err != nil || r.Crashed() || len(r.Problems) != 2 {
		t.Errorf("a line that is not an entry: %+v %v", r, err)
	}
	if _, err := Check(nil, os.ErrPermission); !errors.Is(err, os.ErrPermission) {
		t.Errorf("a log that could not be read was checked: %v", err)
	}
}
