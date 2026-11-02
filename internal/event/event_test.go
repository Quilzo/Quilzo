// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package event

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Written and read back, in order, numbered from one, and marked with the
// log they came from.
func TestAnEventIsKeptAndReadBack(t *testing.T) {
	l := Log{Dir: t.TempDir(), Source: Admin}
	for _, p := range []string{"blog/one", "blog/two"} {
		if _, err := l.Append(Event{Type: PagePublished, Subject: p, Kind: "human"}); err != nil {
			t.Fatal(err)
		}
	}
	got, refused, err := l.Read(0, 0)
	if err != nil || refused != 0 || len(got) != 2 {
		t.Fatalf("%v %d %v", got, refused, err)
	}
	if got[0].Seq != 1 || got[1].Seq != 2 || got[1].Subject != "blog/two" || got[0].Source != Admin ||
		!strings.HasPrefix(got[0].ID, "ev_") || got[0].At.IsZero() {
		t.Fatalf("%+v", got)
	}
	if after, _, _ := l.Read(1, 0); len(after) != 1 || after[0].Seq != 2 {
		t.Fatalf("read after 1: %+v", after)
	}
}

// Many writers at once, in any number of processes, each event gets its
// own number and none is lost.
func TestWritersAtOnceLoseNothing(t *testing.T) {
	l := Log{Dir: t.TempDir(), Source: Site}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if _, err := l.Append(Event{Type: FormSubmitted, Subject: fmt.Sprintf("form-%d", w)}); err != nil {
					t.Error(err)
				}
			}
		}(w)
	}
	wg.Wait()
	got, _, err := l.Read(0, 1000)
	if err != nil || len(got) != 200 {
		t.Fatalf("%d events: %v", len(got), err)
	}
	for i, e := range got {
		if e.Seq != int64(i+1) {
			t.Fatalf("event %d has number %d", i, e.Seq)
		}
	}
}

// The public site writes what visitors do and nothing else: it cannot say
// a page went live, and a line saying so, written into its log by
// something that broke into it, is not believed.
func TestTheSiteCannotSayAPageWentLive(t *testing.T) {
	l := Log{Dir: t.TempDir(), Source: Site}
	if _, err := l.Append(Event{Type: PagePublished, Subject: "index"}); err == nil {
		t.Fatal("the site wrote a publish")
	}
	if _, err := l.Append(Event{Type: HandoffRequested, Subject: "help"}); err != nil {
		t.Fatal(err)
	}
	forged := `{"seq":2,"id":"ev_1","type":"page.published","subject":"index","at":"2026-11-02T10:00:00Z"}` + "\n"
	f, err := os.OpenFile(filepath.Join(l.Dir, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(forged)
	f.Close()
	got, refused, err := l.Read(0, 0)
	if err != nil || refused != 1 || len(got) != 1 || got[0].Type != HandoffRequested {
		t.Fatalf("%+v refused %d %v", got, refused, err)
	}
	// And the admin cannot be told it was the site that wrote its events.
	if (Log{Dir: t.TempDir(), Source: Admin}).Source != Admin {
		t.Fatal("unreachable")
	}
}

// An event names things, never people or what they wrote.
func TestAnEventCarriesNamesNotText(t *testing.T) {
	l := Log{Dir: t.TempDir(), Source: Site}
	for _, subject := range []string{"line one\nline two", strings.Repeat("x", 201), "<script>"} {
		if _, err := l.Append(Event{Type: FormSubmitted, Subject: subject}); err == nil {
			t.Errorf("%q was taken as a subject", subject)
		}
	}
	if _, err := l.Append(Event{Type: "page.deleted"}); err == nil {
		t.Error("an event that does not exist was written")
	}
	pages := make([]string, 80)
	for i := range pages {
		pages[i] = fmt.Sprintf("p%d", i)
	}
	e, err := (Log{Dir: t.TempDir(), Source: Admin}).Append(Event{Type: PagePublished, Pages: pages})
	if err != nil || len(e.Pages) != MaxPages {
		t.Fatalf("%d pages kept: %v", len(e.Pages), err)
	}
}

// A log that grows past its size is rotated, keeping the one before, and a
// reader still part-way through the old one finds the rest.
func TestARotatedLogIsReadAcross(t *testing.T) {
	l := Log{Dir: t.TempDir(), Source: Admin, MaxBytes: 1200}
	for i := 0; i < 12; i++ {
		if _, err := l.Append(Event{Type: RecordChanged, Subject: fmt.Sprintf("events/%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(l.Dir, "events.1.jsonl")); err != nil {
		t.Fatalf("not rotated: %v", err)
	}
	got, _, err := l.Read(0, 0)
	if err != nil || len(got) == 0 || got[len(got)-1].Seq != 12 {
		t.Fatalf("%+v %v", got, err)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Seq != got[i-1].Seq+1 {
			t.Fatalf("a gap between %d and %d", got[i-1].Seq, got[i].Seq)
		}
	}
}

// A process that stopped after writing a line and before keeping its
// number does not have the next event take the same number.
func TestNoNumberIsUsedTwice(t *testing.T) {
	l := Log{Dir: t.TempDir(), Source: Admin}
	for i := 0; i < 3; i++ {
		if _, err := l.Append(Event{Type: PagePublished}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(l.Dir, "seq"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := l.Append(Event{Type: PagePublished})
	if err != nil || e.Seq != 4 {
		t.Fatalf("number %d: %v", e.Seq, err)
	}
}

// Where an event is matched on whole path parts.
func TestWhereIsAPathNotAPrefix(t *testing.T) {
	e := Event{Type: PagePublished, Pages: []string{"blog/first", "about"}}
	for where, want := range map[string]bool{"": true, "/blog": true, "blog/": true, "/blog/first": true,
		"/blo": false, "/blogroll": false, "/shop": false, "about": true} {
		if got := e.Within(where); got != want {
			t.Errorf("Within(%q) = %v", where, got)
		}
	}
	if !(Event{Subject: "enquiries"}).Within("enquiries") {
		t.Error("a form's own name is not within itself")
	}
}
