// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/browser"
)

// What a person does to a taken-over page is left a line at a time for the
// process holding it: whole lines only, never a half-written one, and
// nothing at all once that process is gone.
func TestWhatAPersonDoesIsLeftWholeAndOnlyForALivingWait(t *testing.T) {
	root := t.TempDir()
	id := "run-20260101-00000000"
	rec := agent.Record{ID: id, State: agent.Running, Beat: time.Now(),
		Trace: agent.Trace{Waiting: &agent.Pending{N: 1, Live: true,
			Action: agent.Action{Op: "browser_click"}}}}
	now := time.Now()

	// Nothing waiting, nothing taken over.
	stopped := rec
	stopped.Trace.Waiting = nil
	if err := appendPersonNote(root, stopped, personNote{By: "ana"}, now); err == nil {
		t.Error("a note was left for a run that is waiting on nothing")
	}
	// A process that has gone: beats stopped, so hands that arrive now
	// touch nothing.
	gone := rec
	gone.Beat = now.Add(-2 * agent.StaleAfter)
	if err := appendPersonNote(root, gone, personNote{By: "ana"}, now); err == nil {
		t.Error("a note was left for a process that has ended")
	}

	// Left a line at a time, and read whole: a half-written line waits for
	// its rest rather than acting as it lies.
	var got []browser.PersonInput
	for _, in := range []browser.PersonInput{
		{Click: []float64{120, 40}},
		{Type: "typed by hand"},
		{Key: "Enter"},
	} {
		if err := appendPersonNote(root, rec, personNote{PersonInput: in, By: "ana", At: now}, now); err != nil {
			t.Fatal(err)
		}
		got = append(got, in)
	}
	// A partial line, as a process would leave it mid-write.
	f, err := os.OpenFile(personPath(root, id), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"key":"Tab","`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	var seen []browser.PersonInput
	off := watchPerson(root, id, 0, func(in browser.PersonInput, by string) {
		if by != "ana" {
			t.Errorf("the note carried %q as its person", by)
		}
		seen = append(seen, in)
	})
	if len(seen) != len(got) {
		t.Fatalf("%d of %d notes were read whole", len(seen), len(got))
	}
	for i := range got {
		if seen[i].Key != got[i].Key || seen[i].Type != got[i].Type || len(seen[i].Click) != len(got[i].Click) {
			t.Errorf("note %d arrived as %+v, not %+v", i, seen[i], got[i])
		}
	}
	// The partial line completes, and only then is it read.
	f, err = os.OpenFile(personPath(root, id), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`by":"ana"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	seen = nil
	off = watchPerson(root, id, off, func(in browser.PersonInput, by string) { seen = append(seen, in) })
	if len(seen) != 1 || seen[0].Key != "Tab" {
		t.Fatalf("the completed line arrived as %+v", seen)
	}
	// Nothing new, nothing read.
	seen = nil
	watchPerson(root, id, off, func(in browser.PersonInput, by string) { seen = append(seen, in) })
	if len(seen) != 0 {
		t.Errorf("%d notes were read again", len(seen))
	}
}

// A file replaced under the reader starts over rather than reading from a
// place that no longer means anything.
func TestAPersonFileReplacedStartsOver(t *testing.T) {
	root := t.TempDir()
	id := "run-20260101-00000001"
	dir := filepath.Dir(personPath(root, id))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.Write(personPath(root, id), []byte(`{"key":"Tab","by":"ana"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var seen []browser.PersonInput
	off := watchPerson(root, id, 1<<20, func(in browser.PersonInput, by string) { seen = append(seen, in) })
	if len(seen) != 1 || seen[0].Key != "Tab" {
		t.Fatalf("a replaced file was not read from the start: %+v", seen)
	}
	if off == 1<<20 {
		t.Error("the offset did not follow the new file")
	}
}

// The record offers a live question before the process holding it starts
// to look, so an answer can be there first. It is this question's, and is
// taken: removing whatever was there left the run waiting, for an answer
// that had been given, until its time ran out. One left for an earlier
// question at the same step is still not taken for this one.
func TestAQuickAnswerIsNotLost(t *testing.T) {
	root := t.TempDir()
	id := "run-20260101-00000001"
	asked := time.Now().UTC()
	w := agent.Pending{N: 3, Live: true, Asked: asked, Action: agent.Action{Op: "shell_run"}}
	rec := agent.Record{ID: id, State: agent.Running, Beat: time.Now(), Trace: agent.Trace{Waiting: &w}}
	if err := os.MkdirAll(agentRunsDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	hold := programHold(root, id, nil, nil, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Answered between the record offering it and the hold looking.
	if err := answerLive(root, rec, agent.Verdict{N: 3, Approve: false}, "lee", time.Now()); err != nil {
		t.Fatal(err)
	}
	v, err := hold(ctx, w, func() {})
	if err != nil || v.Approve || v.By != "lee" {
		t.Fatalf("an answer given before the hold looked: %+v %v", v, err)
	}

	// An answer to the step's earlier question, left late, is not this
	// one's: the hold waits on, and takes the answer that is.
	earlier := rec
	before := w
	before.Asked = asked.Add(-time.Second)
	earlier.Trace.Waiting = &before
	if err := answerLive(root, earlier, agent.Verdict{N: 3, Approve: true}, "pat", time.Now()); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(2 * holdPoll)
		_ = answerLive(root, rec, agent.Verdict{N: 3, Approve: false}, "lee", time.Now())
	}()
	v, err = hold(ctx, w, func() {})
	if err != nil || v.Approve || v.By != "lee" {
		t.Fatalf("the earlier question's answer was taken for this one: %+v %v", v, err)
	}
}
