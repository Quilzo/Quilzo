// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package audit

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A log that is not a regular file is read to its end. Read measures a log
// before it reads it, so that a record still being written is not taken for
// a write a crash left unfinished (settled), and a pipe has no size to
// measure. Read took it for an empty file: no entries and no error, which
// Check calls an intact log, of a log nobody had read. It lives in its own
// file because a named pipe is made with a call Windows does not have.
func TestALogReadThroughAPipeIsReadToItsEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	appendRecords(t, path, 0, 3)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// With a line that is not an entry after the three, so that what Read
	// says of the pipe is seen to be what it read, not what it assumed.
	body = append(body, "not an entry\n"...)

	pipe := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("no named pipe can be made here: %v", err)
	}
	// Each end's open waits for the other, so the log is written from
	// beside the read.
	wrote := make(chan error, 1)
	go func() {
		w, err := os.OpenFile(pipe, os.O_WRONLY, 0)
		if err != nil {
			wrote <- err
			return
		}
		_, err = w.Write(body)
		w.Close()
		wrote <- err
	}()
	events, rerr := Read(pipe)
	// A reader that left without reading fails the write, so what was read
	// is looked at first.
	werr := <-wrote
	r, err := Check(events, rerr)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || r.Intact || len(r.Problems) != 1 {
		t.Fatalf("a log of three entries and a line that is not one, read through a pipe, "+
			"is %d entries and %+v", len(events), r)
	}
	if werr != nil {
		t.Fatal(werr)
	}
}
