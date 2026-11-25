// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
)

// `quilzo auditlog dir` is a step of the reference compose's setup, and what
// it said there ran together: "the log is now read from
// /srv/audit/audit.jsonl  start the writer: ...", every line of it written
// without its line break.
func TestAuditlogDirSaysOneThingALine(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	saved := w
	t.Cleanup(func() { w = saved })
	root := filepath.Join(t.TempDir(), "st")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(logs, 0o750); err != nil {
		t.Fatal(err)
	}
	var said bytes.Buffer
	w = &out.Writer{Out: &said, Err: &bytes.Buffer{}}
	for _, args := range [][]string{nil, {logs}, nil} {
		said.Reset()
		if err := cmdAuditDir(root, args); err != nil {
			t.Fatal(err)
		}
		text := said.String()
		if !strings.HasSuffix(text, "\n") {
			t.Errorf("auditlog dir %v ends part way through a line: %q", args, text)
		}
		for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
			if strings.Count(line, "  ") > 1 || strings.Contains(strings.TrimSpace(line), "  ") {
				t.Errorf("auditlog dir %v runs two lines together: %q", args, line)
			}
		}
	}
}

// An empty directory, as an unset shell variable writes one, is refused and
// moves nothing. filepath.Abs makes the working directory of "", so
// `quilzo auditlog dir "$AUDIT"` with AUDIT unset pointed every reader at
// wherever the command happened to run: a new, empty chain that verified
// intact, with the real log left where nobody read it.
func TestAuditlogDirRefusesAnEmptyDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	for _, dir := range []string{"", "  "} {
		_, e, code := cliRun(t, root, "", "auditlog", "dir", dir)
		if code != 2 || !strings.Contains(e, "no directory") {
			t.Errorf("auditlog dir %q exited %d, want 2 and why: %s", dir, code, firstLines(e, 3))
		}
		if o, _, _ := cliRun(t, root, "", "auditlog", "dir", "--json"); !strings.Contains(o, `"in_store": true`) {
			t.Errorf("auditlog dir %q moved the log: %s", dir, firstLines(o, 4))
		}
	}
	if _, err := os.Stat(filepath.Join(root, "auditlog.dir")); !os.IsNotExist(err) {
		t.Errorf("a pointer was written: %v", err)
	}
}
