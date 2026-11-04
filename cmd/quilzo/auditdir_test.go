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
