// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
)

// Every listing answers --json with one JSON document, and nothing else.
//
// --json is global so that a caller scripting this "should not have to
// remember which subcommands happen to support it", and internal/out says the
// JSON is a contract. Nineteen commands ignored it and printed their prose,
// so a script that asked for the tokens, the grants or the version got a
// sentence to parse — which is the failure that package exists to prevent.
//
// The real command line, in a process of its own, because most of these
// write to the process's standard output rather than to a writer a test can
// swap.
func TestEveryListingAnswersInJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("QUILZO_TOKEN", "")
	old := w
	t.Cleanup(func() { w = old })
	w = out.New(false)
	root, tpl := t.TempDir()+"/st", t.TempDir()+"/tpl"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"-publish=false", "-templates", tpl}); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][]string{
		{"agent", "list"}, {"agent", "templates"}, {"apps", "list"}, {"audit", tpl},
		{"auth", "list"}, {"auth", "roles"}, {"brand", "check"}, {"brand", "list"},
		{"browser", "status"}, {"diff"}, {"inbox", "list"}, {"integrations", "list"},
		{"log"}, {"peer", "list"}, {"research", "list"}, {"rights"}, {"secret", "list"},
		{"token", "list"}, {"version"},
	} {
		name := strings.Join(c, " ")
		t.Run(name, func(t *testing.T) {
			args := append([]string{"quilzo-main", "--root", root}, c...)
			cmd := exec.Command(os.Args[0], append(args, "--json")...)
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), "HOME="+home, "QUILZO_TOKEN=")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			_ = cmd.Run() // a refusal still exits non-zero; stdout is the question
			dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
			var doc any
			if err := dec.Decode(&doc); err != nil {
				t.Fatalf("`quilzo %s --json` did not answer in JSON: %v\nstdout: %s\nstderr: %s",
					name, err, firstLines(stdout.String(), 4), firstLines(stderr.String(), 4))
			}
			if _, err := dec.Token(); err != io.EOF {
				t.Errorf("`quilzo %s --json` wrote more than one document: %s", name, stdout.String())
			}
			if strings.Contains(stdout.String(), "\x1b[") {
				t.Errorf("`quilzo %s --json` wrote escape codes", name)
			}
		})
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
