// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
)

// The security modules' commands keep the command line's contract where
// the tests of every registered command (modules_test.go) do not ask: in
// the words each reads for itself.

// A word no record can be called is a misused command line, 2, in every
// module's command that takes an identifier, and an identifier nothing has
// is still not found, 4.
//
// The built-in commands refuse an id of the wrong shape as the command
// line's mistake (`agent receipt ab`, `feature approve ab`, `auditlog show
// ab`), and so does `quilzo evidence show ab`, and the agent interface,
// where register_show refuses the same word as an argument. The commands
// beside them looked the word up: `register show ab` said "no such record
// in the register: "ab" is not a record's identifier" and exited 4, as
// `register history`, the approvals' show, check, reject, approve and
// review, and the programme's approve, run, explain and replay did, so a
// script told "not found" went looking for a record a typo had named. And
// `population show ""` exited 4 where `population count ""` exits 2.
func TestAWordNoRecordCanBeCalledIsMisusedInEveryModule(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	const nothing = "00000000000000000000000000000000"
	for _, line := range [][]string{
		{"register", "show", "ID"},
		{"register", "history", "ID"},
		{"approval", "show", "ID"},
		{"approval", "check", "ID"},
		{"approval", "reject", "ID"},
		{"approval", "approve", "ID", "--surface", "sha256:" + strings.Repeat("0", 64)},
		{"approval", "review", "ID", "upheld", "--surface", "sha256:" + strings.Repeat("0", 64)},
		{"control", "approve", "ID", "--surface", "sha256:" + strings.Repeat("0", 64)},
		{"control", "run", "ID"},
		{"control", "explain", "ID"},
		{"control", "replay", "ID"},
		{"requirement", "approve", "ID", "--surface", "sha256:" + strings.Repeat("0", 64)},
		{"soa", "approve", "ID", "--surface", "sha256:" + strings.Repeat("0", 64)},
	} {
		for word, want := range map[string]int{
			"ab": out.ExitUsage, "": out.ExitUsage, "not an id at all": out.ExitUsage,
			strings.ToUpper("abcdefabcdefabcdefabcdefabcdefab"): out.ExitUsage,
			nothing: out.ExitNotFound,
		} {
			typed := append([]string{}, line...)
			for i, a := range typed {
				if a == "ID" {
					typed[i] = word
				}
			}
			if _, e, code := cliRun(t, root, "", typed...); code != want {
				t.Errorf("`quilzo %s` exited %d, want %d (%s): %s", strings.Join(typed, " "), code, want,
					out.Describe(want), firstLines(e, 2))
			}
		}
	}
	if _, e, code := cliRun(t, root, "", "population", "show", ""); code != out.ExitUsage {
		t.Errorf("`quilzo population show \"\"` exited %d, want %d: %s", code, out.ExitUsage, firstLines(e, 2))
	}
	if _, e, code := cliRun(t, root, "", "population", "show", "nobody"); code != out.ExitNotFound {
		t.Errorf("`quilzo population show nobody` exited %d, want %d: %s", code, out.ExitNotFound, firstLines(e, 2))
	}
}

// Under --json each write of the security modules answers one document
// saying what it did, and the statement asked for as CSV is still one
// document.
//
// The help says stdout carries one document under --json, and three writes
// answered nothing at all with exit 0, each having confirmed only in prose:
// `public target DIR`, so a script could not tell where transfers now go
// from a line that had not run; `attest publish` by the only administrator,
// which sent the attestations and said so to nobody, while the same line
// waiting for a second administrator answered its request; and `profile
// manifest -o FILE`. `soa show SCOPE --csv` wrote the CSV, which no parser
// of the document reads. The register's own writes answered already, and
// are run here beside them, in the order a script setting the record up
// runs them, so a write added to a module is held to it.
func TestAModulesWriteAnswersOneDocument(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	attestations, err := held().Encode()
	if err != nil {
		t.Fatal(err)
	}
	carried := filepath.Join(dir, "carried")
	if err := os.Mkdir(carried, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "manifest.json")
	// answered is what the lines before answered, by the field's name: a
	// decision's id and the hash its approver types back.
	answered := map[string]string{}
	for _, c := range []struct {
		line []string
		// has is a field the document must carry: what the write did.
		has string
	}{
		{[]string{"requirement", "install", "iso-27001"}, "id"},
		{[]string{"requirement", "approve", "ID", "--surface", "SURFACE"}, "receipt"},
		{[]string{"control", "add", "AC-01", "--title", "A second factor", "--domain", "identity"}, "control"},
		{[]string{"control", "map", "AC-01", "iso-27001", "A.5.1", "--relation", "subset-of", "--why", "one part of it"}, "mapping"},
		{[]string{"control", "run", "--due"}, "ran"},
		{[]string{"soa", "scope", "group", "--title", "The group", "--domains", "identity"}, "id"},
		{[]string{"soa", "approve", "ID", "--surface", "SURFACE"}, "receipt"},
		{[]string{"soa", "decide", "group", "iso-27001", "A.5.1", "--applies", "--why", "it is ours"}, "id"},
		{[]string{"soa", "approve", "ID", "--surface", "SURFACE"}, "receipt"},
		{[]string{"soa", "show", "group", "--csv"}, "lines"},
		{[]string{"ingest", "ocsf", evidenceFixturePath(t, "ocsf/prowler-1.2.0.json")}, "receipt"},
		{[]string{"evidence", "expire"}, "erased"},
		{[]string{"register", "expire"}, "expired"},
		{[]string{"approval", "policy", "set", "POLICY"}, "policy"},
		{[]string{"profile", "apply", "security", "--reason", "nothing here sells anything"}, "manifest"},
		{[]string{"profile", "enable", "boards", "--reason", "a forum for the board"}, "manifest"},
		{[]string{"profile", "manifest", "-o", manifest}, "file"},
		{[]string{"attest", "set", write("attestations.json", string(attestations))}, "digest"},
		{[]string{"public", "target", carried}, "to"},
		{[]string{"attest", "publish", "--reason", "the 2025 report is in"}, "digest"},
		{[]string{"public", "send", "--reason", "a fresh head"}, "digest"},
	} {
		line := append([]string{}, c.line...)
		for i, a := range line {
			switch a {
			case "ID":
				line[i] = answered["id"]
			case "SURFACE":
				line[i] = answered["surface"]
			case "POLICY":
				// The policy in force, declared as it stands.
				o, e, code := cliRun(t, root, "", "--json", "approval", "policy")
				var doc struct{ Policy json.RawMessage }
				if code != 0 || json.Unmarshal([]byte(o), &doc) != nil || len(doc.Policy) == 0 {
					t.Fatalf("approval policy: %d %s", code, firstLines(e, 3))
				}
				line[i] = write("policy.json", string(doc.Policy))
			}
		}
		name := strings.Join(c.line, " ")
		o, e, code := cliRun(t, root, "", append([]string{"--json"}, line...)...)
		if code != 0 {
			t.Errorf("`quilzo --json %s` exited %d: %s", name, code, firstLines(e, 3))
			continue
		}
		dec := json.NewDecoder(strings.NewReader(o))
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			t.Errorf("`quilzo --json %s` did not answer a JSON document: %q", name, firstLines(o, 2))
			continue
		}
		if dec.More() {
			t.Errorf("`quilzo --json %s` answered more than one document: %q", name, firstLines(o, 4))
		}
		if _, ok := doc[c.has]; !ok {
			t.Errorf("`quilzo --json %s` answered %.160s, without %q", name, o, c.has)
		}
		for _, k := range []string{"id", "surface"} {
			if v, ok := doc[k].(string); ok {
				answered[k] = v
			}
		}
	}
	if b, err := os.ReadFile(manifest); err != nil || !json.Valid(b) {
		t.Errorf("`quilzo --json profile manifest -o FILE` did not write the manifest: %v", err)
	}
	// What the answers say is what was done: the target is the one kept,
	// and the publication the one recorded as sent.
	o, _, _ := cliRun(t, root, "", "--json", "public", "status")
	var status struct {
		Target string
		Sent   *struct{ To string }
	}
	if err := json.Unmarshal([]byte(o), &status); err != nil || status.Target != carried || status.Sent == nil || status.Sent.To != carried {
		t.Errorf("the public instance is not where the answers said: %s", firstLines(o, 6))
	}
	// At a terminal the statement is still CSV when it is asked for as CSV.
	if o, e, code := cliRun(t, root, "", "soa", "show", "group", "--csv"); code != 0 || !strings.HasPrefix(o, "framework,requirement,") {
		t.Errorf("`quilzo soa show group --csv` exited %d without the CSV: %s %s", code, firstLines(o, 2), firstLines(e, 2))
	}
}
