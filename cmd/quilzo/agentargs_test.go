// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// argsStore is a store with the agent tidy declared, and dana, who may
// change it, as the caller.
func argsStore(t *testing.T) string {
	t.Helper()
	root, _ := identityStore(t)
	toks := &auth.TokenStore{}
	secret, _, err := toks.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), toks); err != nil {
		t.Fatal(err)
	}
	old := flagToken
	flagToken = secret
	t.Cleanup(func() { flagToken = old })
	return root
}

// An agent command takes its flags either side of the file or name it is
// about, as most commands here do.
//
// Found by running one: `quilzo agent declare FILE --widen` printed the
// usage line, and only `--widen FILE` worked. Most agent commands read
// their flags from one side only, each its own way: declare and cost
// from the front, sponsor, renew, receipt and program from after the
// name, import and export from either side but not both. And could read
// a flag after its operation as the page to ask about. Each command here
// is run both ways, each way on a store of its own, and has to come to
// the same thing.
func TestAgentCommandsTakeFlagsEitherSideOfTheirArguments(t *testing.T) {
	widened := asker("tidy")
	widened.Capabilities = append(widened.Capabilities, "read_page")
	helper := asker("helper")
	files := t.TempDir()
	write := func(name string, v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(files, name)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	amendment, imported := write("tidy.json", widened), write("helper.json", helper)
	draft := `{"name": "faq-helper", "kind": "task", "purpose": "keep the FAQ tidy",
		"capabilities": ["read_page"], "autonomy": "draft", "retrieval": {"ref": "draft"}}`
	missing := filepath.Join(files, "no-such-receipt.json")
	run := "run-20261104-0badc0de"

	for _, c := range []struct {
		name string
		// first and then are the same command, its flags before and after
		// what it is about. out is a directory of the run's own.
		first, then func(out string) []string
		// check, when set, says the command did what it was asked.
		check func(t *testing.T, root string)
	}{
		{name: "declare",
			first: func(string) []string { return []string{"declare", "--widen", amendment} },
			then:  func(string) []string { return []string{"declare", amendment, "--widen"} },
			check: func(t *testing.T, root string) {
				set, _ := loadAgents(root)
				if !strings.Contains(strings.Join(set.Agents["tidy"].Capabilities, " "), "read_page") {
					t.Errorf("the widening amendment was not saved: %v", set.Agents["tidy"].Capabilities)
				}
			}},
		{name: "new",
			first: func(string) []string { return []string{"new", "--kind", "task", "helper"} },
			then:  func(string) []string { return []string{"new", "helper", "--kind", "task"} },
			check: func(t *testing.T, root string) {
				if set, _ := loadAgents(root); set.Agents["helper"].Name != "helper" {
					t.Error("helper was not declared")
				}
			}},
		{name: "cost",
			first: func(string) []string { return []string{"cost", "--by", "person", "tidy"} },
			then:  func(string) []string { return []string{"cost", "tidy", "--by", "person"} }},
		{name: "earned",
			first: func(string) []string { return []string{"earned", "--reset", "tidy"} },
			then:  func(string) []string { return []string{"earned", "tidy", "--reset"} }},
		{name: "could",
			first: func(string) []string { return []string{"could", "tidy", "--as", "sam", "read_page", "index"} },
			then:  func(string) []string { return []string{"could", "tidy", "read_page", "index", "--as", "sam"} }},
		{name: "could, with no page",
			first: func(string) []string { return []string{"could", "--as", "nobody-here", "tidy", "read_page"} },
			then:  func(string) []string { return []string{"could", "tidy", "read_page", "--as", "nobody-here"} }},
		{name: "draft",
			first: func(out string) []string {
				return []string{"draft", "--name", "faq-helper", "keep the FAQ tidy", "-o", filepath.Join(out, "d.json")}
			},
			then: func(out string) []string {
				return []string{"draft", "keep the FAQ tidy", "--name", "faq-helper", "-o", filepath.Join(out, "d.json")}
			}},
		{name: "import",
			first: func(string) []string { return []string{"import", "--name", "helper2", imported, "--save"} },
			then:  func(string) []string { return []string{"import", imported, "--name", "helper2", "--save"} },
			check: func(t *testing.T, root string) {
				if set, _ := loadAgents(root); set.Agents["helper2"].Name != "helper2" {
					t.Error("the import was not saved as helper2")
				}
			}},
		{name: "export",
			first: func(out string) []string {
				return []string{"export", "--to", "quilzo", "tidy", "-o", filepath.Join(out, "tidy.json")}
			},
			then: func(out string) []string {
				return []string{"export", "tidy", "--to", "quilzo", "-o", filepath.Join(out, "tidy.json")}
			}},
		{name: "sponsor",
			first: func(string) []string { return []string{"sponsor", "--for", "48h", "tidy", "sam"} },
			then:  func(string) []string { return []string{"sponsor", "tidy", "sam", "--for", "48h"} },
			check: func(t *testing.T, root string) {
				set, _ := loadAgents(root)
				id := set.identityOf("tidy")
				if id == nil || id.Sponsor != "sam" || id.Expires.After(time.Now().Add(49*time.Hour)) {
					t.Errorf("tidy is answered for as %+v", id)
				}
			}},
		{name: "renew",
			first: func(string) []string { return []string{"renew", "--for", "48h", "tidy"} },
			then:  func(string) []string { return []string{"renew", "tidy", "--for", "48h"} },
			check: func(t *testing.T, root string) {
				set, _ := loadAgents(root)
				if id := set.identityOf("tidy"); id == nil || id.Expires.After(time.Now().Add(49*time.Hour)) {
					t.Errorf("tidy was not renewed for 48 hours: %+v", id)
				}
			}},
		{name: "credential issue",
			first: func(out string) []string {
				return []string{"credential", "issue", "--grant", "browser:shop", "tidy", "--generate", filepath.Join(out, "key")}
			},
			then: func(out string) []string {
				return []string{"credential", "issue", "tidy", "--grant", "browser:shop", "--generate", filepath.Join(out, "key")}
			}},
		{name: "lessons try",
			first: func(string) []string { return []string{"lessons", "try", "--k", "2", "tidy", "les-1"} },
			then:  func(string) []string { return []string{"lessons", "try", "tidy", "les-1", "--k", "2"} }},
		{name: "lessons adopt",
			first: func(string) []string { return []string{"lessons", "adopt", "--tainted-ok", "tidy", "les-1"} },
			then:  func(string) []string { return []string{"lessons", "adopt", "tidy", "les-1", "--tainted-ok"} }},
		{name: "lessons retire",
			first: func(string) []string { return []string{"lessons", "retire", "--why", "old", "tidy", "les-1"} },
			then:  func(string) []string { return []string{"lessons", "retire", "tidy", "les-1", "--why", "old"} }},
		{name: "program",
			first: func(string) []string {
				return []string{"program", "--backend", "native", "tidy", "--", "/bin/true"}
			},
			then: func(string) []string {
				return []string{"program", "tidy", "--backend", "native", "--", "/bin/true"}
			},
			check: func(t *testing.T, root string) {
				set, _ := loadAgents(root)
				if p := set.Agents["tidy"].Program; p == nil || p.Backend != "native" || p.Command[0] != "/bin/true" {
					t.Errorf("tidy's program is %+v", p)
				}
			}},
		{name: "receipt",
			first: func(out string) []string { return []string{"receipt", "-o", filepath.Join(out, "r.json"), run} },
			then:  func(out string) []string { return []string{"receipt", run, "-o", filepath.Join(out, "r.json")} }},
		{name: "verify-receipt",
			first: func(string) []string { return []string{"verify-receipt", "--keys", missing, missing} },
			then:  func(string) []string { return []string{"verify-receipt", missing, "--keys", missing} }},
		{name: "workspace",
			first: func(string) []string { return []string{"workspace", "--clear", "tidy"} },
			then:  func(string) []string { return []string{"workspace", "tidy", "--clear"} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got [2]string
			for i, args := range []func(string) []string{c.first, c.then} {
				root := argsStore(t)
				withDraftModel(t, draft)
				out := t.TempDir()
				a := args(out)
				_, read := captureStdout(t)
				err := cmdAgent(root, a)
				read()
				if err != nil {
					got[i] = strings.NewReplacer(root, "ROOT", out, "OUT").Replace(err.Error())
				}
				if strings.HasPrefix(got[i], "usage") || strings.HasPrefix(got[i], "quilzo agent") {
					t.Errorf("%q was refused as misused: %s", a, got[i])
				}
				if c.check != nil {
					c.check(t, root)
				}
			}
			if got[0] != got[1] {
				t.Errorf("the order of its flags changed what it did:\n  flags first: %q\n  flags after: %q", got[0], got[1])
			}
		})
	}
}
