// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// An act by an app at the agent interface, or by an agent under its own
// identity, is recorded. The log refuses an AI act that names no model, and
// a record built from the caller's kind without the caller's model was
// refused, so the act left only the interface's own record of the call.
func TestAnAppsActIsRecordedAsTheApps(t *testing.T) {
	root, _ := identityStore(t)
	app := remoteCaller(auth.Token{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"})
	if err := saveAssistant(root, app, "declare", "help", func(set *assistant.Set) error {
		set.Assistants = append(set.Assistants, assistant.Assistant{Name: "help", Title: "Help"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	events, _ := audit.Read(auditPath(root))
	found := false
	for _, e := range events {
		if e.Action == "assistant.declare" && e.Kind == audit.KindAI && e.Model == "mcp-client" {
			found = true
		}
	}
	if !found {
		t.Error("the app's act is not in the log")
	}
}

// Read from the source: every audit record that takes its kind from a
// caller takes its model from the caller too.
func TestEveryRecordFromACallerNamesItsModel(t *testing.T) {
	kind := regexp.MustCompile(`Kind:\s*(caller|c)\.Kind\b`)
	files, _ := filepath.Glob("*.go")
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, m := range kind.FindAllStringIndex(s, -1) {
			open := enclosingBrace(s, m[0])
			if open < 0 || !strings.HasSuffix(strings.TrimSpace(s[max(0, open-40):open]), "audit.Record") {
				continue
			}
			checked++
			if lit := s[open:closingBrace(s, open)]; !regexp.MustCompile(`\bModel:`).MatchString(lit) {
				line := strings.Count(s[:m[0]], "\n") + 1
				t.Errorf("%s:%d records a caller's kind and not its model; an app's or an agent's act is then refused by the log", f, line)
			}
		}
	}
	// Thirty-one when the security team's commands left for Vaigil; a
	// floor well under that, so a scan that stopped matching fails.
	if checked < 25 {
		t.Errorf("only %d records checked; the test has stopped finding them", checked)
	}
}

func enclosingBrace(s string, at int) int {
	depth := 0
	for j := at - 1; j >= 0; j-- {
		switch s[j] {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				return j
			}
			depth--
		}
	}
	return -1
}

func closingBrace(s string, open int) int {
	depth := 0
	for k := open; k < len(s); k++ {
		switch s[k] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return k
			}
		}
	}
	return len(s)
}
