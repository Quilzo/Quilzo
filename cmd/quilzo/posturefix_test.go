// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The security report tells you to run commands this program has.
//
// It did not. Three of the thirty rules named something the binary answers
// with "unknown command", and they were not obscure rules — the first is what
// a fresh install is told on day one:
//
//	low  Nothing is denied anywhere
//	     fix: quilzo auth deny WHO ROLE --on /some/sensitive/path
//
//	$ quilzo auth deny bob author --on /legal
//	unknown auth command "deny"
//
// The other two were `quilzo token prune`, for expired tokens still listed,
// and `quilzo timestamp`, for live content that has never been timestamped —
// which is a real command that lists timestamps and does not make one, so it
// answers "no timestamps" and the finding stays.
//
// This is the worst shape of wrong for a security dashboard. Somebody acting
// on it is by definition somebody who does not already know the command, and
// what they get is an error that reads as the tool being broken rather than
// the advice being wrong. The same argument the help-text test makes: "a wrong
// one sends them, or an agent reading the help as a schema, to run a command
// that fails."
//
// Checked against the dispatch rather than proof-read, like the help is.
func TestEveryPostureFixNamesACommandThatExists(t *testing.T) {
	subs := realSubcommands(t)
	var bad []string
	checked := 0

	for _, fix := range postureFixes(t) {
		cmd, sub := advisedCommand(fix)
		if cmd == "" {
			continue // advice that is not a command line
		}
		checked++
		if _, known := commandNeeds[cmd]; !known {
			bad = append(bad, "there is no `quilzo "+cmd+"` command, advised by: "+fix)
			continue
		}
		if sub == "" {
			continue
		}
		groups, ok := subs[cmd]
		if !ok || len(groups) == 0 {
			continue // a command with no subcommand switch takes anything
		}
		if !inAnyGroup(groups, sub) {
			bad = append(bad, "`quilzo "+cmd+"` has no `"+sub+
				"` subcommand, advised by: "+fix)
		}
	}

	if checked < 10 {
		t.Fatalf("only %d rules advise a command; the parse is wrong and a "+
			"test that inspects nothing passes", checked)
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s. Somebody acting on a security finding is by definition "+
			"somebody who does not already know the command, and an error "+
			"reads to them as the tool being broken rather than the advice "+
			"being wrong", b)
	}
}

// postureFixes is every Fix line in the rules, read out of the source.
//
// Out of the source because a Fix belongs to a Finding, and a Finding only
// exists once its rule has fired — so asking the package for them would mean
// constructing thirty states that each trip one rule, and a state nobody got
// right would quietly check nothing. The literals are right there.
//
// A Fix built by concatenation contributes its leading literal, which is the
// part that names the command.
func postureFixes(t *testing.T) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(),
		"../../internal/posture/rules.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if id, ok := kv.Key.(*ast.Ident); !ok || id.Name != "Fix" {
			return true
		}
		v := kv.Value
		for {
			bin, ok := v.(*ast.BinaryExpr)
			if !ok {
				break
			}
			v = bin.X
		}
		if lit, ok := v.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				out = append(out, s)
			}
		}
		return true
	})
	return out
}

// advisedCommand reads the command and subcommand out of a rule's fix line.
//
// The fix is written for a person, so it carries placeholders (WHO, PAGE, ID),
// flags, and sometimes a `#` remark. Only the words before any of those are
// the command, and only a lower-case word can be a subcommand — WHO is an
// argument and `--on` is a flag.
func advisedCommand(fix string) (cmd, sub string) {
	fields := strings.Fields(fix)
	if len(fields) < 2 || fields[0] != "quilzo" {
		return "", ""
	}
	words := []string{}
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "-") || strings.HasPrefix(f, "#") ||
			f != strings.ToLower(f) {
			break
		}
		words = append(words, f)
		if len(words) == 2 {
			break
		}
	}
	if len(words) == 0 {
		return "", ""
	}
	if len(words) == 1 {
		return words[0], ""
	}
	return words[0], words[1]
}
