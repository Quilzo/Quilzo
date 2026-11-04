// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Asking any command for help runs nothing, exits 0, and answers about that
// command.
//
// --help was left to each command, and most did not read it: `quilzo init
// --help` in an empty directory created a store there and exited 1,
// `quilzo fediverse init --help` wrote a signing key, `quilzo token keygen
// --help` wrote a key to a file called --help, and `quilzo oidc --help`
// answered "unknown oidc command". A command whose flag set read it listed
// its flags and then failed with "flag: help requested".
//
// So every command and every subcommand the code switches on is asked, in
// the real command line and a process of its own, in an empty directory and
// in a fresh store. Nothing may be written there or in the home directory,
// the exit is 0, and every command line the answer shows is one for the
// command asked, under any of its spellings.
func TestAskingAnyCommandForHelpRunsNothing(t *testing.T) {
	handler := dispatchHandlers(t)
	real := realSubcommands(t)

	template := filepath.Join(t.TempDir(), ".quilzo")
	if err := cmdInit(template); err != nil {
		t.Fatal(err)
	}

	type ask struct {
		store bool
		args  []string
	}
	var asks []ask
	for _, c := range dispatchedCommands(t) {
		if strings.HasPrefix(c, "__") || handler[c] == "" {
			continue // the re-executed shims, and help and version, answered inline
		}
		for _, store := range []bool{false, true} {
			asks = append(asks, ask{store, []string{c, "--help"}})
			for _, g := range real[c] {
				asks = append(asks, ask{store, []string{c, g[0], "--help"}})
				if store {
					// A positional before the flag, as somebody halfway
					// through typing the command has.
					asks = append(asks, ask{store, []string{c, g[0], "x", "-h"}})
				}
			}
		}
	}
	if len(asks) < 500 {
		t.Fatalf("only %d questions to ask; the command list was not read", len(asks))
	}
	entry := regexp.MustCompile(`(?m)^  quilzo (\S+)`)

	for _, a := range asks {
		where := "an empty directory"
		if a.store {
			where = "a fresh store"
		}
		t.Run(where+"/"+strings.Join(a.args, " "), func(t *testing.T) {
			t.Parallel()
			dir, home := t.TempDir(), t.TempDir()
			if a.store {
				copyTree(t, template, filepath.Join(dir, ".quilzo"))
			}
			before := treeState(t, dir) + treeState(t, home)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"quilzo-main"}, a.args...)...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "HOME="+home, "QUILZO_TOKEN=", "NO_COLOR=1")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()

			said := firstLines(stdout.String()+stderr.String(), 6)
			if err != nil {
				t.Errorf("`quilzo %s` in %s: %v\n%s", strings.Join(a.args, " "), where, err, said)
			}
			if after := treeState(t, dir) + treeState(t, home); after != before {
				t.Errorf("`quilzo %s` in %s wrote something:\n%s",
					strings.Join(a.args, " "), where, treeDiff(before, after))
			}
			if strings.Contains(stdout.String()+stderr.String(), "flag: help requested") {
				t.Errorf("`quilzo %s` answered its help as a failure:\n%s", strings.Join(a.args, " "), said)
			}
			lines := entry.FindAllStringSubmatch(stdout.String(), -1)
			if len(lines) == 0 {
				t.Errorf("`quilzo %s` showed no line of the help about it:\n%s", strings.Join(a.args, " "), said)
			}
			for _, m := range lines {
				if handler[m[1]] != handler[a.args[0]] {
					t.Errorf("`quilzo %s` answered with the help for `quilzo %s`", strings.Join(a.args, " "), m[1])
					break
				}
			}
		})
	}
}

// `quilzo help CMD` is the lines about CMD, as `quilzo CMD --help` is: it
// printed all six hundred lines of the help, whatever came after it.
func TestHelpForACommandIsAboutThatCommand(t *testing.T) {
	entry := regexp.MustCompile(`(?m)^  quilzo (\S+)( \S+)?`)
	for _, c := range [][]string{{"help", "oidc"}, {"help", "saml", "add"}, {"help", "forms"}} {
		cmd := exec.Command(os.Args[0], append([]string{"quilzo-main"}, c...)...)
		cmd.Dir = t.TempDir()
		cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "QUILZO_TOKEN=")
		got, err := cmd.Output()
		if err != nil {
			t.Fatalf("`quilzo %s`: %v", strings.Join(c, " "), err)
		}
		lines := entry.FindAllStringSubmatch(string(got), -1)
		if len(lines) == 0 {
			t.Errorf("`quilzo %s` printed no line about it:\n%s", strings.Join(c, " "), got)
		}
		want := strings.TrimSuffix(c[1], "s")
		for _, m := range lines {
			if m[1] != want || (len(c) > 2 && m[2] != " "+c[2]) {
				t.Errorf("`quilzo %s` printed `quilzo %s%s`", strings.Join(c, " "), m[1], m[2])
				break
			}
		}
	}
}

// `quilzo CMD help` is CMD's help wherever CMD takes a subcommand, as
// `quilzo help CMD` is. `quilzo decide help` answered "unknown decide
// command "help"", which tells somebody typing the natural thing that the
// command does not exist.
//
// Every command that switches on a subcommand is asked, in a process of its
// own and a fresh store: nothing may be written, the exit is 0, and every
// line shown is about the command asked. Two take a page where a
// subcommand goes, so "help" there is a page's name, and one has a help of
// its own; those are left to answer as they do.
func TestHelpAfterACommandIsItsHelp(t *testing.T) {
	handler := dispatchHandlers(t)
	real := realSubcommands(t)
	namesFirst := map[string]bool{handler["lock"]: true, handler["share"]: true}

	template := filepath.Join(t.TempDir(), ".quilzo")
	if err := cmdInit(template); err != nil {
		t.Fatal(err)
	}
	entry := regexp.MustCompile(`(?m)^  quilzo (\S+)( \S+)?`)
	asked := 0
	for _, c := range dispatchedCommands(t) {
		if strings.HasPrefix(c, "__") || handler[c] == "" || len(real[c]) == 0 || namesFirst[handler[c]] {
			continue
		}
		ownHelp := false
		for _, g := range real[c] {
			for _, sub := range g {
				ownHelp = ownHelp || sub == "help"
			}
		}
		if ownHelp {
			continue
		}
		for _, args := range [][]string{{c, "help"}, {"help", c}} {
			asked++
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				t.Parallel()
				dir, home := t.TempDir(), t.TempDir()
				copyTree(t, template, filepath.Join(dir, ".quilzo"))
				before := treeState(t, dir) + treeState(t, home)
				cmd := exec.Command(os.Args[0], append([]string{"quilzo-main"}, args...)...)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "HOME="+home, "QUILZO_TOKEN=", "NO_COLOR=1")
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				said := firstLines(stdout.String()+stderr.String(), 6)
				if err != nil {
					t.Errorf("`quilzo %s`: %v\n%s", strings.Join(args, " "), err, said)
				}
				if after := treeState(t, dir) + treeState(t, home); after != before {
					t.Errorf("`quilzo %s` wrote something:\n%s", strings.Join(args, " "), treeDiff(before, after))
				}
				lines := entry.FindAllStringSubmatch(stdout.String(), -1)
				if len(lines) == 0 {
					t.Errorf("`quilzo %s` showed no line of the help about it:\n%s", strings.Join(args, " "), said)
				}
				for _, m := range lines {
					if handler[m[1]] != handler[c] {
						t.Errorf("`quilzo %s` answered with the help for `quilzo %s`", strings.Join(args, " "), m[1])
						break
					}
				}
			})
		}
	}
	if asked < 150 {
		t.Fatalf("only %d questions asked; the command list was not read", asked)
	}

	// Where a page goes, "help" is a page, and geo's help is its own.
	for _, c := range []string{"lock", "locks", "share", "geo", "add", "publish"} {
		if helpAfter(c, []string{"help"}) {
			t.Errorf("`quilzo %s help` is taken as asking for help", c)
		}
	}

	// And after it, the subcommand: the lines about that one alone.
	cmd := exec.Command(os.Args[0], "quilzo-main", "decide", "help", "ask")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "QUILZO_TOKEN=", "NO_COLOR=1")
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("`quilzo decide help ask`: %v\n%s", err, got)
	}
	for _, m := range entry.FindAllStringSubmatch(string(got), -1) {
		if m[1] != "decide" || m[2] != " ask" {
			t.Errorf("`quilzo decide help ask` printed `quilzo %s%s`", m[1], m[2])
		}
	}
}

// `quilzo CMD help` is CMD's help where CMD takes nothing but flags, as it
// is where CMD takes a subcommand. Each of these ran with the word left
// over: `quilzo rollback help` put the live site back a version, `quilzo
// init help` made a store in an empty directory, and `quilzo serve help`
// and `quilzo studio help` started their servers and did not stop.
//
// Asked in a process of its own, in an empty directory and in a store with
// two publications, so a rollback has somewhere to go back to: nothing may
// be written, the exit is 0, and every line shown is about the command.
func TestHelpAfterACommandThatTakesOnlyFlagsIsItsHelp(t *testing.T) {
	handler := dispatchHandlers(t)
	template := filepath.Join(t.TempDir(), ".quilzo")
	if err := cmdInit(template); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(template)
	if err != nil {
		t.Fatal(err)
	}
	for _, title := range []string{"First", "Second"} {
		if _, err := site.SaveDraft(s, map[string]any{"index": map[string]any{"title": title}}, "test", "dana"); err != nil {
			t.Fatal(err)
		}
		if _, err := site.Publish(s, ""); err != nil {
			t.Fatal(err)
		}
	}
	entry := regexp.MustCompile(`(?m)^  quilzo (\S+)`)
	for _, c := range []string{"a11y", "analytics", "init", "log", "mcp", "rollback", "scan", "serve", "studio"} {
		if !helpAfter(c, []string{"help"}) {
			t.Errorf("`quilzo %s help` is not taken as asking for help", c)
		}
		for _, inStore := range []bool{false, true} {
			where := "an empty directory"
			if inStore {
				where = "a store"
			}
			t.Run(where+"/"+c, func(t *testing.T) {
				t.Parallel()
				dir, home := t.TempDir(), t.TempDir()
				if inStore {
					copyTree(t, template, filepath.Join(dir, ".quilzo"))
				}
				before := treeState(t, dir) + treeState(t, home)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "quilzo-main", c, "help")
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "HOME="+home, "QUILZO_TOKEN=", "NO_COLOR=1")
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				said := firstLines(stdout.String()+stderr.String(), 6)
				if err != nil {
					t.Errorf("`quilzo %s help` in %s: %v\n%s", c, where, err, said)
				}
				if after := treeState(t, dir) + treeState(t, home); after != before {
					t.Errorf("`quilzo %s help` in %s wrote something:\n%s", c, where, treeDiff(before, after))
				}
				lines := entry.FindAllStringSubmatch(stdout.String(), -1)
				if len(lines) == 0 {
					t.Errorf("`quilzo %s help` showed no line of the help about it:\n%s", c, said)
				}
				for _, m := range lines {
					if handler[m[1]] != handler[c] {
						t.Errorf("`quilzo %s help` answered with the help for `quilzo %s`", c, m[1])
						break
					}
				}
			})
		}
	}

	// A command that takes a name where its flags go is left to read
	// "help" as one: `quilzo links help` is about a page called help.
	for _, c := range []string{"links", "publish", "rights", "audit", "find", "import"} {
		if helpAfter(c, []string{"help"}) {
			t.Errorf("`quilzo %s help` is taken as asking for help", c)
		}
	}
}

// dispatchHandlers maps every command main.go dispatches to the function
// that runs it, so that two spellings of one command can be told apart from
// two commands.
func dispatchHandlers(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(".", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := map[string]*ast.File{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		pkg[f] = parsed
	}
	return commandHandlers(t, pkg)
}

// copyTree copies a directory of regular files.
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		target := filepath.Join(to, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

// treeState is every path under a directory with its size, mode and time,
// one to a line, so that anything created, removed or rewritten shows.
func treeState(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		size := info.Size()
		if d.IsDir() {
			size = 0 // a directory's size is the filesystem's business
		}
		lines = append(lines, fmt.Sprintf("%s %d %v %d", path, size, info.Mode(), info.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

// treeDiff is the lines of one state that are not in the other.
func treeDiff(before, after string) string {
	was := map[string]bool{}
	for _, l := range strings.Split(before, "\n") {
		was[l] = true
	}
	var out []string
	for _, l := range strings.Split(after, "\n") {
		if l != "" && !was[l] {
			out = append(out, "  "+l)
		}
	}
	if len(out) > 8 {
		out = append(out[:8], "  …")
	}
	return strings.Join(out, "\n")
}

// Every spelling a flag set answers as help is help here too.
//
// The flag package takes -h and -help with one dash or two, and with a
// value after an equals sign, and this took three of the eight. `quilzo init
// --h` in an empty directory created a store and then failed with "flag:
// help requested", `quilzo token keygen --h` wrote a key to a file called
// --h, and `quilzo publish --help=true` listed its flags and exited 1. So the
// spellings are checked against what a flag set does with them, and a
// command that acts before it parses is asked with each.
func TestEverySpellingOfHelpIsHelp(t *testing.T) {
	for _, a := range []string{"-h", "--h", "-help", "--help", "-h=1", "--h=", "-help=false",
		"--help=true", "---help", "-H", "-hh", "--helpme", "help", "-", "--", "-=h", "--=help"} {
		fs := flag.NewFlagSet("x", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		flagSays := errors.Is(fs.Parse([]string{a}), flag.ErrHelp)
		if isHelpFlag(a) != flagSays {
			t.Errorf("isHelpFlag(%q) is %v, and a flag set's answer to it is help: %v", a, isHelpFlag(a), flagSays)
		}
	}

	template := filepath.Join(t.TempDir(), ".quilzo")
	if err := cmdInit(template); err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{"--h", "-h=1", "--help=true"} {
		for _, args := range [][]string{{"init"}, {"token", "keygen"}, {"brand", "init"},
			{"fediverse", "init"}, {"publish"}} {
			for _, store := range []bool{false, true} {
				args := append(append([]string(nil), args...), spelling)
				dir, home := t.TempDir(), t.TempDir()
				if store {
					copyTree(t, template, filepath.Join(dir, ".quilzo"))
				}
				before := treeState(t, dir) + treeState(t, home)
				cmd := exec.Command(os.Args[0], append([]string{"quilzo-main"}, args...)...)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "HOME="+home, "QUILZO_TOKEN=", "NO_COLOR=1")
				said, err := cmd.CombinedOutput()
				if err != nil {
					t.Errorf("`quilzo %s` (store: %v): %v\n%s", strings.Join(args, " "), store, err, firstLines(string(said), 6))
				}
				if after := treeState(t, dir) + treeState(t, home); after != before {
					t.Errorf("`quilzo %s` (store: %v) wrote something:\n%s", strings.Join(args, " "), store, treeDiff(before, after))
				}
				if strings.Contains(string(said), "flag: help requested") {
					t.Errorf("`quilzo %s` answered its help as a failure", strings.Join(args, " "))
				}
			}
		}
	}
}
