// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/register"
)

// The security modules' commands, held to what the built-in ones are held
// to.
//
// The tests that read main.go's switch, its help and the privilege table
// call the helpers below to read the registered modules with them
// (dispatchedCommands, commandHandlers, helpText, everyCommandLine and the
// coverage table's rows), so a registered command is checked by every one of
// them. What those tests do not ask, because the built-in commands answer it
// one by one in tests of their own, is asked here of every module at once:
// that each read answers --json, that a line naming nothing exits 4, that a
// caller the policy refuses exits 3, and that a word the command does not
// take exits 2.

// moduleCommands is every registered module's command.
func moduleCommands() []string {
	var out []string
	for _, m := range cliModules {
		out = append(out, m.command)
	}
	return out
}

// moduleHelp is the modules' lines of the help, as fullHelp places them.
func moduleHelp() string { return moduleSections() }

// moduleOperations is the agent interface's operations the modules offer.
func moduleOperations() []string {
	var out []string
	for _, m := range register.Modules() {
		out = append(out, m.Offers[register.SurfaceMCP]...)
	}
	return out
}

// coverageRows is the coverage table with a row for each module's command,
// made from what the module registered on the other surfaces, so a module
// is accounted for by what it serves and not by a row somebody wrote.
func coverageRows() map[string]surfaces {
	rows := map[string]surfaces{}
	for c, s := range coverage {
		rows[c] = s
	}
	byName := map[string]register.Module{}
	for _, m := range register.Modules() {
		byName[m.Name] = m
	}
	for _, m := range cliModules {
		mod := byName[m.module]
		row := surfaces{MCP: mod.Offers[register.SurfaceMCP], Why: mod.Without[register.SurfaceAdmin],
			NoMCP: mod.Without[register.SurfaceMCP]}
		if screens := mod.Offers[register.SurfaceAdmin]; len(screens) > 0 {
			row.GUI = screens[0]
		}
		rows[m.command] = row
	}
	return rows
}

// Every module is on every surface, or says why not.
//
// The command line's tests link the admin and the content API, so by the
// time this runs every surface has written what it registered into the
// register's ledger. A module with a command and no screen, or a screen and
// no route in the API, fails here with its name.
func TestEveryModuleIsOnEverySurface(t *testing.T) {
	mods := register.Modules()
	if len(mods) == 0 {
		t.Fatal("no module is registered on any surface; the register's own module is the example every later one copies")
	}
	for _, m := range mods {
		for _, s := range m.Missing() {
			t.Errorf("the module %s offers nothing on %s and does not say why: %v", m.Name, s, m.Offers)
		}
		for s, why := range m.Without {
			if !isRealReason(why) {
				t.Errorf("the module %s does without %s because %q, which is not a reason", m.Name, s, why)
			}
		}
	}
	for _, c := range cliModules {
		if !slices.ContainsFunc(mods, func(m register.Module) bool { return m.Name == c.module }) {
			t.Errorf("quilzo %s is the module %s's, which the ledger does not hold", c.command, c.module)
		}
	}
}

// Each module's command keeps the contract the help states for every
// command: what reads answers --json, what is not there exits 4, what the
// policy refuses exits 3, and a word it does not take exits 2.
func TestEveryRegisteredCommandKeepsItsContract(t *testing.T) {
	if len(cliModules) == 0 {
		t.Fatal("no module registers a command")
	}
	root, token := accessStore(t)
	// A reader of the whole site, who holds no role on the compliance area,
	// where the register is.
	if _, e, code := cliRun(t, root, token, "auth", "grant", "rita", "reader"); code != 0 {
		t.Fatalf("auth grant: %s", e)
	}
	o, e, code := cliRun(t, root, token, "token", "issue", "rita", "--principal", "rita", "--role", "reader", "--json")
	if code != 0 {
		t.Fatalf("token issue: %s", e)
	}
	var tok struct{ Token string }
	if err := json.Unmarshal([]byte(o), &tok); err != nil || tok.Token == "" {
		t.Fatalf("token issue answered no token: %v", err)
	}
	for _, m := range cliModules {
		if len(m.reads) == 0 {
			t.Errorf("quilzo %s names no line that reads, so nothing here checks it answers --json", m.command)
		}
		for _, line := range m.reads {
			name := strings.Join(line, " ")
			o, e, code := cliRun(t, root, token, append([]string{"--json"}, line...)...)
			if code != 0 {
				t.Errorf("`quilzo --json %s` exited %d: %s", name, code, firstLines(e, 3))
				continue
			}
			if !json.Valid([]byte(o)) || !strings.HasPrefix(strings.TrimSpace(o), "{") {
				t.Errorf("`quilzo --json %s` answered what is not a JSON object: %s", name, firstLines(o, 3))
			}
			if _, e, code := cliRun(t, root, tok.Token, line...); code != 3 {
				t.Errorf("`quilzo %s` by a reader with no role on %s exited %d, not 3: %s", name, m.area, code, firstLines(e, 3))
			}
			if _, e, code := cliRun(t, root, token, append(line, "zzw1")...); code != 2 {
				t.Errorf("`quilzo %s zzw1` exited %d, not 2: %s", name, code, firstLines(e, 3))
			}
		}
		if len(m.absent) == 0 {
			t.Errorf("quilzo %s names no line about something that is not there, so nothing checks it exits 4", m.command)
			continue
		}
		if _, e, code := cliRun(t, root, token, m.absent...); code != 4 {
			t.Errorf("`quilzo %s` exited %d, not 4: %s", strings.Join(m.absent, " "), code, firstLines(e, 3))
		}
	}
}

// Each module's lines are in the help as it is printed, not only in the
// source the other help tests read: in `quilzo help` under the module's
// heading, and in `quilzo help COMMAND` and `quilzo COMMAND --help`, each of
// which exits 0. The tests that read the help's source read the module's
// own lines, so a help that printed none of them passed every one.
func TestEveryRegisteredCommandIsInThePrintedHelp(t *testing.T) {
	if len(cliModules) == 0 {
		t.Fatal("no module registers a command")
	}
	all, e, code := cliRun(t, "", "", "help")
	if code != 0 {
		t.Fatalf("`quilzo help` exited %d: %s", code, firstLines(e, 3))
	}
	for _, m := range cliModules {
		if !strings.Contains(all, "\n"+m.heading+"\n") {
			t.Errorf("`quilzo help` has no section headed %q", m.heading)
		}
		lines := strings.Split(strings.TrimRight(m.help, "\n"), "\n")
		for _, line := range lines {
			if !strings.Contains(all, line+"\n") {
				t.Errorf("`quilzo help` does not print the line %q", strings.TrimSpace(line))
			}
		}
		for _, asked := range [][]string{{"help", m.command}, {m.command, "--help"}} {
			o, e, code := cliRun(t, "", "", asked...)
			if code != 0 {
				t.Errorf("`quilzo %s` exited %d: %s", strings.Join(asked, " "), code, firstLines(e, 3))
				continue
			}
			for _, line := range lines {
				if strings.HasPrefix(line, "  quilzo ") && !strings.Contains(o, line) {
					t.Errorf("`quilzo %s` does not print the line %q", strings.Join(asked, " "), strings.TrimSpace(line))
				}
			}
		}
	}
}

// What registerCLI refuses, it refuses before anything is changed: a
// command already taken, one with no lines in the help or lines about
// another command, a row of the privilege table that needs nothing and does
// not say why, and a function the source-walking tests could not find.
func TestRegisteringACommandIsHeldToTheTables(t *testing.T) {
	good := cliModule{module: "example", command: "example-check", heading: "an example",
		help:  "  quilzo example-check list          what there is\n",
		run:   cmdVersionLikeForTest,
		needs: map[string]need{"example-check": {action: auth.ActView}}}
	if err := checkCLIModule(good); err != nil {
		t.Fatalf("a module declared rightly is refused: %v", err)
	}
	for what, change := range map[string]func(*cliModule){
		"a command that is taken":      func(m *cliModule) { m.command, m.needs = "publish", map[string]need{"publish": {action: auth.ActView}} },
		"no lines in the help":         func(m *cliModule) { m.help = "" },
		"a line about another command": func(m *cliModule) { m.help = "  quilzo publish list   what there is\n" },
		"a line that says nothing":     func(m *cliModule) { m.help = "  quilzo example-check list\n" },
		"no row of its own":            func(m *cliModule) { m.needs = map[string]need{} },
		"a row that needs nothing silently": func(m *cliModule) {
			m.needs = map[string]need{"example-check": {}}
		},
		"a row about another command": func(m *cliModule) {
			m.needs = map[string]need{"example-check": {action: auth.ActView}, "publish": {action: auth.ActView}}
		},
		"a function the tests cannot find": func(m *cliModule) { m.run = func(string, []string) error { return nil } },
		"an area that is none":             func(m *cliModule) { m.area = "/blog" },
		"no heading":                       func(m *cliModule) { m.heading = "" },
	} {
		m := good
		change(&m)
		if err := checkCLIModule(m); err == nil {
			t.Errorf("a module with %s is registered", what)
		}
	}
	if _, ok := commandNeeds["example-check"]; ok {
		t.Error("checking a module changed the privilege table")
	}
}

func cmdVersionLikeForTest(string, []string) error { return errors.New("not run") }

// The operations a module registers are on the agent interface buildMCP
// serves, gated as every operation is.
func TestBuildMCPOffersTheModulesOperations(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, &Caller{Name: "test"}, "templates")
	have := map[string]mcp.Operation{}
	for _, op := range srv.Operations() {
		have[op.Name] = op
	}
	ops := moduleOperations()
	if len(ops) == 0 {
		t.Fatal("no module registers an operation")
	}
	for _, name := range ops {
		op, ok := have[name]
		if !ok {
			t.Errorf("%s is in the ledger and buildMCP does not offer it", name)
			continue
		}
		if op.Area == "" || !auth.IsArea(op.Area) {
			t.Errorf("%s is asked about %q; a module's operation is asked about its area", name, op.Area)
		}
	}
}
