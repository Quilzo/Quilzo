// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agentexec"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// A security module's commands and operations, registered from the module's
// own file.
//
// A command has always been five edits in five places: a case in main's
// switch, lines in the help, a row in the privilege table, an area in the
// table of areas, and a call in buildMCP for its operations. That is right
// for one program written in order, and it is how two people adding two
// modules in the same week edit the same five lists. The security modules
// are built side by side, so each brings its command with it: a file that
// ends with one call to registerCLI, in an init, and no line changed
// anywhere else.
//
// What is registered is held to what the tables are held to, by the same
// tests. The tests that read main.go's switch, its help and the privilege
// table read the registered modules with them (modules_test.go), so a
// registered command is in the help, has a row, refuses a word it does not
// take and is accounted for on every surface exactly as if it had been
// written into the tables; and a further test runs each one for its
// documented exits.

// cliModule is what a module adds to the command line and to the agent
// interface.
type cliModule struct {
	// module is the module's name, under which its screens and its routes
	// in the content API are registered too (internal/register's ledger).
	module string
	// command is the word it is run by. It is not an alias of anything,
	// and nothing else may be called it.
	command string
	// heading is the section of the help its lines go under, as the help's
	// other sections are headed, and help is the lines themselves, each
	// "  quilzo COMMAND ..." with its description after two spaces or more.
	heading string
	help    string
	// run runs the command with what followed its name. It is a function
	// named cmdSomething, as the commands in main's switch are, so the
	// tests that read a command's subcommands from its switch read it.
	run func(root string, args []string) error
	// needs is what each line needs before it runs, keyed as the privilege
	// table is: the command alone, or the command and a subcommand.
	needs map[string]need
	// area is the area of the access policy the command is asked about in
	// place of the whole site, as the table of areas has it.
	area string
	// reads are lines that only read: each answers --json, and a test runs
	// each to see it does.
	reads [][]string
	// absent is a line that names something that is not there, which a
	// test runs to see it exit 4.
	absent []string
	// ops registers the module's operations on the agent interface. It
	// calls srv.Register and nothing else when it is called; the work is in
	// the handlers.
	ops func(srv *mcp.Server, root string, caller *Caller)
	// jobs is the work the module needs done because time passed (a
	// retention period ending), which the admin server runs on its upkeep
	// timer with its own (upkeepJobs). Nil is none.
	jobs func(root string) []upkeep.Job
	// notForRuns says why an agent's run does not perform the module's
	// operations through the agent interface, as an outside agent may.
	// Empty, they are performed for a run like the store's own reads and
	// proposals (agentexec.Bridged), and registerCLI adds them there.
	notForRuns string
}

// cliModules is every module's commands, in the order of their names.
var cliModules []cliModule

var reHelpLine = regexp.MustCompile(`^  quilzo ([a-z][a-z0-9-]*)( .*)?$`)

// registerCLI adds a module's command. It is called from an init in the
// module's own file. A module declared wrongly stops the program starting,
// with what is wrong: that is a mistake in the program, found the first time
// anything runs, tests included.
func registerCLI(m cliModule) {
	if err := checkCLIModule(m); err != nil {
		panic("quilzo: the module " + m.module + ": " + err.Error())
	}
	for key, n := range m.needs {
		commandNeeds[key] = n
	}
	if m.area != "" {
		commandAreas[m.command] = m.area
	}
	cliModules = append(cliModules, m)
	sort.Slice(cliModules, func(i, j int) bool { return cliModules[i].command < cliModules[j].command })
	register.Offer(m.module, register.SurfaceCLI, "quilzo "+m.command)
	if names := operationsOf(m); len(names) > 0 {
		register.Offer(m.module, register.SurfaceMCP, names...)
	}
	if m.notForRuns == "" {
		for _, op := range operationList(m) {
			agentexec.Bridged[op.Name] = op.Writes
		}
	}
}

// operationsOf is the names of the operations a module registers, found by
// letting it register them on a server nobody serves: what is offered here
// is what buildMCP will offer.
func operationsOf(m cliModule) []string {
	var names []string
	for _, op := range operationList(m) {
		names = append(names, op.Name)
	}
	return names
}

func operationList(m cliModule) []mcp.Operation {
	if m.ops == nil {
		return nil
	}
	srv := mcp.NewServer("quilzo", version)
	m.ops(srv, "", &Caller{})
	return srv.Operations()
}

// notForRuns is why a module's operation is not performed for an agent's
// run, or "" when it is or is no module's.
func notForRuns(op string) string {
	for _, m := range cliModules {
		for _, name := range operationsOf(m) {
			if name == op {
				return m.notForRuns
			}
		}
	}
	return ""
}

// checkCLIModule is what registerCLI refuses, without changing anything.
func checkCLIModule(m cliModule) error {
	switch {
	case m.command == "" || strings.HasPrefix(m.command, "-") || strings.HasPrefix(m.command, "_"):
		return fmt.Errorf("%q is not a command's name", m.command)
	case m.run == nil:
		return fmt.Errorf("quilzo %s runs nothing", m.command)
	case !strings.HasPrefix(funcName(m.run), "cmd"):
		return fmt.Errorf("quilzo %s runs %s; a command's function is called cmdSomething, which is how its tests find it",
			m.command, funcName(m.run))
	case strings.TrimSpace(m.heading) == "" || strings.Contains(m.heading, "\n"):
		return fmt.Errorf("quilzo %s has no heading for its lines of the help", m.command)
	case m.area != "" && !auth.IsArea(m.area):
		return fmt.Errorf("quilzo %s is asked about %q, which is not an area", m.command, m.area)
	}
	if _, taken := commandNeeds[m.command]; taken {
		return fmt.Errorf("quilzo %s is a command already", m.command)
	}
	if movedOut[m.command] {
		return fmt.Errorf("quilzo %s is a command that has left Quilzo, and its name says so", m.command)
	}
	lines := 0
	for _, line := range strings.Split(strings.TrimRight(m.help, "\n"), "\n") {
		if strings.HasPrefix(line, "    ") {
			continue // the rest of the entry above
		}
		sub := reHelpLine.FindStringSubmatch(line)
		if sub == nil || sub[1] != m.command {
			return fmt.Errorf("the help line %q is not about quilzo %s", line, m.command)
		}
		if !helpDescription.MatchString(sub[2]) {
			return fmt.Errorf("the help line %q says nothing about what it does", line)
		}
		lines++
	}
	if lines == 0 {
		return fmt.Errorf("quilzo %s has no lines in the help", m.command)
	}
	if _, ok := m.needs[m.command]; !ok {
		return fmt.Errorf("quilzo %s does not say what it needs to run", m.command)
	}
	for key, n := range m.needs {
		if key != m.command && !strings.HasPrefix(key, m.command+" ") {
			return fmt.Errorf("the privilege row %q is not about quilzo %s", key, m.command)
		}
		if n.action == "" && strings.TrimSpace(n.why) == "" {
			return fmt.Errorf("the privilege row %q needs nothing and does not say why that is safe", key)
		}
	}
	for _, line := range append(append([][]string{}, m.reads...), m.absent) {
		if len(line) > 0 && line[0] != m.command {
			return fmt.Errorf("the line %q a test runs is not quilzo %s", strings.Join(line, " "), m.command)
		}
	}
	return nil
}

// moduleCommand is the module whose command cmd is.
func moduleCommand(cmd string) (cliModule, bool) {
	for _, m := range cliModules {
		if m.command == cmd {
			return m, true
		}
	}
	return cliModule{}, false
}

// registerModuleOps adds every module's operations to the agent interface,
// after the program's own (buildMCP).
func registerModuleOps(srv *mcp.Server, root string, caller *Caller) {
	for _, m := range cliModules {
		if m.ops != nil {
			m.ops(srv, root, caller)
		}
	}
}

// moduleJobs is every module's upkeep jobs, in the order of their
// commands.
func moduleJobs(root string) []upkeep.Job {
	var out []upkeep.Job
	for _, m := range cliModules {
		if m.jobs != nil {
			out = append(out, m.jobs(root)...)
		}
	}
	return out
}

// fullHelp is the help as it is printed: usageText, with each module's
// section placed before the exit codes, which end it.
//
// Every place the help is read from reads this, so a module's lines answer
// `quilzo help COMMAND`, `quilzo COMMAND --help` and a refusal's quotation
// of the lines about a command, as the lines in usageText do.
func fullHelp() string {
	sections := moduleSections()
	if sections == "" {
		return usageText
	}
	const end = "exit codes\n"
	i := strings.LastIndex(usageText, end)
	if i < 0 {
		return usageText + "\n" + sections
	}
	return usageText[:i] + sections + usageText[i:]
}

// moduleSections is the modules' lines of the help, under their headings,
// each section followed by a blank line as the help's own are.
func moduleSections() string {
	var b strings.Builder
	var headings []string
	byHeading := map[string][]string{}
	for _, m := range cliModules {
		if _, seen := byHeading[m.heading]; !seen {
			headings = append(headings, m.heading)
		}
		byHeading[m.heading] = append(byHeading[m.heading], strings.TrimRight(m.help, "\n"))
	}
	for _, h := range headings {
		b.WriteString(h + "\n")
		for _, lines := range byHeading[h] {
			b.WriteString(lines + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// funcName is the name a function was declared with, without its package.
func funcName(fn any) string {
	f := runtime.FuncForPC(reflect.ValueOf(fn).Pointer())
	if f == nil {
		return ""
	}
	name := f.Name()
	return name[strings.LastIndex(name, ".")+1:]
}
