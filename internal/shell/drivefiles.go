// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// The driver's side of the file actions in files.go, and code_run.

// Bounds on code given to code_run.
const (
	// MaxCode is the most code code_run takes.
	MaxCode = 128 << 10
	// MaxAskedCode is the most code that may change the workspace: it is
	// shown whole to the person asked, and more than this is not something
	// a person can read and approve.
	MaxAskedCode = 8 << 10
)

// Languages are what code_run runs, each by the interpreters that run it
// (the first the declaration names is used) and the arguments that make
// one read its program from its input.
var Languages = map[string]struct {
	Programs []string
	Args     []string
}{
	"python":     {[]string{"python3", "python"}, []string{"-"}},
	"javascript": {[]string{"node"}, []string{"-"}},
	"typescript": {[]string{"deno"}, []string{"run", "--no-prompt", "-"}},
	"shell":      {[]string{"sh", "bash"}, []string{"-s"}},
	"bash":       {[]string{"bash"}, []string{"-s"}},
	"ruby":       {[]string{"ruby"}, []string{"-"}},
	"perl":       {[]string{"perl"}, []string{"-"}},
	"php":        {[]string{"php"}, nil},
	"lua":        {[]string{"lua"}, []string{"-"}},
}

// languageAliases are other names a model gives a language.
var languageAliases = map[string]string{"py": "python", "python3": "python", "js": "javascript", "node": "javascript",
	"ts": "typescript", "deno": "typescript", "sh": "shell"}

// interpreter is the program that runs a language here and its arguments.
func (d *Driver) interpreter(language string) (string, []string, error) {
	l := strings.ToLower(strings.TrimSpace(language))
	if a, ok := languageAliases[l]; ok {
		l = a
	}
	lang, ok := Languages[l]
	if !ok {
		return "", nil, fmt.Errorf("%q is not a language code_run runs (%s)", language, strings.Join(LanguageNames(), ", "))
	}
	sh := d.decl()
	for _, p := range lang.Programs {
		if sh.Runs(p) {
			return p, lang.Args, nil
		}
	}
	return "", nil, fmt.Errorf("this agent may not run %s: its declaration names none of %s", l, strings.Join(lang.Programs, ", "))
}

// LanguageNames are the languages code_run runs, sorted.
func LanguageNames() []string { return slices.Sorted(maps.Keys(Languages)) }

func (d *Driver) readLines(name string, from, lines int) (string, error) {
	text, total, err := d.Workspace.ReadLines(name, from, lines)
	if err != nil {
		return "", err
	}
	d.Session.ReadFiles(name)
	if from < 1 {
		from = 1
	}
	shown := strings.Count(text, "\n")
	return fmt.Sprintf("%s, lines %d to %d of %d:\n%s", name, from, from+max(shown, 1)-1, total, text), nil
}

// change edits, moves or deletes, and says what changed.
func (d *Driver) change(a agent.Action) (string, error) {
	sh := d.decl()
	if sh.ReadOnly {
		return "", errors.New("this run only reads; nothing is changed")
	}
	before := d.scan()
	now := time.Now()
	var said string
	switch a.Op {
	case "file_edit":
		if err := d.overQuota(before, sh); err != nil {
			return "", err
		}
		name := str(a, "path")
		if _, inserting := a.Input["insert"]; inserting {
			if err := d.Workspace.Insert(name, num(a, "line"), raw(a, "insert")); err != nil {
				return "", err
			}
			said = fmt.Sprintf("inserted %d bytes into %s after line %d", len(raw(a, "insert")), name, num(a, "line"))
			break
		}
		n, err := d.Workspace.Edit(name, raw(a, "old"), raw(a, "new"), yes(a, "all"))
		if err != nil {
			return "", err
		}
		said = fmt.Sprintf("replaced %s in %s", plural(n, "one place", "places"), name)
	case "file_move":
		out, err := d.Workspace.Move(nonEmpty(str(a, "from"), str(a, "path")), str(a, "to"), now)
		if err != nil {
			return "", err
		}
		said = out
	case "file_delete":
		name := str(a, "path")
		where, err := d.Workspace.Delete(name, now)
		if err != nil {
			return "", err
		}
		if where == "" {
			said = "deleted " + name + " for good"
		} else {
			said = fmt.Sprintf("moved %s to the bin as %s; file_move brings it back within a week", name, where)
		}
	}
	d.wrote()
	return said + "; " + d.rescan().Since(before).String(), nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func (d *Driver) search(a agent.Action) (string, error) {
	under := str(a, "path")
	found, cut, err := d.Workspace.Search(under, str(a, "name"), raw(a, "text"), yes(a, "regex"), yes(a, "ignore_case"))
	if err != nil {
		return "", err
	}
	// What a search shows is the workspace's words, which may be somebody
	// else's.
	d.Session.ReadFiles(nonEmpty(under, "."))
	var b strings.Builder
	switch {
	case len(found) == 0:
		b.WriteString("nothing found")
	case raw(a, "text") == "":
		fmt.Fprintf(&b, "%s:\n", plural(len(found), "one file", "files"))
		for _, f := range found {
			fmt.Fprintf(&b, "  %s\n", f.File)
		}
	default:
		fmt.Fprintf(&b, "%s:\n", plural(len(found), "one line", "lines"))
		for _, f := range found {
			fmt.Fprintf(&b, "  %s:%d: %s\n", f.File, f.Line, f.Text)
		}
	}
	if cut {
		fmt.Fprintf(&b, "\n… it stopped before looking everywhere (at most %d found and %d files read); narrow it with path or name", MaxFound, MaxSearched)
	}
	return b.String(), nil
}

// code runs code with an interpreter the declaration names. Without
// "writes" the workspace is read-only to it, so it reads, computes and
// prints, and needs nobody; with it, the code may change anything there,
// and a person sees it whole first (Weighs). It never reaches the network.
func (d *Driver) code(ctx context.Context, a agent.Action) (string, error) {
	sh := d.decl()
	program, args, err := d.interpreter(str(a, "language"))
	if err != nil {
		return "", err
	}
	code := raw(a, "code")
	writes := yes(a, "writes")
	switch {
	case strings.TrimSpace(code) == "":
		return "", errors.New(`give the program to run in "code"`)
	case len(code) > MaxCode:
		return "", fmt.Errorf("the code is %d bytes; at most %d", len(code), MaxCode)
	case writes && len(strings.TrimSpace(code)) > MaxAskedCode:
		return "", fmt.Errorf("code that changes the workspace is shown whole to a person first, and this is %d bytes; "+
			"at most %d. Write it to a file and run that with shell_run", len(code), MaxAskedCode)
	case writes && sh.ReadOnly:
		return "", errors.New("this run only reads, and this code would change the workspace")
	}
	path, err := Find(program)
	if err != nil {
		return "", err
	}
	kind := Kind{}
	if writes {
		kind = Kind{Writes: true, Destroys: true}
	}
	var before Index
	if writes {
		before = d.scan()
		if err := d.overQuota(before, sh); err != nil {
			return "", err
		}
	}
	b := d.Box
	b.Timeout, b.MemoryMB, b.Proxy = sh.CommandTimeout(), sh.Memory(), nil
	if t := str(a, "timeout"); t != "" {
		if dur, err := time.ParseDuration(t); err == nil && dur > 0 && dur < b.Timeout {
			b.Timeout = dur
		}
	}
	out, err := d.execute(ctx, b, Command{Path: path, Args: args, Kind: kind, Stdin: code}, sh)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(code))
	digest := "code sha256:" + hex.EncodeToString(sum[:]) + fmt.Sprintf(" (%d bytes)", len(code))
	line := program + " " + strings.Join(args, " ")
	d.Session.ReadFiles(line)
	var changes Changes
	if writes {
		d.wrote()
		changes = d.rescan().Since(before)
	}
	if d.Keep != nil {
		d.Keep(Kept{Program: program, Args: args, Kind: kind.String(), Exit: out.Exit, Took: out.Took, Stopped: out.Stopped,
			Total: out.Total, Digest: out.Digest, Output: out.Kept, Changes: changes, Input: digest})
	}
	var head strings.Builder
	fmt.Fprintf(&head, "%s code: exit %d in %s", program, out.Exit, out.Took.Round(time.Millisecond))
	if out.Stopped != "" {
		fmt.Fprintf(&head, " (stopped: %s)", out.Stopped)
	}
	if writes {
		fmt.Fprintf(&head, "; %s", changes)
	}
	if out.Total == 0 {
		return head.String() + "; it printed nothing", nil
	}
	return head.String() + "\n" + out.Text, nil
}
