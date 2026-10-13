// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// The workspace's actions, performed for a run. Each is one step: the
// session has checked the declaration holds it, the breaker has had its
// say, and a command that commits to something has been seen by a person
// (Weighs). What is left is to do it and say what happened.

// Driver performs the workspace's actions for one run.
type Driver struct {
	Session   *agent.Session
	Workspace *Workspace
	// Box runs commands; its Proxy is used only for a command that reaches
	// the network, and only when the declaration names hosts.
	Box Box
	// Keep is told about each command, for the run's record. Nil keeps
	// nothing.
	Keep func(Kept)
	// Beat says the run is still going, every half minute while a command
	// runs, so a long one does not make it look cut off.
	Beat func()
	// Wrote is told when the workspace was written while the run held
	// something private, so a later run on it knows (the breaker).
	Wrote func(private []string)

	mu    sync.Mutex
	index *Index
}

// Kept is a command as the run's record has it.
type Kept struct {
	Program string
	Args    []string
	Kind    string
	Exit    int
	Took    time.Duration
	Stopped string
	Total   int64
	Digest  string
	Output  []byte
	Changes Changes
}

// Performs reports whether the driver performs an action.
func Performs(a agent.Action) bool { return a.Tool == "" && a.Delegate == "" && agent.IsShell(a.Op) }

func (d *Driver) decl() *agent.Shell {
	if s := d.Session.Manifest().Shell; s != nil {
		return s
	}
	return &agent.Shell{}
}

func str(a agent.Action, k string) string {
	v, _ := a.Input[k].(string)
	return strings.TrimSpace(v)
}

// argv is a command's program and arguments as the action gives them.
func argv(a agent.Action) (string, []string, error) {
	program := str(a, "program")
	var args []string
	switch v := a.Input["args"].(type) {
	case nil:
	case []string:
		args = v
	case []any:
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return "", nil, errors.New("each argument is text")
			}
			args = append(args, s)
		}
	default:
		return "", nil, errors.New(`"args" is a list of the program's arguments`)
	}
	if program == "" {
		return "", nil, errors.New(`name the program to run in "program", and its arguments in "args"`)
	}
	if len(args) > 256 {
		return "", nil, errors.New("at most 256 arguments")
	}
	// Refused rather than cut: a command is asked about whole, and one
	// longer than a person can read is not one they can approve.
	total := len(program)
	for _, a := range args {
		total += len(a) + 1
	}
	if total > MaxCommand {
		return "", nil, fmt.Errorf("the command is %d bytes; at most %d", total, MaxCommand)
	}
	return program, args, nil
}

// MaxCommand bounds a command's program and arguments together.
const MaxCommand = 4096

// Line is a command as a person reads it, cut for a list.
func Line(program string, args []string) string {
	s := FullLine(program, args)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// FullLine is a command as a person reads it, whole: what they are asked
// about.
func FullLine(program string, args []string) string {
	parts := []string{program}
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n'\"\\$`;&|<>(){}*?[]#~") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

// Perform wraps a run's performer: the workspace's actions here, the rest
// passed on.
func (d *Driver) Perform(next func(context.Context, agent.Action) (string, error)) func(context.Context, agent.Action) (string, error) {
	return func(ctx context.Context, a agent.Action) (string, error) {
		if !Performs(a) {
			return next(ctx, a)
		}
		if err := d.Session.Check(a.Op); err != nil {
			return "", err
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		switch a.Op {
		case "file_list":
			return d.list(str(a, "path"))
		case "file_read":
			return d.read(str(a, "path"))
		case "file_write":
			text, _ := a.Input["text"].(string)
			return d.write(str(a, "path"), text)
		case "shell_run":
			return d.run(ctx, a)
		}
		return "", fmt.Errorf("%q is not one of the workspace's actions", a.Op)
	}
}

func (d *Driver) list(name string) (string, error) {
	items, more, err := d.Workspace.List(name)
	if err != nil {
		return "", err
	}
	// File names are words too, and may be somebody else's.
	d.Session.ReadFiles(name)
	var b strings.Builder
	where := name
	if where == "" {
		where = "."
	}
	fmt.Fprintf(&b, "%s holds %d things:\n", where, len(items))
	for _, it := range items {
		switch it.Kind {
		case "folder":
			fmt.Fprintf(&b, "  %s/\n", it.Name)
		case "link":
			fmt.Fprintf(&b, "  %s (a link)\n", it.Name)
		default:
			fmt.Fprintf(&b, "  %s (%d bytes)\n", it.Name, it.Size)
		}
	}
	if more {
		fmt.Fprintf(&b, "… and more, left out after %d\n", MaxListed)
	}
	return b.String(), nil
}

func (d *Driver) read(name string) (string, error) {
	text, err := d.Workspace.Read(name)
	if err != nil {
		return "", err
	}
	// Whatever is in the workspace may have been written by somebody else:
	// a repository cloned, a file a page gave.
	d.Session.ReadFiles(name)
	return text, nil
}

func (d *Driver) write(name, text string) (string, error) {
	sh := d.decl()
	if sh.ReadOnly {
		return "", errors.New("this run only reads; nothing is written")
	}
	before := d.scan()
	if err := d.overQuota(before, sh); err != nil {
		return "", err
	}
	if err := d.Workspace.Write(name, text); err != nil {
		return "", err
	}
	d.wrote()
	after := d.rescan()
	return fmt.Sprintf("wrote %s (%d bytes); %s", name, len(text), after.Since(before)), nil
}

// overQuota says why nothing more may be written: the workspace and the
// run's scratch home together are over the quota, or could not be
// measured.
func (d *Driver) overQuota(ix Index, sh *agent.Shell) error {
	quota := int64(sh.Quota()) << 20
	home, ok := SizeOf(d.Box.Home)
	switch {
	case ix.Cut || !ok:
		return fmt.Errorf("the workspace could not be measured (a folder it cannot read, or more than %d things); "+
			"remove something before writing", MaxEntries)
	case ix.Size+home > quota:
		return fmt.Errorf("the workspace is %d MiB, over its %d MiB; remove something before writing", (ix.Size+home)>>20, sh.Quota())
	}
	return nil
}

// wrote tells whoever keeps the breaker's memory that the workspace was
// written while the run held something private.
func (d *Driver) wrote() {
	if d.Wrote != nil {
		if p := d.Session.Private(); len(p) > 0 {
			d.Wrote(p)
		}
	}
}

// scan is the last index of the workspace, made if there is none yet.
func (d *Driver) scan() Index {
	if d.index == nil {
		ix := d.Workspace.Scan()
		d.index = &ix
	}
	return *d.index
}

func (d *Driver) rescan() Index {
	ix := d.Workspace.Scan()
	d.index = &ix
	return ix
}

func (d *Driver) run(ctx context.Context, a agent.Action) (string, error) {
	sh := d.decl()
	program, args, err := argv(a)
	if err != nil {
		return "", err
	}
	if !sh.Runs(program) {
		return "", fmt.Errorf("%s is not a program this agent may run (%s)", program, strings.Join(sh.Programs, ", "))
	}
	path, err := Find(program)
	if err != nil {
		return "", err
	}
	kind := Classify(program, args)
	line := Line(program, args)
	switch {
	case sh.ReadOnly && !kind.Reads():
		return "", fmt.Errorf("this run only reads, and %s %s", line, kind)
	case kind.Network && len(sh.Hosts) == 0 && kind.Destroys:
		// Could do anything, a shell say, and is asked about whatever it
		// is; with no host named it runs with no network.
		kind.Network = false
	case kind.Network && len(sh.Hosts) == 0:
		return "", fmt.Errorf("%s reaches the network, and this agent may reach no host", line)
	}
	before := d.scan()
	if kind.Writes && !kind.Destroys {
		if err := d.overQuota(before, sh); err != nil {
			return "", err
		}
	}
	b := d.Box
	b.Timeout = sh.CommandTimeout()
	if t := str(a, "timeout"); t != "" {
		if dur, err := time.ParseDuration(t); err == nil && dur > 0 && dur < b.Timeout {
			b.Timeout = dur
		}
	}
	b.MemoryMB = sh.Memory()
	if !kind.Network {
		b.Proxy = nil
	}
	// While it runs: the run's record kept fresh, and the workspace and
	// home measured, so a command that would fill the disk is stopped
	// when it goes over rather than found afterwards.
	cctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		quota := int64(sh.Quota()) << 20
		beat, measure := time.NewTicker(30*time.Second), time.NewTicker(5*time.Second)
		defer beat.Stop()
		defer measure.Stop()
		for {
			select {
			case <-cctx.Done():
				return
			case <-beat.C:
				if d.Beat != nil {
					d.Beat()
				}
			case <-measure.C:
				if kind.Reads() {
					continue
				}
				ws, ok1 := SizeOf(b.Workspace)
				home, ok2 := SizeOf(b.Home)
				if !ok1 || !ok2 || ws+home > quota {
					cancel(fmt.Errorf("it went over the workspace's %d MiB", sh.Quota()))
					return
				}
			}
		}
	}()
	out, err := b.Run(cctx, Command{Path: path, Args: args, Kind: kind})
	cancel(nil)
	<-watched
	if cause := context.Cause(cctx); cause != nil && cause != context.Canceled && ctx.Err() == nil {
		out.Stopped = cause.Error()
		err = nil
	}
	if err != nil {
		return "", err
	}
	if kind.Writes || kind.Destroys {
		d.wrote()
	}
	// What it printed may be somebody else's words: a file's, a server's.
	d.Session.ReadFiles(line)
	var changes Changes
	if kind.Writes || kind.Destroys {
		changes = d.rescan().Since(before)
	}
	if d.Keep != nil {
		d.Keep(Kept{Program: program, Args: args, Kind: kind.String(), Exit: out.Exit, Took: out.Took,
			Stopped: out.Stopped, Total: out.Total, Digest: out.Digest, Output: out.Kept, Changes: changes})
	}
	var head strings.Builder
	fmt.Fprintf(&head, "%s: exit %d in %s", line, out.Exit, out.Took.Round(time.Millisecond))
	if out.Stopped != "" {
		fmt.Fprintf(&head, " (stopped: %s)", out.Stopped)
	}
	if kind.Writes || kind.Destroys {
		fmt.Fprintf(&head, "; %s", changes)
	}
	if out.Total == 0 {
		return head.String() + "; it printed nothing", nil
	}
	return head.String() + "\n" + out.Text, nil
}

// Weighs says why an action commits to something a person should see
// first. What it cannot weigh (a program not declared, an argument list
// that does not parse) it leaves to the action, which refuses it.
func (d *Driver) Weighs(a agent.Action) string {
	if !Performs(a) {
		return ""
	}
	sh := d.decl()
	switch a.Op {
	case "file_write":
		if sh.Asks("write") && !sh.ReadOnly {
			return "it writes " + str(a, "path") + " in the workspace"
		}
	case "shell_run":
		program, args, err := argv(a)
		if err != nil || !sh.Runs(program) {
			return ""
		}
		kind := Classify(program, args)
		var why []string
		if kind.Destroys {
			why = append(why, "it deletes or rewrites history, which nothing brings back")
		}
		if kind.Network && len(sh.Hosts) > 0 {
			if sh.Asks("network") {
				why = append(why, "it reaches the network ("+strings.Join(sh.Hosts, ", ")+")")
			}
			if b, breaks := d.Session.BreaksTo(strings.Join(sh.Hosts, ", ")); breaks {
				why = append(why, b)
			}
		}
		if kind.Writes && !kind.Destroys && sh.Asks("write") {
			why = append(why, "it changes the workspace")
		}
		if len(why) > 0 && !sh.ReadOnly {
			return "it runs " + FullLine(program, args) + ": " + strings.Join(why, "; and ")
		}
	}
	return ""
}
