// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// OpenShell is NVIDIA OpenShell as a program's box: its sandbox, its
// Landlock, seccomp and network namespace, and its policy, compiled from
// the agent's manifest here.
//
// What OpenShell enforces it enforces itself, inside a container this
// process cannot see into; what Quilzo adds is the same as for the native
// box. The sandbox's network policy allows exactly one place: this
// machine, on the ports a run's services listen on. So the program reaches
// the store only through its run's interface, a model only through the
// gateway, and the outside only through the run's proxy, which asks the
// run's gate about each host and records each connection: OpenShell's
// network rules and Quilzo's are not two policies that can disagree,
// because OpenShell's says "Quilzo" and nothing else.
//
// Driven through its command line, as documented for v0.1: `openshell
// sandbox create --name --policy --no-tty --upload [--from] -- COMMAND`,
// and `openshell sandbox delete NAME`. The run's environment, its
// credential among it, is uploaded as a file rather than put on a command
// line any process here could read.
type OpenShell struct {
	// CLI is the openshell program; empty is the one on PATH.
	CLI string
	// Listen is the address of this machine the sandbox reaches, and Reach
	// the name it uses for it.
	Listen, Reach string
	// Image is the sandbox's --from, when the program's declaration names
	// one.
	Image string
	// Exec stands in for running the CLI, in tests.
	Exec func(ctx context.Context, argv []string, s Spec) (int, error)
}

func (o OpenShell) Name() string { return "openshell" }

func (o OpenShell) cli() (string, error) {
	if o.CLI != "" {
		return o.CLI, nil
	}
	return exec.LookPath("openshell")
}

func (o OpenShell) Check() Availability {
	will := Confinement{Backend: "openshell", Namespaces: true, Files: true, Ports: true, Seccomp: true,
		Capabilities: true, Note: "enforced by OpenShell inside its sandbox; this build compiles its policy"}
	if _, err := o.cli(); err != nil && o.Exec == nil {
		return Availability{Will: will, Why: "the openshell command is not installed here (https://docs.nvidia.com/openshell)"}
	}
	if net.ParseIP(o.Listen) == nil || o.Reach == "" {
		return Availability{Will: will, Why: "set where a sandbox reaches this machine: quilzo config set " +
			"agents.openshell_listen 172.17.0.1, and agents.openshell_reach to the name the sandbox uses for it"}
	}
	return Availability{OK: true, Will: will}
}

var reSandboxName = regexp.MustCompile(`[^a-z0-9-]+`)

// SandboxName is the sandbox a run gets: one per run, named for it.
func SandboxName(run string) string {
	n := "quilzo-" + reSandboxName.ReplaceAllString(strings.ToLower(run), "-")
	if len(n) > 63 {
		n = n[:63]
	}
	return strings.TrimRight(n, "-")
}

// Policy is a sandbox's policy, compiled from a run's spec: the paths it
// reads and writes, Landlock required rather than attempted, and one
// network rule, to this machine on the ports given, for the program alone.
func Policy(s Spec, reach string, ports map[string]int) []byte {
	var b strings.Builder
	q := func(v string) string { j, _ := json.Marshal(v); return string(j) } // a YAML double-quoted scalar
	b.WriteString("version: 1\n")
	b.WriteString("# Compiled by Quilzo from the agent " + q(s.Agent) + " for run " + q(s.Run) + ".\n")
	b.WriteString("filesystem_policy:\n  include_workdir: true\n  read_only:\n")
	reads := append(append([]string{}, systemReads...), "/dev/urandom")
	reads = append(reads, s.Read...)
	for _, r := range dedupe(reads) {
		b.WriteString("    - " + q(r) + "\n")
	}
	b.WriteString("  read_write:\n    - \"/tmp\"\n    - \"/dev/null\"\n")
	b.WriteString("landlock:\n  compatibility: hard_requirement\n")
	b.WriteString("network_policies:\n  quilzo_run:\n    name: " + q(SandboxName(s.Run)) + "\n    endpoints:\n")
	names := make([]string, 0, len(ports))
	for n := range ports {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "      - host: %s\n        port: %d\n        protocol: tcp\n        enforcement: enforce\n", q(reach), ports[n])
	}
	b.WriteString("    binaries:\n      - path: " + q(s.Program) + "\n")
	return []byte(b.String())
}

func dedupe(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range list {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// envFile is the program's environment as a file a shell reads, with the
// services' loopback addresses rewritten to where the sandbox reaches them.
func envFile(env []string, reach string, ports map[uint16]int) string {
	var b strings.Builder
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		for inside, outside := range ports {
			v = strings.ReplaceAll(v, "127.0.0.1:"+strconv.Itoa(int(inside)), net.JoinHostPort(reach, strconv.Itoa(outside)))
		}
		if k == "NO_PROXY" || k == "no_proxy" {
			v = reach
		}
		// Single-quoted, with each quote closed and reopened: nothing in a
		// value is ever read by the shell as anything but text.
		fmt.Fprintf(&b, "export %s='%s'\n", k, strings.ReplaceAll(v, "'", `'\''`))
	}
	return b.String()
}

// Run runs the program in a new sandbox, waits for it, and deletes the
// sandbox.
func (o OpenShell) Run(ctx context.Context, s Spec) (Result, error) {
	if len(s.Files) > 0 {
		return Result{}, errors.New("an OpenShell sandbox cannot be handed open files; a browser runs in the native box")
	}
	if a := o.Check(); !a.OK {
		return Result{}, fmt.Errorf("%w: %s", ErrUnavailable, a.Why)
	}
	if s.Workdir == "" || s.Program == "" {
		return Result{}, errors.New("a sandbox needs a program and a working directory")
	}
	// Each service on a port of its own, on the address the sandbox reaches.
	ports := map[string]int{}
	inside := map[uint16]int{}
	var lns []net.Listener
	defer func() {
		for _, ln := range lns {
			ln.Close()
		}
	}()
	for _, sv := range s.Services {
		ln, err := net.Listen("tcp", net.JoinHostPort(o.Listen, "0"))
		if err != nil {
			return Result{}, fmt.Errorf("the run's %s cannot listen on %s: %w", sv.Name, o.Listen, err)
		}
		lns = append(lns, ln)
		go forward(ln, sv.Socket)
		p := ln.Addr().(*net.TCPAddr).Port
		ports[sv.Name], inside[sv.Port] = p, p
	}
	policy := filepath.Join(s.Workdir, "openshell-policy.yaml")
	if err := os.WriteFile(policy, Policy(s, o.Reach, ports), 0o600); err != nil {
		return Result{}, err
	}
	env := filepath.Join(s.Workdir, "quilzo-env")
	if err := os.WriteFile(env, []byte(envFile(s.Env, o.Reach, inside)), 0o600); err != nil {
		return Result{}, err
	}
	defer os.Remove(env)
	name := SandboxName(s.Run)
	argv := []string{"sandbox", "create", "--name", name, "--policy", policy, "--no-tty",
		"--upload", env + ":/tmp/.quilzo-env"}
	if o.Image != "" {
		argv = append(argv, "--from", o.Image)
	}
	argv = append(argv, "--", "/bin/sh", "-c", `. /tmp/.quilzo-env && rm -f /tmp/.quilzo-env && exec "$@"`, "sh", s.Program)
	argv = append(argv, s.Args...)

	if s.Wall > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Wall)
		defer cancel()
	}
	start := time.Now()
	exit, err := o.exec(ctx, argv, s)
	res := Result{Exit: exit, Took: time.Since(start), Confined: o.Check().Will}
	if ctx.Err() == context.DeadlineExceeded {
		res.Stopped = fmt.Sprintf("it ran for its whole time (%s) and was stopped", s.Wall)
	}
	// Deleted whatever happened: a sandbox left behind is a program left
	// running with a run's reach after the run has ended.
	dctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, derr := o.exec(dctx, []string{"sandbox", "delete", name}, Spec{}); derr != nil && err == nil {
		res.Confined.Note = "the sandbox could not be deleted: " + derr.Error()
	}
	return res, err
}

func (o OpenShell) exec(ctx context.Context, argv []string, s Spec) (int, error) {
	if o.Exec != nil {
		return o.Exec(ctx, argv, s)
	}
	cli, err := o.cli()
	if err != nil {
		return 0, err
	}
	cmd := exec.CommandContext(ctx, cli, argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.Stdin, s.Stdout, s.Stderr
	// The CLI's own environment, which finds its gateway; the program's is
	// in the uploaded file.
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, err
}
