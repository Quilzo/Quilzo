// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package agentbox runs an agent's own program somewhere it reaches only
// what it was handed.
//
// # What a program is, here
//
// A model choosing from a manifest is one way an agent decides. A program
// is the other: a coding agent's command line, a script, a runtime somebody
// built their agent in. Quilzo does not run it as itself. It runs it in a
// box, and hands in three things over the box's own loopback:
//
//   - the agent interface, as MCP, for this run only: every operation the
//     program asks for is one step of the run, through the same gate,
//     budget, approvals, audit records and receipt as any other;
//   - a model endpoint, OpenAI-shaped, that goes through the model gateway:
//     the run is charged, budgets hold, and no provider key is ever inside;
//   - a proxy to the hosts the manifest names and nothing else, each
//     connection recorded.
//
// Nothing else is reachable. The program has a working directory of its
// own, reads the system's libraries and nothing of the store, holds no
// capability, and makes none of the system calls a confined program has
// no business making.
//
// # Backends
//
// Where the box is is a backend. The native one is built here from the
// kernel's own parts, needing no root, no daemon and no container runtime:
// user, PID, network, IPC and UTS namespaces, Landlock for files and ports,
// seccomp, no capabilities, resource limits. Another runtime (OpenShell,
// see openshell.go) can be the backend instead, with the same services
// handed in and the same manifest compiled to its policy.
package agentbox

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/quilzo/quilzo/internal/sandbox"
)

// Service is something handed into the box: a socket on this side, a port
// on the box's loopback.
type Service struct {
	Name   string `json:"name"`
	Socket string `json:"socket"`
	Port   uint16 `json:"port"`
}

// The ports the services are on inside the box. Fixed, so a program's own
// configuration can name them; the box has no other network for them to
// collide with.
const (
	PortMCP   uint16 = 8701
	PortModel uint16 = 8702
	PortProxy uint16 = 8703
)

// Spec is one run of a program.
type Spec struct {
	Run     string
	Agent   string
	Program string   // absolute
	Args    []string // after the program's own name
	// Env is the program's whole environment. Nothing of this process's
	// is passed on.
	Env []string
	// Workdir is the program's own directory, which it may write; its HOME
	// and TMPDIR are inside it.
	Workdir string
	// Read are further paths it may read, beyond the system's own.
	Read     []string
	Services []Service
	Limits   sandbox.Limits
	// Wall is how long it may run before it is stopped.
	Wall   time.Duration
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Files are handed to the program as its file descriptors from 3 on, in
	// order: a browser's control pipe, whose other ends this process keeps.
	// Nothing in the box can open them; only the program is given them.
	Files []*os.File
	// Started is called once the box's first process is running and holds
	// its own copies of Files, so the caller may close its ends.
	Started func()
}

// Result is how a run of a program ended.
type Result struct {
	Exit    int
	Stopped string // why it was stopped, when it was
	Took    time.Duration
	// Confined is what the box actually enforced, as the program's side
	// reported it before the program started.
	Confined Confinement
}

// Confinement is what a box enforced.
type Confinement struct {
	Backend      string `json:"backend"`
	Namespaces   bool   `json:"namespaces"`
	Landlock     int    `json:"landlock"`
	Files        bool   `json:"files"`
	Ports        bool   `json:"ports"`
	Seccomp      bool   `json:"seccomp"`
	Capabilities bool   `json:"capabilities_dropped"`
	// OwnProc is a /proc showing only the box's own processes.
	OwnProc bool   `json:"own_proc,omitempty"`
	Note    string `json:"note,omitempty"`
}

// Availability is whether a backend can run programs here, and what it
// would enforce.
type Availability struct {
	OK   bool
	Why  string
	Will Confinement
}

// Backend runs programs in boxes.
type Backend interface {
	Name() string
	Check() Availability
	Run(ctx context.Context, s Spec) (Result, error)
}

// ErrUnavailable is a backend that cannot run anything here.
var ErrUnavailable = errors.New("this backend cannot run programs here")
