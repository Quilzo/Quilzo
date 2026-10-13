// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/sandbox"
)

// One command, in a box of its own: the agent box's namespaces, Landlock,
// system call filter and limits, writing only the workspace and a scratch
// home, with no network unless the command is one that reaches it. Its
// input is empty and its environment asks for no prompts, so a program
// that would ask a question gets nothing rather than waiting. When it ends,
// the box ends, and everything it started ends with it.

// Bounds on what a command's output is kept and shown as.
const (
	MaxKept   = 1 << 20
	ShownHead = 2 << 10
	ShownTail = 6 << 10
)

// Path is where a program is looked for, outside the box and in it.
var Path = []string{"/usr/local/bin", "/usr/bin", "/bin"}

// Find is a program's path, by name, on Path.
func Find(name string) (string, error) {
	if !reName(name) {
		return "", fmt.Errorf("%q is not a program's name", name)
	}
	for _, dir := range Path {
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s is not installed here (looked in %s)", name, strings.Join(Path, ", "))
}

func reName(s string) bool {
	if s == "" || len(s) > 64 || strings.ContainsAny(s, "/\\\x00") || s == "." || s == ".." {
		return false
	}
	return true
}

// Box is where one run's commands run.
type Box struct {
	Backend agentbox.Backend
	RunID   string
	Agent   string
	// Workspace is the folder commands work in. Home is this run's scratch
	// home, outside it and made fresh for the run; Cache the agent's caches
	// (modules, builds), kept between runs and written only by a command
	// that writes. A command that only reads gets a home of its own, made
	// for it and removed after, and the caches to read.
	Workspace, Home, Cache string
	// Proxy is handed only to a command that reaches the network, and
	// ProxyURL is what it is told to use.
	Proxy    *agentbox.Service
	ProxyURL string
	// Env is the declaration's own settings; nothing secret.
	Env      []string
	Timeout  time.Duration
	MemoryMB int
}

// Command is one command to run.
type Command struct {
	// Path is the program, found by Find; Args its arguments as given.
	Path string
	Args []string
	Kind Kind
}

// Output is how a command went.
type Output struct {
	Exit    int
	Took    time.Duration
	Stopped string
	// Text is what the model is shown: all of the output, or its start
	// and its end.
	Text string
	// Kept is the start of the output, up to MaxKept, for the run's record.
	Kept []byte
	// Total is how much it printed, and Digest the SHA-256 of all of it.
	Total  int64
	Digest string
}

// Run runs a command and waits for it.
func (b Box) Run(ctx context.Context, c Command) (Output, error) {
	if b.Backend == nil {
		return Output{}, errors.New("no box to run a command in here")
	}
	if !filepath.IsAbs(c.Path) {
		return Output{}, fmt.Errorf("%q is not a program found on the box's path", c.Path)
	}
	timeout := b.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	mem := b.MemoryMB
	if mem <= 0 {
		mem = 2048
	}
	if err := os.MkdirAll(b.Home, 0o700); err != nil {
		return Output{}, err
	}
	home, write, read := b.Home, []string{b.Home}, []string(nil)
	if c.Kind.Reads() {
		// Nothing a reading command leaves behind outlives it: not in the
		// workspace, not in a home a later command would read.
		h, err := os.MkdirTemp(b.Home, ".read-")
		if err != nil {
			return Output{}, err
		}
		defer os.RemoveAll(h)
		home, write = h, []string{h}
	}
	cache := b.Cache
	if cache == "" {
		cache = filepath.Join(home, ".cache")
	}
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return Output{}, err
	}
	if c.Kind.Reads() {
		read = append(read, cache)
	} else if b.Cache != "" {
		write = append(write, cache)
	}
	tmp := filepath.Join(home, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return Output{}, err
	}
	buildCache := filepath.Join(cache, "go-build")
	if c.Kind.Reads() {
		buildCache = filepath.Join(home, "go-build")
	}
	env := []string{
		"PATH=" + strings.Join(Path, ":"), "HOME=" + home, "TMPDIR=" + tmp, "LANG=C.UTF-8",
		"GOCACHE=" + buildCache, "GOMODCACHE=" + filepath.Join(cache, "go-mod"),
		"npm_config_cache=" + filepath.Join(cache, "npm"), "PIP_CACHE_DIR=" + filepath.Join(cache, "pip"),
		"XDG_CACHE_HOME=" + filepath.Join(home, ".cache"), "PYTHONNOUSERSITE=1",
		// Nobody is at a terminal: no prompts, no pager, no colour, and no
		// tool fetching a newer version of itself.
		"CI=1", "NO_COLOR=1", "TERM=dumb", "PAGER=cat", "GIT_PAGER=cat", "GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false", "DEBIAN_FRONTEND=noninteractive", "GOTOOLCHAIN=local",
		// Git takes no settings from the scratch home or the system, which
		// an earlier command could have planted; it commits as the agent.
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=agent " + b.Agent, "GIT_AUTHOR_EMAIL=" + b.Agent + "@agents.quilzo.invalid",
		"GIT_COMMITTER_NAME=agent " + b.Agent, "GIT_COMMITTER_EMAIL=" + b.Agent + "@agents.quilzo.invalid",
	}
	if c.Kind.Reads() {
		// Nothing written, not even git's own optional index refresh.
		env = append(env, "GIT_OPTIONAL_LOCKS=0")
	}
	env = append(env, b.Env...)
	var services []agentbox.Service
	if c.Kind.Network && b.Proxy != nil {
		services = []agentbox.Service{*b.Proxy}
		env = append(env, "HTTPS_PROXY="+b.ProxyURL, "HTTP_PROXY="+b.ProxyURL,
			"https_proxy="+b.ProxyURL, "http_proxy="+b.ProxyURL)
	}
	out := &capture{h: sha256.New()}
	res, err := b.Backend.Run(ctx, agentbox.Spec{
		Run: b.RunID, Agent: b.Agent, Program: c.Path, Args: c.Args, Env: env,
		// A command that only reads gets its workspace read-only, so what it
		// runs in turn (a repository's configured hook, a preprocessor, a
		// sed script) cannot change it: the kind is enforced, as the
		// network is.
		Workdir: b.Workspace, ReadOnlyWorkdir: c.Kind.Reads(), Read: read, Write: write, Services: services,
		Limits: sandbox.Limits{CPUSeconds: uint64(timeout/time.Second) + 1, DataBytes: uint64(mem) << 20,
			FileBytes: 256 << 20, OpenFiles: 1024, Processes: 512},
		Wall:  timeout,
		Stdin: strings.NewReader(""), Stdout: out, Stderr: out,
	})
	o := Output{Exit: res.Exit, Took: res.Took, Stopped: res.Stopped}
	o.Text, o.Kept, o.Total, o.Digest = out.result()
	return o, err
}

// capture keeps the start and the end of a command's output, both streams
// as they come, and a digest of all of it.
type capture struct {
	mu    sync.Mutex
	head  []byte
	tail  []byte
	total int64
	h     interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total += int64(len(p))
	_, _ = c.h.Write(p)
	if room := MaxKept - len(c.head); room > 0 {
		c.head = append(c.head, p[:min(room, len(p))]...)
	}
	c.tail = append(c.tail, p...)
	if len(c.tail) > ShownTail {
		c.tail = append([]byte(nil), c.tail[len(c.tail)-ShownTail:]...)
	}
	return len(p), nil
}

func (c *capture) result() (text string, kept []byte, total int64, digest string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	digest = "sha256:" + hex.EncodeToString(c.h.Sum(nil))
	if c.total <= ShownHead+ShownTail {
		text = string(c.head)
	} else {
		text = string(c.head[:ShownHead]) +
			fmt.Sprintf("\n… %d bytes not shown …\n", c.total-int64(ShownHead)-int64(len(c.tail))) +
			string(c.tail)
	}
	return strings.ToValidUTF8(text, "�"), c.head, c.total, digest
}
