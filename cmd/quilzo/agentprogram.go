// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/auth"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/sandbox"
)

// An agent's own program, run in a box for one run. See
// internal/agentbox: the program decides, every operation it asks for is a
// step of the run, its model calls go through the gateway charged to the
// run, and it reaches the outside only through a proxy to its manifest's
// hosts.

const (
	agentboxInit = "__agentbox"
	agentboxShim = "__agentbox-exec"
)

// programModel names a program where a model would be named: the actor of
// a run a program decided is the agent, and the log says what decided.
type programModel struct{ name string }

func (p programModel) Name() string { return "program:" + p.name }

func (p programModel) Complete(context.Context, string, string) (string, error) {
	return "", errors.New("a program decides for itself")
}

var _ assist.Model = programModel{}

// programBackend is where a program's box is.
func programBackend(root, name, image string) (agentbox.Backend, error) {
	switch name {
	case "", "native":
		self, err := os.Executable()
		if err != nil {
			return nil, err
		}
		return agentbox.Native{Exe: self, Init: []string{agentboxInit}, Shim: []string{agentboxShim}}, nil
	case "openshell":
		return openShellBackend(root, image)
	}
	return nil, fmt.Errorf("%q is not a backend", name)
}

// testBackend stands in for the real one in tests.
var testBackend agentbox.Backend

// programRun is one program running for one run.
type programRun struct {
	bridge  *agentbox.Bridge
	cancel  context.CancelFunc
	done    chan struct{}
	result  agentbox.Result
	err     error
	stdout  *capped
	stderr  *capped
	servers []*http.Server
	dirs    []string
	backend string
}

// capped keeps the last part of what a program wrote.
type capped struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf.Write(p)
	if over := c.buf.Len() - c.max; over > 0 {
		c.buf.Next(over)
	}
	return len(p), nil
}

func (c *capped) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// serveUnix serves a handler on a socket only this account can reach.
func (p *programRun) serveUnix(path string, h http.Handler) error {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	p.servers = append(p.servers, srv)
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// startProgram opens the box and starts the program in it. The run then
// decides through the returned bridge.
func startProgram(ctx context.Context, root string, m agent.Manifest, sess *agent.Session,
	caller *Caller, goal, runID string, catalog []mcp.Operation) (*programRun, error) {

	backend := testBackend
	if backend == nil {
		var err error
		if backend, err = programBackend(root, m.Program.Backend, m.Program.Image); err != nil {
			return nil, err
		}
	}
	if a := backend.Check(); !a.OK {
		return nil, fmt.Errorf("%s's program cannot run on %s here: %s", m.Name, backend.Name(), a.Why)
	}
	if err := clearOfStore(root, m.Program); err != nil {
		return nil, err
	}
	secret, err := randomSecret()
	if err != nil {
		return nil, err
	}
	p := &programRun{bridge: agentbox.NewBridge(), done: make(chan struct{}), backend: backend.Name(),
		stdout: &capped{max: 64 << 10}, stderr: &capped{max: 16 << 10}}
	fail := func(err error) (*programRun, error) { p.close(); return nil, err }

	// The sockets in a directory of their own: a socket's path is limited
	// to about a hundred bytes, which a store's own path can use up.
	sockDir, err := os.MkdirTemp("", "qzrun-")
	if err != nil {
		return nil, err
	}
	p.dirs = append(p.dirs, sockDir)
	work, err := os.MkdirTemp("", "qzwork-")
	if err != nil {
		return fail(err)
	}
	p.dirs = append(p.dirs, work)
	if err := os.Mkdir(filepath.Join(work, "tmp"), 0o700); err != nil {
		return fail(err)
	}

	sess.DecidedBy(m.Program.Command[0])
	version := "quilzo"
	runServer := agentbox.RunServer(p.bridge, m, catalog, version)
	endpoint := &mcp.Endpoint{
		Authenticate: func(_ *http.Request, token string) (*mcp.Caller, error) {
			if subtle.ConstantTimeCompare([]byte(token), []byte(secret)) != 1 {
				return nil, errors.New("not this run's credential")
			}
			return &mcp.Caller{Principal: agent.Principal(m.Name)}, nil
		},
		Build: func(*http.Request, *mcp.Caller) (*mcp.Server, error) { return runServer, nil },
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", endpoint)
	if err := p.serveUnix(filepath.Join(sockDir, "mcp.sock"), mux); err != nil {
		return fail(err)
	}

	// The model, through the gateway, charged to the agent and to whoever
	// started the run; and bounded by the run's own caps, which a model's
	// decisions meet at each step and a program's calls meet here.
	var payers []string
	if caller != nil && caller.Verified && !strings.HasPrefix(caller.Name, agent.PrincipalPrefix) {
		payers = append(payers, "person:"+caller.Name)
	}
	model, why := agentRunModel(root, m.Name, payers...)
	models := &agentbox.Models{Secret: secret, Complete: func(ctx context.Context, system, user string) (string, int, int, error) {
		if model == nil {
			return "", 0, 0, errors.New("no model is configured for this run: " + why)
		}
		if err := runModelGate(m, sess); err != nil {
			return "", 0, 0, err
		}
		type costed interface {
			CompleteCosted(ctx context.Context, system, user string) (string, assist.Usage, int64, error)
		}
		switch mm := model.(type) {
		case costed:
			out, u, cost, err := mm.CompleteCosted(ctx, system, user)
			sess.Tokens(u.In + u.Out)
			sess.Charge(cost)
			return out, u.In, u.Out, err
		case assist.Metered:
			out, u, err := mm.CompleteMetered(ctx, system, user)
			sess.Tokens(u.In + u.Out)
			return out, u.In, u.Out, err
		}
		out, err := model.Complete(ctx, system, user)
		return out, 0, 0, err
	}, Chat: func(ctx context.Context, req assist.ChatRequest) (assist.ChatReply, error) {
		if model == nil {
			return assist.ChatReply{}, errors.New("no model is configured for this run: " + why)
		}
		if err := runModelGate(m, sess); err != nil {
			return assist.ChatReply{}, err
		}
		type costed interface {
			ChatCosted(ctx context.Context, req assist.ChatRequest) (assist.ChatReply, int64, error)
		}
		switch mm := model.(type) {
		case costed:
			r, cost, err := mm.ChatCosted(ctx, req)
			sess.Tokens(r.Usage.In + r.Usage.Out)
			sess.Charge(cost)
			return r, err
		case assist.Chatter:
			r, err := mm.Chat(ctx, req)
			sess.Tokens(r.Usage.In + r.Usage.Out)
			return r, err
		}
		return assist.ChatReply{}, fmt.Errorf("%s takes a prompt, not a conversation with pictures or tools", model.Name())
	}}
	if err := p.serveUnix(filepath.Join(sockDir, "model.sock"), models); err != nil {
		return fail(err)
	}

	// The way out: the run's own gate decides each host, and each
	// connection is in the log, against the run.
	actor := programModel{name: filepath.Base(m.Program.Command[0])}
	proxy := &agentbox.Proxy{Secret: secret,
		Allow: func(host string, _ int) error {
			// The exfiltration breaker first: a program cannot be held for
			// a person, so a connection that would complete the three is
			// refused, with the reason.
			if why, breaks := sess.BreaksTo(host); breaks {
				return errors.New(why)
			}
			return sess.MayReach(host)
		},
		Record: func(e agentbox.Egress) {
			outcome := audit.Success
			if !e.Allowed {
				outcome = audit.Denied
			}
			d := map[string]string{"run": runID, "agent": m.Name, "host": e.Host, "port": strconv.Itoa(e.Port),
				"method": e.Method, "up": strconv.FormatInt(e.Up, 10), "down": strconv.FormatInt(e.Down, 10)}
			if e.Why != "" {
				d["why"] = clip(e.Why, 300)
			}
			record(root, actorRecord(caller, "agent.egress", outcome, m, actor, d))
		}}
	if err := p.serveUnix(filepath.Join(sockDir, "proxy.sock"), proxy); err != nil {
		return fail(err)
	}

	proxyURL := "http://run:" + secret + "@127.0.0.1:" + strconv.Itoa(int(agentbox.PortProxy))
	env := []string{
		"HOME=" + work, "TMPDIR=" + filepath.Join(work, "tmp"), "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8",
		"QUILZO_RUN=" + runID, "QUILZO_AGENT=" + m.Name, "QUILZO_GOAL=" + goal, "QUILZO_RUN_TOKEN=" + secret,
		"QUILZO_MCP_URL=http://127.0.0.1:" + strconv.Itoa(int(agentbox.PortMCP)) + "/mcp",
		"OPENAI_BASE_URL=http://127.0.0.1:" + strconv.Itoa(int(agentbox.PortModel)) + "/v1", "OPENAI_API_KEY=" + secret,
		"HTTP_PROXY=" + proxyURL, "HTTPS_PROXY=" + proxyURL, "http_proxy=" + proxyURL, "https_proxy=" + proxyURL,
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost",
	}
	for k, v := range m.Program.Env {
		env = append(env, k+"="+v)
	}
	// Memory is bounded by what the program writes (RLIMIT_DATA), not by the
	// address space it reserves: a JavaScript engine, in Node or in a
	// browser, reserves tens of gigabytes it never touches, and an
	// address-space limit killed it before it started.
	limits := sandbox.Limits{CPUSeconds: 600, DataBytes: 2 << 30, FileBytes: 256 << 20, OpenFiles: 1024, Processes: 4096}
	if m.Program.MemoryMB > 0 {
		limits.DataBytes = uint64(m.Program.MemoryMB) << 20
	}
	if m.Program.CPUSeconds > 0 {
		limits.CPUSeconds = uint64(m.Program.CPUSeconds)
	}
	spec := agentbox.Spec{Run: runID, Agent: m.Name, Program: m.Program.Command[0], Args: m.Program.Command[1:],
		Env: env, Workdir: work, Read: m.Program.Read, Limits: limits, Wall: time.Duration(m.Budget.Duration),
		Stdin: strings.NewReader(goal), Stdout: p.stdout, Stderr: p.stderr,
		Services: []agentbox.Service{
			{Name: "mcp", Socket: filepath.Join(sockDir, "mcp.sock"), Port: agentbox.PortMCP},
			{Name: "model", Socket: filepath.Join(sockDir, "model.sock"), Port: agentbox.PortModel},
			{Name: "proxy", Socket: filepath.Join(sockDir, "proxy.sock"), Port: agentbox.PortProxy},
		}}
	bctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	go func() {
		defer close(p.done)
		p.result, p.err = backend.Run(bctx, spec)
		said := lastWords(p.stdout.String())
		if p.err != nil {
			said = "the program could not run: " + p.err.Error()
		} else if p.result.Exit != 0 && said == "" {
			said = fmt.Sprintf("the program ended with exit status %d", p.result.Exit)
		}
		p.bridge.Finish(said)
	}()
	return p, nil
}

// lastWords is what a program said last: the end of what it printed,
// as its answer.
func lastWords(out string) string {
	out = strings.TrimSpace(out)
	if len(out) > 2000 {
		out = out[len(out)-2000:]
		if i := strings.IndexByte(out, '\n'); i >= 0 {
			out = out[i+1:]
		}
	}
	return out
}

// end stops what is left of the program once its run has ended, and
// records how it went.
func (p *programRun) end(root string, m agent.Manifest, caller *Caller, runID, why string) {
	p.bridge.Stop(why)
	p.cancel()
	<-p.done
	p.close()
	c := p.result.Confined
	d := map[string]string{"run": runID, "agent": m.Name, "backend": p.backend,
		"exit": strconv.Itoa(p.result.Exit), "took": p.result.Took.Round(time.Millisecond).String(),
		"namespaces": strconv.FormatBool(c.Namespaces), "landlock": strconv.Itoa(c.Landlock),
		"seccomp": strconv.FormatBool(c.Seccomp), "capabilities_dropped": strconv.FormatBool(c.Capabilities)}
	outcome := audit.Success
	if p.result.Stopped != "" {
		d["stopped"] = p.result.Stopped
	}
	if p.err != nil {
		d["error"], outcome = clip(p.err.Error(), 300), audit.Failure
	}
	record(root, actorRecord(caller, "agent.program", outcome, m,
		programModel{name: filepath.Base(m.Program.Command[0])}, d))
}

func (p *programRun) close() {
	for _, s := range p.servers {
		_ = s.Close()
	}
	for _, d := range p.dirs {
		_ = os.RemoveAll(d)
	}
}

// cmdAgentbox and cmdAgentboxShim are the box's first process and the
// shim, dispatched by name; nobody types them.
func cmdAgentbox() { agentbox.InitMain() }

func cmdAgentboxShim(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo %s SPEC", agentboxShim)
	}
	agentbox.ShimMain(args[0])
	return errors.New("the box was not closed, so the program did not run")
}

// agentBackends is `quilzo agent backends`: where a program can run here,
// and what its box would enforce.
func agentBackends(root string) error {
	type row struct {
		Backend   string               `json:"backend"`
		Available bool                 `json:"available"`
		Why       string               `json:"why,omitempty"`
		Enforces  agentbox.Confinement `json:"enforces"`
	}
	var rows []row
	for _, name := range []string{"native", "openshell"} {
		b, err := programBackend(root, name, "")
		if err != nil {
			rows = append(rows, row{Backend: name, Why: err.Error()})
			continue
		}
		a := b.Check()
		rows = append(rows, row{Backend: name, Available: a.OK, Why: a.Why, Enforces: a.Will})
	}
	if w.JSON(rows) {
		return nil
	}
	for _, r := range rows {
		state, colour := "available", green
		if !r.Available {
			state, colour = "unavailable", yellow
		}
		w.Human("%s%-10s%s %s%s%s\n", bold, r.Backend, reset, colour, state, reset)
		if r.Available {
			e := r.Enforces
			w.Human("  %snamespaces %v, Landlock %d (files %v, ports %v), system call filter %v, no capabilities %v%s\n",
				dim, e.Namespaces, e.Landlock, e.Files, e.Ports, e.Seccomp, e.Capabilities, reset)
		}
		if r.Why != "" {
			w.Human("  %s%s%s\n", dim, r.Why, reset)
		}
	}
	return nil
}

// clearOfStore refuses a program that would be given the store: the store
// holds the tokens, the policy and the keys, and a program reaches its
// content only through its run's interface.
func clearOfStore(root string, p *agent.Program) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	for _, path := range append([]string{p.Command[0]}, p.Read...) {
		real := path
		if r, err := filepath.EvalSymlinks(path); err == nil {
			real = r
		}
		if within(abs, real) || within(real, abs) {
			return fmt.Errorf("%s would give the program the store (%s), which holds its tokens and keys; "+
				"a program reaches the store's content only through its run", path, abs)
		}
	}
	return nil
}

// within reports whether path is dir or below it.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// agentProgramCmd is `quilzo agent program NAME [flags] -- COMMAND [ARG...]`
// and `quilzo agent program NAME --remove`: what an agent's program is.
// Deciding what runs, with the run's reach, is an administrator's.
func agentProgramCmd(root string, args []string) error {
	usage := errors.New("quilzo agent program NAME [--backend native|openshell] [--image IMG] [--read DIR]... " +
		"[--env K=V]... [--memory-mb N] -- COMMAND [ARG...]  |  quilzo agent program NAME --remove")
	if len(args) < 2 {
		return usage
	}
	name, rest := args[0], args[1:]
	var command []string
	for i, a := range rest {
		if a == "--" {
			command, rest = rest[i+1:], rest[:i]
			break
		}
	}
	fs := flag.NewFlagSet("agent program", flag.ContinueOnError)
	backend := fs.String("backend", "", "native (the default) or openshell")
	image := fs.String("image", "", "what an OpenShell sandbox is made from")
	memory := fs.Int("memory-mb", 0, "the most memory it may use")
	remove := fs.Bool("remove", false, "the agent has no program any more")
	var reads, envs multiFlag
	fs.Var(&reads, "read", "a further path it may read (repeat)")
	fs.Var(&envs, "env", "a setting K=V, never a secret (repeat)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return fmt.Errorf("what an agent's program is, is an administrator's decision: %w", err)
	}
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	m, ok := set.Agents[name]
	if !ok {
		return fmt.Errorf("no agent called %s is declared", name)
	}
	detail := map[string]string{"agent": name}
	if *remove {
		m.Program = nil
		detail["removed"] = "true"
	} else {
		if len(command) == 0 {
			return usage
		}
		p := &agent.Program{Command: command, Backend: *backend, Image: *image, Read: reads, MemoryMB: *memory}
		for _, kv := range envs {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return fmt.Errorf("%q is not K=V", kv)
			}
			if p.Env == nil {
				p.Env = map[string]string{}
			}
			p.Env[k] = v
		}
		if err := clearOfStore(root, p); err != nil {
			return err
		}
		m.Program = p
		detail["program"] = clip(strings.Join(command, " "), 300)
		detail["backend"] = p.Backend
	}
	if err := m.Validate(knownCapabilities(root)); err != nil {
		return err
	}
	set.Agents[name] = m
	if err := saveJSON(agentsPath(root), set); err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord("agent.program-set", "/", audit.Success, detail)); err != nil {
		return err
	}
	if *remove {
		fmt.Printf("%s has no program; it runs by walking its manifest, or with --model\n", name)
		return nil
	}
	fmt.Printf("%s runs %s in a box; quilzo agent run %s --program \"what it should do\"\n", name, command[0], name)
	return nil
}

// sameProgram reports whether two declarations run the same thing.
func sameProgram(a, b *agent.Program) bool {
	if a == nil || b == nil {
		return a == b
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// runModelGate is the run's own caps, which a model's decisions meet at
// each step and a program's model calls meet here.
func runModelGate(m agent.Manifest, sess *agent.Session) error {
	if b := m.Budget.Tokens; b > 0 && sess.TokensUsed() >= b {
		return fmt.Errorf("the run has used %d tokens and its budget is %d", sess.TokensUsed(), b)
	}
	if b, _ := m.Budget.MoneyMicros(); b > 0 && sess.Cost() >= b {
		return fmt.Errorf("the run has spent its money budget of %s", m.Budget.Money)
	}
	return nil
}
