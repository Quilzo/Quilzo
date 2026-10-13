// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/shell"
	"github.com/quilzo/quilzo/internal/vault"
)

// A run's workspace and commands, for an agent that holds the workspace's
// capabilities.
//
// The workspace is the agent's folder, kept between runs, and one run
// works on it at a time. Each command runs in a box of its own against it
// (internal/shell), writing only the workspace and a scratch home kept
// beside it for caches, and reaching the network only when it is a command
// that does and the declaration names hosts: then through a proxy this
// process serves, which lets those hosts through on 443 and nothing else.
// What each command printed is kept with the run, sealed when the store
// has a keyring, and its digest goes into the step's record.

// holdsShell reports whether a manifest holds any workspace capability.
func holdsShell(m agent.Manifest) bool {
	for _, c := range m.Capabilities {
		if agent.IsShell(c) {
			return true
		}
	}
	return false
}

// holdsLive reports whether a run of the agent asks people in its own
// process: its browser's page or its workspace's commands live there.
func holdsLive(m agent.Manifest) bool {
	return holdsBrowser(m) || holdsShell(m) || holdsCell(m)
}

func workspacesDir(root string) string { return filepath.Join(root, "workspaces") }

// reWorkspaceAgent is what an agent's name must be to name folders here:
// it becomes a path, so never "..", a dot name or a separator.
var reWorkspaceAgent = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// workspaceDir is where an agent's workspace is: the folder it declares,
// or its own beside the store's other folders.
func workspaceDir(root string, m agent.Manifest) (string, error) {
	if !reWorkspaceAgent.MatchString(m.Name) {
		return "", fmt.Errorf("%q is not a name a workspace can be kept under: lower case letters, digits and hyphens", m.Name)
	}
	store, err := realPath(root)
	if err != nil {
		return "", err
	}
	own := filepath.Join(store, "workspaces", m.Name)
	if m.Shell == nil || m.Shell.Workspace == "" {
		return own, nil
	}
	ws := filepath.Clean(m.Shell.Workspace)
	// Reached as written, or not at all: a link anywhere on the way could
	// point at the store, another agent's workspace, or a home folder.
	real, err := realPath(ws)
	if err != nil {
		return "", err
	}
	if real != ws {
		return "", fmt.Errorf("%s's workspace %s is reached through a link (it is %s); name the folder itself", m.Name, ws, real)
	}
	sep := string(filepath.Separator)
	switch {
	case ws == store || strings.HasPrefix(store+sep, ws+sep):
		// The store holds keys and tokens.
		return "", fmt.Errorf("%s's workspace %s holds the store; name a folder of its own", m.Name, ws)
	case strings.HasPrefix(ws, store+sep) && ws != own:
		return "", fmt.Errorf("%s's workspace %s is inside the store; inside it, an agent's workspace is %s", m.Name, ws, own)
	}
	return ws, nil
}

// realPath is a path with every link in it followed, as far as it exists;
// what does not exist yet is joined on as written.
func realPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	rest := ""
	for cur := abs; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// claimPath is where the claim on a workspace is kept, by the workspace's
// own path, so two agents naming one folder take turns.
func claimPath(root, ws string) string {
	sum := sha256.Sum256([]byte(ws))
	return filepath.Join(workspacesDir(root), ".claims", hex.EncodeToString(sum[:8])+".claim")
}

// runShell is one run's workspace and what it keeps.
type runShell struct {
	driver  *shell.Driver
	outputs *runOutputs
	close   []func()
}

// newRunShell opens a run's workspace, claims it, and readies its box.
func newRunShell(root string, m agent.Manifest, sess *agent.Session, caller *Caller, actor assist.Model,
	runID string) (*runShell, error) {

	ws, err := workspaceDir(root, m)
	if err != nil {
		return nil, err
	}
	rs := &runShell{}
	fail := func(err error) (*runShell, error) { rs.end(); return nil, err }
	claimant := runID
	if claimant == "" {
		claimant = fmt.Sprintf("pid-%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	claim, err := shell.ClaimWorkspace(claimPath(root, ws), claimant)
	if err != nil {
		return nil, err
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				claim.Renew()
			}
		}
	}()
	rs.close = append(rs.close, func() { close(stop); claim.Release() })
	w, err := shell.OpenWorkspace(ws)
	if err != nil {
		return fail(err)
	}
	rs.close = append(rs.close, func() { _ = w.Close() })
	// Still the folder that was checked, now it is open.
	if real, err := realPath(ws); err != nil || real != ws {
		return fail(fmt.Errorf("%s's workspace %s changed as it was opened; nothing was run", m.Name, ws))
	}
	store, err := realPath(root)
	if err != nil {
		return fail(err)
	}
	// A home made fresh for this run, gone when it ends, so nothing a
	// command plants there (a configuration, a startup file) reaches the
	// next run; the agent's caches are kept beside it.
	home := filepath.Join(store, "workspaces", ".home", m.Name, claimant)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return fail(err)
	}
	rs.close = append(rs.close, func() { _ = removeAllForce(home) })
	cache := filepath.Join(store, "workspaces", ".cache", m.Name)
	// What an earlier run left in the workspace after reading what is not
	// published is still private to this one (the breaker).
	if from, ok := privateMarker(root, ws); ok {
		sess.HoldsPrivate("what " + from + " left in the workspace after reading what is not published")
	}
	backend := testBackend
	if backend == nil {
		if backend, err = programBackend(root, "native", ""); err != nil {
			return fail(err)
		}
	}
	box := shell.Box{Backend: backend, RunID: runID, Agent: m.Name, Workspace: ws, Home: home, Cache: cache}
	decl := m.Shell
	if decl != nil && len(decl.Hosts) > 0 && !decl.ReadOnly {
		secret, err := randomSecret()
		if err != nil {
			return fail(err)
		}
		host := &programRun{}
		rs.close = append(rs.close, host.close)
		sockDir, err := os.MkdirTemp("", "qzsh-")
		if err != nil {
			return fail(err)
		}
		host.dirs = append(host.dirs, sockDir)
		proxy := &agentbox.Proxy{Secret: secret,
			Allow: func(h string, port int) error {
				if port != 443 {
					return fmt.Errorf("port %d: a command reaches its hosts on 443 only", port)
				}
				if !decl.Reaches(h) {
					return fmt.Errorf("%s is not a host this agent's commands may reach", h)
				}
				return nil
			},
			Record: func(e agentbox.Egress) {
				outcome := audit.Success
				if !e.Allowed {
					outcome = audit.Denied
				}
				detail := map[string]string{"run": runID, "agent": m.Name, "host": e.Host, "port": strconv.Itoa(e.Port),
					"method": e.Method, "up": strconv.FormatInt(e.Up, 10), "down": strconv.FormatInt(e.Down, 10), "via": "shell"}
				if e.Why != "" {
					detail["why"] = clip(e.Why, 300)
				}
				record(root, actorRecord(caller, "agent.egress", outcome, m, actor, detail))
			}}
		sock := filepath.Join(sockDir, "proxy.sock")
		if err := host.serveUnix(sock, proxy); err != nil {
			return fail(err)
		}
		box.Proxy = &agentbox.Service{Name: "proxy", Socket: sock, Port: agentbox.PortProxy}
		box.ProxyURL = "http://run:" + secret + "@127.0.0.1:" + strconv.Itoa(int(agentbox.PortProxy))
	}
	rs.driver = &shell.Driver{Session: sess, Workspace: w, Box: box,
		Beat: func() { touchRun(root, runID) },
		Wrote: func([]string) {
			who := runID
			if who == "" {
				who = "a run"
			} else {
				who = "run " + who
			}
			markPrivate(root, ws, who)
		}}
	if runID != "" {
		kr, err := loadKeyring(root)
		if err != nil {
			return fail(err)
		}
		kept, err := loadRunOutputs(root, runID)
		if err != nil {
			return fail(err)
		}
		rs.outputs = &runOutputs{root: root, id: runID, kr: kr, index: kept}
		rs.driver.Keep = rs.outputs.keep
	}
	return rs, nil
}

// end lets the workspace go and closes what was opened for it.
func (rs *runShell) end() {
	for i := len(rs.close) - 1; i >= 0; i-- {
		rs.close[i]()
	}
	rs.close = nil
}

// MaxRunOutputs bounds the commands' outputs one run keeps.
const MaxRunOutputs = 500

// runOutputs keeps what a run's commands printed beside its record.
type runOutputs struct {
	root, id string
	kr       *vault.Keyring

	mu    sync.Mutex
	index []runOutput
}

// runOutput is one kept output.
type runOutput struct {
	N       int           `json:"n"`
	Command string        `json:"command"`
	Kind    string        `json:"kind"`
	Exit    int           `json:"exit"`
	Took    string        `json:"took"`
	Total   int64         `json:"total"`
	Digest  string        `json:"digest"`
	Changes shell.Changes `json:"changes,omitzero"`
	When    time.Time     `json:"when"`
	File    string        `json:"file,omitempty"`
	Sealed  bool          `json:"sealed,omitempty"`
}

func runOutputsDir(root, id string) string { return filepath.Join(agentRunsDir(root), id+".shell") }

func outputAAD(id string, n int) []byte { return []byte("run-output/" + id + "/" + strconv.Itoa(n)) }

// keep writes one command's output, sealed when the store has a keyring.
// One that cannot be kept is not a reason to stop the run.
func (o *runOutputs) keep(k shell.Kept) {
	o.mu.Lock()
	defer o.mu.Unlock()
	dir := runOutputsDir(o.root, o.id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	n := len(o.index) + 1
	e := runOutput{N: n, Command: shell.Line(k.Program, k.Args), Kind: k.Kind, Exit: k.Exit,
		Took: k.Took.Round(time.Millisecond).String(), Total: k.Total, Digest: k.Digest, Changes: capChanges(k.Changes), When: time.Now().UTC()}
	// Past the bound, a command is still recorded (what ran, how it ended,
	// the digest of what it printed); only its output is not kept.
	if len(k.Output) > 0 && len(o.index) < MaxRunOutputs {
		data, name := k.Output, fmt.Sprintf("%04d.out", n)
		if o.kr != nil {
			s, err := o.kr.Seal(data, outputAAD(o.id, n))
			if err == nil {
				if data, err = vault.Marshal(s); err == nil {
					name, e.Sealed = name+".sealed", true
				}
			}
			if !e.Sealed {
				data = nil
			}
		}
		if data != nil && atomicfile.Write(filepath.Join(dir, name), data, 0o600) == nil {
			e.File = name
		}
	}
	o.index = append(o.index, e)
	if b, err := json.MarshalIndent(o.index, "", "  "); err == nil {
		_ = atomicfile.Write(filepath.Join(dir, "outputs.json"), b, 0o600)
	}
}

// loadRunOutputs is what a run's commands printed, in order.
func loadRunOutputs(root, id string) ([]runOutput, error) {
	if !agent.ValidRecordID(id) {
		return nil, fmt.Errorf("%q is not a run", id)
	}
	b, err := os.ReadFile(filepath.Join(runOutputsDir(root, id), "outputs.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []runOutput
	return out, json.Unmarshal(b, &out)
}

// runOutputText is one kept output, opened when it was sealed.
func runOutputText(root, id string, n int) ([]byte, error) {
	outs, err := loadRunOutputs(root, id)
	if err != nil {
		return nil, err
	}
	for _, o := range outs {
		if o.N != n || o.File == "" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(runOutputsDir(root, id), filepath.Base(o.File)))
		if err != nil || !o.Sealed {
			return b, err
		}
		kr, err := frameKeyring(root)
		if err != nil {
			return nil, err
		}
		if kr == nil {
			return nil, errors.New("this output is sealed and the store has no keyring")
		}
		s, err := vault.Unmarshal(b)
		if err != nil {
			return nil, err
		}
		return kr.Open(s, outputAAD(id, n))
	}
	return nil, fmt.Errorf("%s kept no output %d", id, n)
}

// agentWorkspace is quilzo agent workspace NAME [--clear].
func agentWorkspace(root string, args []string) error {
	fs := flag.NewFlagSet("agent workspace", flag.ContinueOnError)
	clear := fs.Bool("clear", false, "empty it: everything in it is removed")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo agent workspace NAME [--clear]")
	}
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	m, ok := set.Agents[pos[0]]
	if !ok {
		return fmt.Errorf("no agent called %q; `quilzo agent list`", pos[0])
	}
	if !holdsShell(m) {
		return fmt.Errorf("%s holds none of the workspace's capabilities, so it has no workspace", m.Name)
	}
	ws, err := workspaceDir(root, m)
	if err != nil {
		return err
	}
	if *clear {
		claim, err := shell.ClaimWorkspace(claimPath(root, ws), fmt.Sprintf("clear-%d", os.Getpid()))
		if err != nil {
			return err
		}
		defer claim.Release()
		ents, _ := os.ReadDir(ws)
		for _, e := range ents {
			if err := removeAllForce(filepath.Join(ws, e.Name())); err != nil {
				return err
			}
		}
		// And what its runs kept beside it: homes, caches, and the note that
		// something private was left there.
		store, err := realPath(root)
		if err != nil {
			return err
		}
		for _, d := range []string{filepath.Join(store, "workspaces", ".home", m.Name), filepath.Join(store, "workspaces", ".cache", m.Name)} {
			if err := removeAllForce(d); err != nil {
				return err
			}
		}
		_ = os.Remove(privatePath(root, ws))
		caller := resolveCaller(root, "")
		if err := recordE(root, caller.auditRecord("agent.workspace.cleared", "/agents", audit.Success,
			map[string]string{"agent": m.Name, "removed": strconv.Itoa(len(ents))})); err != nil {
			return err
		}
		fmt.Printf("%s%s's workspace is empty%s (%d removed)\n", green, m.Name, reset, len(ents))
		return nil
	}
	size, files := int64(0), 0
	if w, err := shell.OpenWorkspace(ws); err == nil {
		ix := w.Scan()
		size, files = ix.Size, len(ix.Files)
		w.Close()
	}
	quota := 2048
	if m.Shell != nil {
		quota = m.Shell.Quota()
	}
	if w.JSON(map[string]any{"agent": m.Name, "workspace": ws, "bytes": size, "files": files, "quota_mb": quota}) {
		return nil
	}
	fmt.Printf("%s\n  %d files, %.1f MiB of %d MiB\n", ws, files, float64(size)/(1<<20), quota)
	return nil
}

// stepEvidence is what a step saw or printed, by digest, for its record: the
// picture kept after a browser step and the one a person was asked about,
// or the output of a command.
func stepEvidence(root, runID string, st agent.Step) map[string]string {
	if runID == "" || st.At.IsZero() {
		return nil
	}
	d := map[string]string{}
	switch {
	case agent.IsBrowser(st.Action.Op):
		frames, _ := loadRunFrames(root, runID)
		for _, f := range frames {
			if f.When.Before(st.At) || f.Digest == "" {
				continue
			}
			if f.Asking != "" {
				d["asked_frame_sha256"] = f.Digest
			} else {
				d["frame_sha256"] = f.Digest
			}
		}
	case st.Action.Op == "shell_run":
		outs, _ := loadRunOutputs(root, runID)
		for _, o := range outs {
			if !o.When.Before(st.At) {
				d["output_sha256"], d["exit"], d["output_bytes"] = o.Digest, strconv.Itoa(o.Exit), strconv.FormatInt(o.Total, 10)
			}
		}
	}
	return d
}

// capChanges is what a step changed as the record keeps it: the first names
// of each kind, and how many more.
func capChanges(c shell.Changes) shell.Changes {
	const keep = 100
	cut := func(names []string) []string {
		if len(names) <= keep {
			return names
		}
		return append(append([]string(nil), names[:keep]...), fmt.Sprintf("… and %d more", len(names)-keep))
	}
	return shell.Changes{Added: cut(c.Added), Changed: cut(c.Changed), Removed: cut(c.Removed)}
}

// privatePath is where the note is kept that a workspace was written while
// a run held something private.
func privatePath(root, ws string) string {
	sum := sha256.Sum256([]byte(ws))
	return filepath.Join(workspacesDir(root), ".private", hex.EncodeToString(sum[:8]))
}

func markPrivate(root, ws, who string) {
	p := privatePath(root, ws)
	if os.MkdirAll(filepath.Dir(p), 0o700) == nil {
		_ = atomicfile.Write(p, []byte(who+"\n"), 0o600)
	}
}

// privateMarker says which run left something private in the workspace.
func privateMarker(root, ws string) (string, bool) {
	b, err := os.ReadFile(privatePath(root, ws))
	if err != nil {
		return "", false
	}
	who := strings.TrimSpace(string(b))
	if who == "" {
		who = "an earlier run"
	}
	return who, true
}

// removeAllForce removes a folder a command may have made hard to remove
// (a folder with no permissions), never following a link out of it.
func removeAllForce(dir string) error {
	var open func(p string)
	open = func(p string) {
		fi, err := os.Lstat(p)
		if err != nil || !fi.IsDir() {
			return
		}
		_ = os.Chmod(p, 0o700)
		ents, _ := os.ReadDir(p)
		for _, e := range ents {
			if e.IsDir() && e.Type()&os.ModeSymlink == 0 {
				open(filepath.Join(p, e.Name()))
			}
		}
	}
	open(dir)
	return os.RemoveAll(dir)
}
