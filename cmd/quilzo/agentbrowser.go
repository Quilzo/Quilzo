// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/browser"
	"github.com/quilzo/quilzo/internal/cdp"
	"github.com/quilzo/quilzo/internal/vault"
)

// A run's browser, for an agent that holds the browser's capabilities.
//
// Chromium runs in a box of its own, made for this run when the agent
// first opens a page: the agent box's namespaces, Landlock and system call
// filter, and a network whose only way out is a proxy this process serves,
// which lets through only the hosts the declaration names, on 443. Inside
// that, every request a page makes is decided by the rule (read hosts are
// only read from), and every target a page starts is watched before it
// runs (internal/browser). The driver is here, outside the box, over a
// pipe only this process holds.
//
// What the agent did is kept with the run as pictures: one after each
// action, and one of what a person is asked about, with the element
// outlined. Sealed when the store has a keyring, since a page an agent was
// signed in to is somebody's own.

// browserTestLaunch stands in for the boxed browser in tests.
var browserTestLaunch func(ctx context.Context) (*cdp.Browser, error)

// holdsBrowser reports whether a manifest holds any browser capability.
func holdsBrowser(m agent.Manifest) bool {
	for _, c := range m.Capabilities {
		if agent.IsBrowser(c) {
			return true
		}
	}
	return false
}

// runBrowser is one run's browser and what it keeps.
type runBrowser struct {
	driver *browser.Driver
	frames *runFrames

	mu    sync.Mutex
	pics  [][]byte
	close []func()
	// slot is this run's place among the browsers the machine allows,
	// taken when its browser first starts and given back if it does not.
	slot func()
	// refused counts the requests refused per host, so a page that asks
	// for thousands leaves a count in the log rather than thousands.
	refused map[string]int
}

// MaxRefusedRecords is how many refused requests to one host are written
// to the log one by one; the rest are counted, and the count written when
// the browser closes.
const MaxRefusedRecords = 20

// newRunBrowser makes a run's browser, which starts when the agent first
// opens a page. actor is what decides the run, for the record each request
// leaves; chat says it takes pictures.
func newRunBrowser(root string, m agent.Manifest, sess *agent.Session, caller *Caller, actor assist.Model,
	runID string, chat bool) (*runBrowser, error) {
	rb := &runBrowser{refused: map[string]int{}}
	if runID != "" {
		kr, err := loadKeyring(root)
		if err != nil {
			return nil, err
		}
		// A run continued keeps the pictures it took before, and goes on
		// numbering after them.
		kept, err := loadRunFrames(root, runID)
		if err != nil {
			return nil, err
		}
		rb.frames = &runFrames{root: root, id: runID, kr: kr, index: kept}
	}
	d := &browser.Driver{Session: sess,
		Secret: func(name string) (string, error) { return readSecret(root, name) },
		Refused: func(r browser.Refusal) {
			host, method := "", r.Request.Method
			if r.Request.URL != nil {
				host = r.Request.URL.Hostname()
			}
			rb.mu.Lock()
			rb.refused[host]++
			n := rb.refused[host]
			rb.mu.Unlock()
			if n > MaxRefusedRecords {
				return
			}
			record(root, actorRecord(caller, "agent.egress", audit.Denied, m, actor,
				map[string]string{"run": runID, "agent": m.Name, "host": host, "method": method,
					"kind": r.Request.Kind, "why": clip(r.Why, 300), "via": "browser"}))
		},
	}
	if rb.frames != nil {
		d.Frames, d.Live = rb.frames.keep, rb.frames.now
	}
	if chat {
		d.Picture = func(png []byte) {
			rb.mu.Lock()
			rb.pics = append(rb.pics, png)
			rb.mu.Unlock()
		}
	}
	d.Launch = func(ctx context.Context) (*cdp.Browser, error) {
		rb.mu.Lock()
		held := rb.slot != nil
		rb.mu.Unlock()
		if !held {
			// While it waits, the run's record says it is still going, so
			// it is not taken for one that was cut off.
			release, err := takeBrowserSlot(ctx, root, runID, browserSessions(root), func() { touchRun(root, runID) })
			if err != nil {
				return nil, err
			}
			rb.mu.Lock()
			rb.slot = release
			rb.mu.Unlock()
		}
		var b *cdp.Browser
		var err error
		if browserTestLaunch != nil {
			b, err = browserTestLaunch(ctx)
		} else {
			b, err = rb.launch(ctx, root, m, caller, actor, runID, d)
		}
		if err != nil {
			// No browser, so no place held for one.
			rb.mu.Lock()
			release := rb.slot
			rb.slot = nil
			rb.mu.Unlock()
			release()
		}
		return b, err
	}
	rb.driver = d
	// How many more were refused than were written down, per host.
	rb.close = append(rb.close, func() {
		for host, n := range rb.refused {
			if n > MaxRefusedRecords {
				record(root, actorRecord(caller, "agent.egress", audit.Denied, m, actor,
					map[string]string{"run": runID, "agent": m.Name, "host": host, "via": "browser",
						"count": strconv.Itoa(n - MaxRefusedRecords), "why": "more requests to the same host, refused"}))
			}
		}
	})
	return rb, nil
}

// touchRun marks a kept run as still going, while it is inside a step and
// nothing else writes its record.
func touchRun(root, id string) {
	if id == "" {
		return
	}
	if rec, err := loadAgentRun(root, id); err == nil && rec.State == agent.Running {
		_ = writeAgentRun(root, rec)
	}
}

// pictures hands over the screenshots taken since the last decision.
func (rb *runBrowser) pictures() [][]byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	out := rb.pics
	rb.pics = nil
	return out
}

// end closes the browser and everything made for it.
func (rb *runBrowser) end() {
	rb.driver.Close()
	if rb.frames != nil {
		rb.frames.endLive()
	}
	rb.mu.Lock()
	closers, slot := rb.close, rb.slot
	rb.close, rb.slot = nil, nil
	rb.mu.Unlock()
	for i := len(closers) - 1; i >= 0; i-- {
		closers[i]()
	}
	if slot != nil {
		slot()
	}
}

// launch starts Chromium in the run's box, behind the run's proxy.
func (rb *runBrowser) launch(ctx context.Context, root string, m agent.Manifest, caller *Caller,
	actor assist.Model, runID string, d *browser.Driver) (*cdp.Browser, error) {

	path, _, err := browserPath(root)
	if err != nil {
		return nil, err
	}
	backend := testBackend
	if backend == nil {
		if backend, err = programBackend(root, "native", ""); err != nil {
			return nil, err
		}
	}
	secret, err := randomSecret()
	if err != nil {
		return nil, err
	}
	// The sockets and the box's own directory, like a program's, removed
	// when the run ends.
	host := &programRun{}
	launched := false
	defer func() {
		if launched {
			rb.mu.Lock()
			rb.close = append(rb.close, host.close)
			rb.mu.Unlock()
		} else {
			// Nothing started: nothing of it is kept.
			host.close()
		}
	}()
	sockDir, err := os.MkdirTemp("", "qzbrs-")
	if err != nil {
		return nil, err
	}
	host.dirs = append(host.dirs, sockDir)
	work, err := os.MkdirTemp("", "qzbrw-")
	if err != nil {
		return nil, err
	}
	host.dirs = append(host.dirs, work)
	if err := os.Mkdir(filepath.Join(work, "tmp"), 0o700); err != nil {
		return nil, err
	}

	decl := m.Browser
	proxy := &agentbox.Proxy{Secret: secret,
		Allow: func(h string, port int) error {
			if port != 443 {
				return fmt.Errorf("port %d: an agent's browser uses https, on 443, only", port)
			}
			if !decl.Reads(h) {
				return fmt.Errorf("%s is not a host this agent's browser may reach", h)
			}
			return nil
		},
		Record: func(e agentbox.Egress) {
			outcome := audit.Success
			if !e.Allowed {
				outcome = audit.Denied
			}
			detail := map[string]string{"run": runID, "agent": m.Name, "host": e.Host, "port": strconv.Itoa(e.Port),
				"method": e.Method, "up": strconv.FormatInt(e.Up, 10), "down": strconv.FormatInt(e.Down, 10), "via": "browser"}
			if e.Why != "" {
				detail["why"] = clip(e.Why, 300)
			}
			record(root, actorRecord(caller, "agent.egress", outcome, m, actor, detail))
		}}
	if err := host.serveUnix(filepath.Join(sockDir, "proxy.sock"), proxy); err != nil {
		return nil, err
	}
	d.ProxyUser, d.ProxyPass = "run", secret

	stderr := &capped{max: 16 << 10}
	bx := browser.Box{Backend: backend, Run: runID, Agent: m.Name, Workdir: work,
		Services: []agentbox.Service{{Name: "proxy", Socket: filepath.Join(sockDir, "proxy.sock"), Port: agentbox.PortProxy}},
		Wall:     time.Duration(m.Budget.Duration), MemoryMB: 2048}
	b, err := cdp.Launch(ctx, cdp.Options{Path: path, Profile: filepath.Join(work, "profile"), Boxed: true,
		Env:    []string{"HOME=" + work, "TMPDIR=" + filepath.Join(work, "tmp"), "LANG=C.UTF-8"},
		Args:   []string{"--proxy-server=http://127.0.0.1:" + strconv.Itoa(int(agentbox.PortProxy)), "--proxy-bypass-list=<-loopback>"},
		Stderr: stderr, Start: bx.Start(stderr)})
	if err != nil {
		if s := stderr.String(); s != "" {
			return nil, fmt.Errorf("%w (the browser said: %s)", err, clip(onOneLine(s), 300))
		}
		return nil, err
	}
	launched = true
	return b, nil
}

// browserSessions is how many browsers may run at once here.
func browserSessions(root string) int {
	n := 2
	if c, err := loadConfig(root); err == nil {
		if v := c.Int("browser.sessions"); v > 0 {
			n = v
		}
	}
	return n
}

// browserSlot is a browser running for a run, as the slots file has it.
type browserSlot struct {
	Run  string    `json:"run"`
	Beat time.Time `json:"beat"`
}

// browserSlotStale is how long a slot is held without its run beating
// before it is taken as left behind by a process that died.
const browserSlotStale = 2 * time.Minute

// takeBrowserSlot waits for one of the browsers this machine allows, for
// as long as ctx lets it, and keeps it until released.
func takeBrowserSlot(ctx context.Context, root, run string, max int, beat func()) (func(), error) {
	dir := browserDir(root)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "sessions.json")
	change := func(f func([]browserSlot) ([]browserSlot, bool)) (bool, error) {
		unlock, err := atomicfile.Lock(path + ".lock")
		if err != nil {
			return false, err
		}
		defer unlock()
		var slots, live []browserSlot
		if b, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(b, &slots)
		}
		for _, s := range slots {
			// Stale when nothing has beaten for a while, or when it claims
			// a time to come: a clock set back must not hold a slot for
			// as long as it was set back by.
			if age := time.Since(s.Beat); age < browserSlotStale && age > -time.Minute {
				live = append(live, s)
			}
		}
		out, ok := f(live)
		b, err := json.Marshal(out)
		if err != nil {
			return false, err
		}
		return ok, atomicfile.Write(path, b, 0o600)
	}
	key := run + "/" + strconv.FormatInt(time.Now().UnixNano(), 36)
	lastBeat := time.Now()
	for {
		ok, err := change(func(s []browserSlot) ([]browserSlot, bool) {
			if len(s) >= max {
				return s, false
			}
			return append(s, browserSlot{Run: key, Beat: time.Now().UTC()}), true
		})
		if err != nil {
			return nil, err
		}
		if ok {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%d browsers are running here already (browser.sessions), "+
				"and none came free while this run waited", max)
		case <-time.After(500 * time.Millisecond):
		}
		if beat != nil && time.Since(lastBeat) > 30*time.Second {
			beat()
			lastBeat = time.Now()
		}
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(30 * time.Second):
				_, _ = change(func(s []browserSlot) ([]browserSlot, bool) {
					for i := range s {
						if s[i].Run == key {
							s[i].Beat = time.Now().UTC()
							return s, true
						}
					}
					// Dropped as stale (a clock that jumped, a process that
					// was suspended): still running, so still counted.
					return append(s, browserSlot{Run: key, Beat: time.Now().UTC()}), true
				})
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(stop)
			wg.Wait()
			_, _ = change(func(s []browserSlot) ([]browserSlot, bool) {
				out := s[:0]
				for _, x := range s {
					if x.Run != key {
						out = append(out, x)
					}
				}
				return out, true
			})
		})
	}, nil
}

// MaxRunFrames bounds the pictures one run keeps.
const MaxRunFrames = 300

// runFrames keeps a run's pictures beside its record.
type runFrames struct {
	root, id string
	kr       *vault.Keyring

	mu    sync.Mutex
	index []runFrame
}

// runFrame is one kept picture.
type runFrame struct {
	N      int       `json:"n"`
	Op     string    `json:"op"`
	At     string    `json:"at,omitempty"`
	Asking string    `json:"asking,omitempty"`
	When   time.Time `json:"when"`
	File   string    `json:"file"`
	Sealed bool      `json:"sealed,omitempty"`
}

func runFramesDir(root, id string) string { return filepath.Join(agentRunsDir(root), id+".frames") }

func frameAAD(id string, n int) []byte { return []byte("run-frame/" + id + "/" + strconv.Itoa(n)) }

// keep writes one picture, sealed when the store has a keyring. A picture
// that cannot be kept is not a reason to stop the run.
func (f *runFrames) keep(fr browser.Frame) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// What a person is asked about is always kept; the pictures after
	// each action stop at the bound.
	if len(fr.JPEG) == 0 || (len(f.index) >= MaxRunFrames && fr.Asking == "") || len(f.index) >= 2*MaxRunFrames {
		return
	}
	dir := runFramesDir(f.root, f.id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	n := len(f.index) + 1
	e := runFrame{N: n, Op: fr.Op, At: clip(fr.At, 500), Asking: fr.Asking, When: time.Now().UTC(),
		File: fmt.Sprintf("%04d.jpg", n)}
	data := fr.JPEG
	if f.kr != nil {
		s, err := f.kr.Seal(data, frameAAD(f.id, n))
		if err != nil {
			return
		}
		if data, err = vault.Marshal(s); err != nil {
			return
		}
		e.File, e.Sealed = e.File+".sealed", true
	}
	if atomicfile.Write(filepath.Join(dir, e.File), data, 0o600) != nil {
		return
	}
	f.index = append(f.index, e)
	if b, err := json.MarshalIndent(f.index, "", "  "); err == nil {
		_ = atomicfile.Write(filepath.Join(dir, "frames.json"), b, 0o600)
	}
}

// now keeps what the page shows now, in place of the last one: for a
// person watching the run, not part of its record.
func (f *runFrames) now(jpg []byte) {
	dir := runFramesDir(f.root, f.id)
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	name := "live.jpg"
	if f.kr != nil {
		s, err := f.kr.Seal(jpg, frameAAD(f.id, 0))
		if err != nil {
			return
		}
		if jpg, err = vault.Marshal(s); err != nil {
			return
		}
		name += ".sealed"
	}
	_ = atomicfile.Write(filepath.Join(dir, name), jpg, 0o600)
}

// liveFrame is the picture of now a run keeps, and whether it is sealed.
func liveFrame(root, id string) (string, bool) {
	dir := runFramesDir(root, id)
	if _, err := os.Stat(filepath.Join(dir, "live.jpg.sealed")); err == nil {
		return filepath.Join(dir, "live.jpg.sealed"), true
	}
	if _, err := os.Stat(filepath.Join(dir, "live.jpg")); err == nil {
		return filepath.Join(dir, "live.jpg"), false
	}
	return "", false
}

// endLive removes the picture of now once the run is over.
func (f *runFrames) endLive() {
	dir := runFramesDir(f.root, f.id)
	_ = os.Remove(filepath.Join(dir, "live.jpg"))
	_ = os.Remove(filepath.Join(dir, "live.jpg.sealed"))
}

// loadRunFrames is the pictures a run kept, in order.
func loadRunFrames(root, id string) ([]runFrame, error) {
	if !agent.ValidRecordID(id) {
		return nil, fmt.Errorf("%q is not a run", id)
	}
	b, err := os.ReadFile(filepath.Join(runFramesDir(root, id), "frames.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []runFrame
	return out, json.Unmarshal(b, &out)
}

// runFramePicture is one kept picture's bytes, opened when it was sealed.
func runFramePicture(root, id string, n int) ([]byte, error) {
	frames, err := loadRunFrames(root, id)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		path, sealed := liveFrame(root, id)
		if path == "" {
			return nil, fmt.Errorf("%s has no picture of now", id)
		}
		frames = []runFrame{{N: 0, File: filepath.Base(path), Sealed: sealed}}
	}
	for _, f := range frames {
		if f.N != n {
			continue
		}
		b, err := os.ReadFile(filepath.Join(runFramesDir(root, id), filepath.Base(f.File)))
		if err != nil || !f.Sealed {
			return b, err
		}
		kr, err := frameKeyring(root)
		if err != nil {
			return nil, err
		}
		if kr == nil {
			return nil, errors.New("this picture is sealed and the store has no keyring")
		}
		s, err := vault.Unmarshal(b)
		if err != nil {
			return nil, err
		}
		return kr.Open(s, frameAAD(id, n))
	}
	return nil, fmt.Errorf("%s kept no picture %d", id, n)
}

// frameKeyring is the store's keyring, opened at most once a minute for the
// pictures a run's page shows: opening it can mean asking a key service,
// and a page showing a run asks for every picture each time it refreshes.
func frameKeyring(root string) (*vault.Keyring, error) {
	frameKeys.mu.Lock()
	defer frameKeys.mu.Unlock()
	if frameKeys.root == root && time.Since(frameKeys.at) < time.Minute {
		return frameKeys.kr, nil
	}
	kr, err := loadKeyring(root)
	if err != nil {
		return nil, err
	}
	frameKeys.root, frameKeys.kr, frameKeys.at = root, kr, time.Now()
	return kr, nil
}

var frameKeys struct {
	mu   sync.Mutex
	root string
	kr   *vault.Keyring
	at   time.Time
}
