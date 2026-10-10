// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package cdp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Options says how to start a browser.
type Options struct {
	// Path is the browser's executable, absolute.
	Path string
	// Profile is the user-data directory, a fresh one for each session.
	// Never a person's own: Chrome refuses to be driven on its default
	// profile, and that refusal is right.
	Profile string
	// Width and Height are the window, 1280 by 800 when zero: a screen most
	// sites lay out for and small enough to send a model.
	Width, Height int
	// Boxed says the browser runs inside an agent's box, which confines it
	// more tightly than Chromium's own sandbox could there (that needs the
	// user namespaces the box refuses), so its own is turned off.
	Boxed bool
	// Args are further switches.
	Args []string
	// Env is the browser's whole environment.
	Env []string
	// Stderr receives what the browser logs.
	Stderr io.Writer
	// Start starts the process with in and out as its file descriptors 3
	// and 4. Nil runs Path directly; the agent box supplies its own.
	Start func(ctx context.Context, argv []string, env []string, in, out *os.File) (Process, error)
}

// Process is a started browser.
type Process interface {
	Wait() error
	Kill() error
}

// Browser is a browser this process started and holds the only connection to.
type Browser struct {
	*Conn
	proc     Process
	waitOnce sync.Once
	waitErr  error
	exited   chan struct{}
}

// Switches every browser gets. Each one is a way Chromium would otherwise
// talk to somebody nobody asked it to, or do something an agent's browser
// has no business doing: phone home for updates, safe-browsing lists,
// metrics, crash reports or sync; run extensions; keep passwords in the
// desktop's keyring; play sound.
var hardening = []string{
	"--no-first-run", "--no-default-browser-check",
	"--disable-background-networking", "--disable-component-update", "--disable-sync",
	"--disable-default-apps", "--disable-extensions", "--disable-domain-reliability",
	"--disable-client-side-phishing-detection", "--disable-breakpad", "--disable-crash-reporter",
	"--metrics-recording-only", "--disable-background-timer-throttling",
	"--password-store=basic", "--use-mock-keychain", "--mute-audio",
	"--disable-features=Translate,MediaRouter,OptimizationHints,AutofillServerCommunication",
	"--disable-dev-shm-usage",
}

// Argv is the command line a browser is started with.
func (o Options) Argv() ([]string, error) {
	if !filepath.IsAbs(o.Path) {
		return nil, fmt.Errorf("%q is not an absolute path to a browser", o.Path)
	}
	if o.Profile == "" || !filepath.IsAbs(o.Profile) {
		return nil, errors.New("a browser needs a profile directory of its own")
	}
	w, h := o.Width, o.Height
	if w <= 0 || h <= 0 {
		w, h = 1280, 800
	}
	argv := []string{o.Path, "--headless", "--remote-debugging-pipe",
		"--user-data-dir=" + o.Profile, "--window-size=" + strconv.Itoa(w) + "," + strconv.Itoa(h)}
	argv = append(argv, hardening...)
	if o.Boxed {
		argv = append(argv, "--no-sandbox")
	}
	argv = append(argv, o.Args...)
	// Nothing to open at start: pages are made on purpose, each one a
	// target this process attached to.
	return append(argv, "about:blank"), nil
}

// Launch starts a browser and connects to it.
func Launch(ctx context.Context, o Options) (*Browser, error) {
	argv, err := o.Argv()
	if err != nil {
		return nil, err
	}
	// Two pipes: the browser reads commands from its fd 3 and writes replies
	// to its fd 4. The ends it gets are closed here once it has them.
	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	repR, repW, err := os.Pipe()
	if err != nil {
		cmdR.Close()
		cmdW.Close()
		return nil, err
	}
	start := o.Start
	if start == nil {
		start = direct(o.Stderr)
	}
	proc, err := start(ctx, argv, o.Env, cmdR, repW)
	cmdR.Close()
	repW.Close()
	if err != nil {
		cmdW.Close()
		repR.Close()
		return nil, fmt.Errorf("cannot start the browser: %w", err)
	}
	b := &Browser{Conn: New(repR, cmdW), proc: proc, exited: make(chan struct{})}
	go func() {
		b.waitOnce.Do(func() { b.waitErr = proc.Wait() })
		cmdW.Close()
		close(b.exited)
	}()
	// The first command answers when the browser is ready to take them.
	vctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var v struct {
		Product string `json:"product"`
	}
	if err := b.Call(vctx, "", "Browser.getVersion", nil, &v); err != nil {
		b.Close()
		return nil, fmt.Errorf("the browser did not answer: %w", err)
	}
	return b, nil
}

func direct(stderr io.Writer) func(context.Context, []string, []string, *os.File, *os.File) (Process, error) {
	return func(ctx context.Context, argv, env []string, in, out *os.File) (Process, error) {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = env
		cmd.Stderr = stderr
		cmd.ExtraFiles = []*os.File{in, out}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return execProcess{cmd}, nil
	}
}

type execProcess struct{ cmd *exec.Cmd }

func (p execProcess) Wait() error { return p.cmd.Wait() }
func (p execProcess) Kill() error { return p.cmd.Process.Kill() }

// Close asks the browser to end, and ends it if it does not.
func (b *Browser) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = b.Call(ctx, "", "Browser.close", nil, nil)
	select {
	case <-b.exited:
	case <-time.After(5 * time.Second):
		_ = b.proc.Kill()
		<-b.exited
	}
	return nil
}

// Exited is closed when the browser's process has ended.
func (b *Browser) Exited() <-chan struct{} { return b.exited }
