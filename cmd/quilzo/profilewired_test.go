// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/cdp"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/profile"
	"github.com/quilzo/quilzo/internal/public"
)

// lockedBuffer is a server's standard error, written by its process and
// read by the test while it runs.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// startServer runs `quilzo --root root ARGS` as a person runs it, and
// returns once something answers at port on loopback, with what it says on
// standard error so far and from then on.
func startServer(t *testing.T, root, token, port string, args ...string) *lockedBuffer {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"quilzo-main", "--root", root}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "QUILZO_TOKEN="+token, "NO_COLOR=1")
	stderr := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = io.Discard, stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-exited })
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			exited <- err
			t.Fatalf("`quilzo %s` stopped before it answered (%v):\n%s", strings.Join(args, " "), err, stderr.String())
		default:
		}
		if c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 200*time.Millisecond); err == nil {
			c.Close()
			return stderr
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("`quilzo %s` did not answer on port %s:\n%s", strings.Join(args, " "), port, stderr.String())
	return nil
}

func fetchServed(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := (&http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// The profile is enforced where each surface is served, and not only where
// a test puts its gate: the command line refuses a switched-off command
// before it runs, the admin `quilzo serve` starts and the public server
// `quilzo site` starts answer a switched-off address as off, serve says at
// start that it listens where the internet could reach it, and a feature
// switched back on is served from the next request, without a restart.
func TestTheProfileIsEnforcedWhereEachSurfaceIsServed(t *testing.T) {
	root := securedStore(t)
	token := flagToken

	_, stderr, code := cliRun(t, root, token, "pay")
	if code != out.ExitBlocked || !strings.Contains(stderr, "switched off") ||
		!strings.Contains(stderr, "quilzo profile enable commerce") {
		t.Errorf("`quilzo pay` under the security profile exited %d: %s", code, firstLines(stderr, 4))
	}

	adminPort := freePort(t)
	said := startServer(t, root, token, adminPort, "serve", "--addr", "0.0.0.0:"+adminPort)
	if !strings.Contains(said.String(), "listens on every interface") {
		t.Errorf("serve on every interface did not warn:\n%s", said.String())
	}
	resp, _ := fetchServed(t, "http://127.0.0.1:"+adminPort+"/pay")
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get(profile.OffHeader) != "commerce" {
		t.Errorf("the admin served /pay with commerce switched off: %d %q", resp.StatusCode, resp.Header.Get(profile.OffHeader))
	}

	tpl := t.TempDir()
	if err := os.WriteFile(filepath.Join(tpl, "page.html"),
		[]byte(`<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head><body><h1>{{ page.title }}</h1></body></html>`), 0o600); err != nil {
		t.Fatal(err)
	}
	sitePort := freePort(t)
	startServer(t, root, token, sitePort, "site", "--addr", "127.0.0.1:"+sitePort, "--templates", tpl)
	const refusal = "Nothing is served at this address."
	for _, path := range []string{"/.well-known/ucp", "/board/general", "/@/inbox"} {
		if resp, body := fetchServed(t, "http://127.0.0.1:"+sitePort+path); resp.StatusCode != http.StatusNotFound ||
			!strings.Contains(body, refusal) {
			t.Errorf("the site answered %s with %d, not as switched off", path, resp.StatusCode)
		}
	}

	if err := cmdProfile(root, []string{"enable", "commerce", "--reason", "the conference sells tickets"}); err != nil {
		t.Fatal(err)
	}
	if resp, _ := fetchServed(t, "http://127.0.0.1:"+adminPort+"/pay"); resp.Header.Get(profile.OffHeader) != "" {
		t.Error("with commerce switched back on, the running admin still answers /pay as switched off")
	}
	if _, body := fetchServed(t, "http://127.0.0.1:"+sitePort+"/.well-known/ucp"); strings.Contains(body, refusal) {
		t.Error("with commerce switched back on, the running site still answers /.well-known/ucp as switched off")
	}
	if _, stderr, _ := cliRun(t, root, token, "pay"); strings.Contains(stderr, "switched off") {
		t.Errorf("with commerce switched back on, `quilzo pay` is still refused: %s", firstLines(stderr, 3))
	}
}

// An agent run asking for a browser is refused it while browser hands are
// switched off, before a place is taken and whatever would launch it, and
// given one once they are switched back on.
func TestAnAgentRunIsRefusedItsBrowserWithBrowserHandsOff(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	if err := cmdProfile(root, []string{"apply", "security", "--reason", "the security install"}); err != nil {
		t.Fatal(err)
	}
	m := agent.Manifest{Name: "buyer", Kind: agent.KindTask, Purpose: "Pay the supplier's invoice",
		Capabilities: []string{"browser_open", "browser_read"}, Autonomy: agent.AutonomyDraft,
		Browser: &agent.Browser{Read: []string{"shop.example.com"}},
		Budget:  agent.Budget{Steps: 8, Tools: 1, Duration: agent.Duration(2 * time.Minute)}}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	launched := errors.New("the browser was launched")
	browserTestLaunch = func(context.Context) (*cdp.Browser, error) { return nil, launched }
	t.Cleanup(func() { browserTestLaunch = nil })
	open := agent.Action{Op: "browser_open", Input: map[string]any{"url": "https://shop.example.com/cart"}}
	try := func() error {
		t.Helper()
		rb, err := newRunBrowser(root, m, agent.NewSession(m, nil), asAdmin("dana"), nil, "", false)
		if err != nil {
			t.Fatal(err)
		}
		defer rb.end()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err = rb.driver.Perform(nil)(ctx, open)
		return err
	}
	if err := try(); err == nil || !strings.Contains(err.Error(), "switched off") || strings.Contains(err.Error(), launched.Error()) {
		t.Errorf("a run was not refused its browser with browser hands switched off: %v", err)
	}
	if err := cmdProfile(root, []string{"enable", "browser-hands", "--reason", "the crew checks the published site"}); err != nil {
		t.Fatal(err)
	}
	if err := try(); err == nil || !strings.Contains(err.Error(), launched.Error()) {
		t.Errorf("with browser hands switched back on, the run's browser was not launched: %v", err)
	}
}

// With experiments and personalisation switched off, the site serves every
// visitor the same page: the sets it reads per request are empty, whatever
// tests and rules were declared before, and come back when the features
// are switched back on.
func TestTheSiteServesEveryVisitorTheSamePageWithTheirFeaturesOff(t *testing.T) {
	root := securedStore(t)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	if err := os.WriteFile(a, []byte(`{"title":"About us","body":"Who we are."}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(`{"title":"About us B","body":"Who we are, again."}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCmd(t, root, "add", "about="+a, "about-b="+b, "-m", "two pages"); err != nil {
		t.Fatal(err)
	}
	// Declared by calling the commands, which the dispatch refuses under
	// the profile: what was declared before it was applied is what this is
	// about.
	if err := cmdExperiment(root, []string{"add", "signup", "--page", "about", "--variant", "b=about-b",
		"--goal", "page:/contact"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdPersonalise(root, []string{"add", "spring", "--page", "about", "--variant", "about-b",
		"--when", "campaign=spring"}); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	st := &public.Site{}
	siteRun{root: root, store: s, counter: &analytics.Counter{}}.dress(st)
	sets := func() (int, int) {
		t.Helper()
		e, err := st.Experiments()
		if err != nil {
			t.Fatal(err)
		}
		p, err := st.Personalise()
		if err != nil {
			t.Fatal(err)
		}
		return len(e.Experiments), len(p.Rules)
	}
	if e, p := sets(); e != 0 || p != 0 {
		t.Errorf("with experiments and personalisation off, the site reads %d experiments and %d rules", e, p)
	}
	for _, f := range []string{"experiments", "personalisation"} {
		if err := cmdProfile(root, []string{"enable", f, "--reason", "the spring campaign"}); err != nil {
			t.Fatal(err)
		}
	}
	if e, p := sets(); e != 1 || p != 1 {
		t.Errorf("switched back on, the site reads %d experiments and %d rules, want one of each", e, p)
	}
}
