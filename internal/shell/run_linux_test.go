// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build linux

package shell

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agentbox"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "agentbox-init":
			agentbox.InitMain()
		case "agentbox-shim":
			agentbox.ShimMain(os.Args[2])
			os.Exit(125)
		case "connect":
			// A probe: reach an address, and say whether it could.
			c, err := net.DialTimeout("tcp", os.Args[2], 2*time.Second)
			if err != nil {
				fmt.Println("refused:", err)
				os.Exit(1)
			}
			c.Close()
			fmt.Println("connected")
			os.Exit(0)
		case "write":
			if err := os.WriteFile(os.Args[2], []byte("x"), 0o644); err != nil {
				fmt.Println("refused:", err)
				os.Exit(1)
			}
			fmt.Println("wrote")
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func testBox(t *testing.T) Box {
	t.Helper()
	n := agentbox.Native{Exe: os.Args[0], Init: []string{"agentbox-init"}, Shim: []string{"agentbox-shim"}}
	if a := n.Check(); !a.OK {
		t.Skip("no box here: " + a.Why)
	}
	base := t.TempDir()
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	return Box{Backend: n, RunID: "run-1", Agent: "coder", Workspace: ws, Home: filepath.Join(base, "home"),
		Timeout: 20 * time.Second}
}

func run(t *testing.T, b Box, path string, args ...string) Output {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	o, err := b.Run(ctx, Command{Path: path, Args: args, Kind: Classify(filepath.Base(path), args)})
	if err != nil {
		t.Fatalf("%s %v: %v", path, args, err)
	}
	return o
}

// A command runs in the workspace, prints, and is recorded by a digest of
// everything it printed.
func TestACommandRunsInTheWorkspace(t *testing.T) {
	b := testBox(t)
	sh, err := Find("sh")
	if err != nil {
		t.Skip(err)
	}
	o := run(t, b, sh, "-c", "pwd; echo hello > made.txt; cat made.txt")
	if o.Exit != 0 || !strings.Contains(o.Text, b.Workspace) || !strings.Contains(o.Text, "hello") {
		t.Fatalf("%+v", o)
	}
	if !strings.HasPrefix(o.Digest, "sha256:") || o.Total == 0 {
		t.Errorf("%+v", o)
	}
	if got, _ := os.ReadFile(filepath.Join(b.Workspace, "made.txt")); string(got) != "hello\n" {
		t.Errorf("the workspace holds %q", got)
	}
}

// It writes the workspace and its scratch home, and nothing else.
func TestACommandWritesOnlyTheWorkspace(t *testing.T) {
	b := testBox(t)
	outside := filepath.Join(filepath.Dir(b.Workspace), "outside.txt")
	if o := run(t, b, os.Args[0], "write", outside); o.Exit == 0 {
		t.Errorf("wrote outside the workspace: %s", o.Text)
	}
	if o := run(t, b, os.Args[0], "write", filepath.Join(b.Workspace, "in.txt")); o.Exit != 0 {
		t.Errorf("could not write the workspace: %s", o.Text)
	}
	if o := run(t, b, os.Args[0], "write", filepath.Join(b.Home, "cache.txt")); o.Exit != 0 {
		t.Errorf("could not write its home: %s", o.Text)
	}
}

// A command not taken as reaching the network has no way out at all.
func TestACommandThatDoesNotReachTheNetworkCannot(t *testing.T) {
	b := testBox(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if o := run(t, b, os.Args[0], "connect", ln.Addr().String()); o.Exit == 0 {
		t.Errorf("reached %s from the box: %s", ln.Addr(), o.Text)
	}
	if o := run(t, b, os.Args[0], "connect", "1.1.1.1:443"); o.Exit == 0 {
		t.Errorf("reached the internet from the box: %s", o.Text)
	}
}

// Nothing a command starts outlives it.
func TestNothingOutlivesTheCommand(t *testing.T) {
	b := testBox(t)
	sh, err := Find("sh")
	if err != nil {
		t.Skip(err)
	}
	marker := fmt.Sprintf("quilzo-left-behind-%d", time.Now().UnixNano())
	o := run(t, b, sh, "-c", "sleep 300 "+marker+" 2>/dev/null & echo started")
	if !strings.Contains(o.Text, "started") {
		t.Fatalf("%+v", o)
	}
	time.Sleep(300 * time.Millisecond)
	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, p := range procs {
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), marker) {
			t.Fatalf("a process the command started is still running: %s", p)
		}
	}
}

// A command that takes too long is stopped, and says so.
func TestACommandThatTakesTooLongIsStopped(t *testing.T) {
	b := testBox(t)
	b.Timeout = time.Second
	sleep, err := Find("sleep")
	if err != nil {
		t.Skip(err)
	}
	start := time.Now()
	o := run(t, b, sleep, "30")
	if o.Exit == 0 || time.Since(start) > 15*time.Second {
		t.Errorf("not stopped: %+v after %v", o, time.Since(start))
	}
}

// A long output is shown by its start and its end, and kept whole up to
// the bound; the digest is of all of it.
func TestALongOutputIsShownByItsEnds(t *testing.T) {
	b := testBox(t)
	seq, err := Find("seq")
	if err != nil {
		t.Skip(err)
	}
	o := run(t, b, seq, "1", "20000")
	if o.Total < 100000 || len(o.Text) > ShownHead+ShownTail+100 {
		t.Fatalf("total %d, shown %d", o.Total, len(o.Text))
	}
	if !strings.HasPrefix(o.Text, "1\n2\n") || !strings.HasSuffix(o.Text, "20000\n") || !strings.Contains(o.Text, "bytes not shown") {
		t.Errorf("shown: %.80q … %.80q", o.Text, o.Text[len(o.Text)-80:])
	}
	if int64(len(o.Kept)) != o.Total {
		t.Errorf("kept %d of %d", len(o.Kept), o.Total)
	}
}
