// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain lets this test binary stand in for a maker: run with
// QUILZO_FAKE_VMM naming a file, it serves the maker's API on the socket
// its arguments name and writes each request to that file.
func TestMain(m *testing.M) {
	if log := os.Getenv("QUILZO_FAKE_VMM"); log != "" {
		fakeVMM(log)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeVMM ends on the maker's own shutdown, unless QUILZO_FAKE_VMM_STUBBORN
// is set; with QUILZO_FAKE_VMM_DIE set it ends before making a socket.
func fakeVMM(logPath string) {
	if os.Getenv("QUILZO_FAKE_VMM_DIE") != "" {
		os.Exit(3)
	}
	var socket string
	for i, a := range os.Args[:len(os.Args)-1] {
		switch a {
		case "--api-sock":
			socket = os.Args[i+1]
		case "--api-socket":
			socket = strings.TrimPrefix(os.Args[i+1], "path=")
		}
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		os.Exit(4)
	}
	stubborn := os.Getenv("QUILZO_FAKE_VMM_STUBBORN") != ""
	done := make(chan struct{})
	var once sync.Once
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			fmt.Fprintf(f, "%s %s %s\n", r.Method, r.URL.Path, body)
			f.Close()
		}
		w.WriteHeader(http.StatusNoContent)
		if !stubborn && (r.URL.Path == "/actions" || r.URL.Path == "/api/v1/vmm.shutdown") {
			once.Do(func() { close(done) })
		}
	})}
	go srv.Serve(ln)
	<-done
	time.Sleep(50 * time.Millisecond)
}

// fakeMaker is this test binary as a maker's binary, and the file its
// requests are written to.
func fakeMaker(t *testing.T, env ...string) (string, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "calls")
	t.Setenv("QUILZO_FAKE_VMM", log)
	for i := 0; i+1 < len(env); i += 2 {
		t.Setenv(env[i], env[i+1])
	}
	return exe, log
}

func calls(t *testing.T, log string) string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func ended(v *vmm, within time.Duration) bool {
	select {
	case <-v.done:
		return true
	case <-time.After(within):
		return false
	}
}

// A maker lives as long as the cell, not as long as the call that started
// it, and Stop ends it and takes its socket with it.
func TestAMakerOutlivesTheCallThatStartedIt(t *testing.T) {
	exe, log := fakeMaker(t)
	f := &Firecracker{Binary: exe}
	socket := filepath.Join(t.TempDir(), "vm.sock")
	ctx, cancel := context.WithCancel(context.Background())
	if err := f.start(ctx, Machine{Snapshot: "/warm/snap", Memory: "/warm/mem"}, socket); err != nil {
		t.Fatal(err)
	}
	cancel()
	v := f.procs.by[socket]
	if v == nil || ended(v, 200*time.Millisecond) {
		t.Fatal("the maker ended with the context its start was given")
	}
	if got := calls(t, log); !strings.Contains(got, "PUT /snapshot/load") || !strings.Contains(got, `"backend_path":"/warm/mem"`) {
		t.Fatalf("the restore: %s", got)
	}
	if err := f.Stop(context.Background(), socket); err != nil {
		t.Fatal(err)
	}
	if !ended(v, 5*time.Second) {
		t.Fatal("the maker is still running after Stop")
	}
	if !strings.Contains(calls(t, log), "PUT /actions") {
		t.Error("Stop did not ask the guest to end first")
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Error("the socket was left behind")
	}
}

// Cloud Hypervisor's restore names the snapshot and nothing of the shape,
// then resumes; and a maker that ignores its shutdown is killed when the
// grace runs out.
func TestAStubbornMakerIsKilled(t *testing.T) {
	exe, log := fakeMaker(t, "QUILZO_FAKE_VMM_STUBBORN", "1")
	grace := stopGrace
	stopGrace = 200 * time.Millisecond
	t.Cleanup(func() { stopGrace = grace })
	c := &CloudHypervisor{Binary: exe}
	socket := filepath.Join(t.TempDir(), "vm.sock")
	if err := c.start(context.Background(), Machine{Snapshot: "/warm/snap"}, socket); err != nil {
		t.Fatal(err)
	}
	got := calls(t, log)
	if !strings.Contains(got, `PUT /api/v1/vm.restore {"source_url":"file:///warm/snap"}`) ||
		!strings.Contains(got, "PUT /api/v1/vm.resume") {
		t.Fatalf("the restore: %s", got)
	}
	v := c.procs.by[socket]
	if err := c.Stop(context.Background(), socket); err != nil {
		t.Fatal(err)
	}
	if !ended(v, 2*time.Second) {
		t.Fatal("a maker that ignored its shutdown is still running")
	}
}

// A maker that ends before it makes a socket is said plainly and at once,
// and one asked to restore a snapshot without its memory file is not run.
func TestAMakerThatCannotStartIsSaidPlainly(t *testing.T) {
	exe, _ := fakeMaker(t, "QUILZO_FAKE_VMM_DIE", "1")
	f := &Firecracker{Binary: exe}
	socket := filepath.Join(t.TempDir(), "vm.sock")
	began := time.Now()
	err := f.start(context.Background(), Machine{Snapshot: "/warm/snap", Memory: "/warm/mem"}, socket)
	if err == nil || !strings.Contains(err.Error(), "ended before it made its socket") {
		t.Fatalf("a dead maker: %v", err)
	}
	if time.Since(began) > 2*time.Second {
		t.Error("a dead maker was waited on until the limit")
	}
	if err := f.start(context.Background(), Machine{Snapshot: "/warm/snap"}, socket); err == nil {
		t.Fatal("a snapshot without its memory file was restored")
	}
	if len(f.procs.by) != 0 {
		t.Error("a maker that never started is still kept")
	}
}
