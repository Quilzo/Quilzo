// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build linux

package agentbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary is also the box's first process, its shim, and the
// program inside it, dispatched here before any test runs.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "agentbox-init":
			InitMain()
		case "agentbox-shim":
			ShimMain(os.Args[2])
			os.Exit(125)
		case "agentbox-program":
			programMain(os.Args[2:])
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func native(t *testing.T) Native {
	t.Helper()
	n := Native{Exe: os.Args[0], Init: []string{"agentbox-init"}, Shim: []string{"agentbox-shim"}}
	if a := n.Check(); !a.OK {
		t.Skip("no box here: " + a.Why)
	}
	return n
}

// seen is what the program inside reported.
type seen struct {
	UID      int               `json:"uid"`
	PID      int               `json:"pid"`
	CapEff   string            `json:"cap_eff"`
	CapBnd   string            `json:"cap_bnd"`
	Service  string            `json:"service"`
	Refused  map[string]string `json:"refused"`
	Wrote    bool              `json:"wrote"`
	Env      string            `json:"env"`
	Hostname string            `json:"hostname"`
	Procs    int               `json:"procs"`
}

// programMain is the program inside the box: it tries the doors and says
// which opened.
func programMain(args []string) {
	if len(args) > 0 && args[0] == "sleep" {
		time.Sleep(time.Minute)
		return
	}
	s := seen{UID: os.Getuid(), PID: os.Getpid(), Refused: map[string]string{}, Env: os.Getenv("QUILZO_SEEN")}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "CapEff:"); ok {
				s.CapEff = strings.TrimSpace(v)
			}
			if v, ok := strings.CutPrefix(l, "CapBnd:"); ok {
				s.CapBnd = strings.TrimSpace(v)
			}
		}
	}
	s.Hostname, _ = os.Hostname()
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, e := range entries {
			if e.Name()[0] >= '0' && e.Name()[0] <= '9' {
				s.Procs++
			}
		}
	}
	c := http.Client{Timeout: 3 * time.Second}
	if res, err := c.Get("http://127.0.0.1:8701/hello"); err == nil {
		b, _ := io.ReadAll(res.Body)
		s.Service = string(b)
	} else {
		s.Refused["service"] = err.Error()
	}
	try := func(name string, f func() error) {
		if err := f(); err != nil {
			s.Refused[name] = err.Error()
		}
	}
	dial := func(addr string) func() error {
		return func() error {
			c, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err == nil {
				c.Close()
			}
			return err
		}
	}
	try("other port", dial("127.0.0.1:8702"))
	try("outside", dial("1.1.1.1:443"))
	try("host loopback", dial(os.Getenv("QUILZO_HOST_ADDR")))
	try("secret", func() error { _, err := os.ReadFile(os.Getenv("QUILZO_SECRET")); return err })
	try("listen", func() error {
		l, err := net.Listen("tcp", "127.0.0.1:9999")
		if err == nil {
			l.Close()
		}
		return err
	})
	try("unshare", func() error { return syscall.Unshare(syscall.CLONE_NEWUSER) })
	s.Wrote = os.WriteFile(filepath.Join(os.Getenv("HOME"), "out.txt"), []byte("x"), 0o600) == nil
	b, _ := json.Marshal(s)
	os.Stdout.Write(b)
}

func TestAProgramInTheNativeBoxReachesOnlyWhatItWasHanded(t *testing.T) {
	n := native(t)
	sock, err := os.MkdirTemp("", "qzbox-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sock)
	ln, err := net.Listen("unix", filepath.Join(sock, "mcp.sock"))
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hi from "+r.URL.Path) }))
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("token"), 0o600)
	work := t.TempDir()

	var out, errs bytes.Buffer
	res, err := n.Run(context.Background(), Spec{
		Run: "run-1", Agent: "worker", Program: os.Args[0], Args: []string{"agentbox-program"},
		Env: []string{"HOME=" + work, "QUILZO_SEEN=yes", "QUILZO_SECRET=" + secret,
			"QUILZO_HOST_ADDR=" + host.Addr().String()},
		Workdir: work, Services: []Service{{Name: "mcp", Socket: filepath.Join(sock, "mcp.sock"), Port: PortMCP}},
		Wall: 30 * time.Second, Stdout: &out, Stderr: &errs,
	})
	if err != nil || res.Exit != 0 {
		t.Fatalf("%v exit %d\n%s", err, res.Exit, errs.String())
	}
	c := res.Confined
	if !c.Namespaces || !c.Files || !c.Ports || !c.Seccomp || !c.Capabilities || c.Landlock < 4 {
		t.Errorf("confinement %+v", c)
	}
	var s seen
	if err := json.Unmarshal(out.Bytes(), &s); err != nil {
		t.Fatalf("%v: %s / %s", err, out.String(), errs.String())
	}
	if s.Service != "hi from /hello" {
		t.Errorf("the handed-in service: %q (%v)", s.Service, s.Refused["service"])
	}
	for _, door := range []string{"other port", "outside", "host loopback", "secret", "listen", "unshare"} {
		if s.Refused[door] == "" {
			t.Errorf("%s was open", door)
		}
	}
	if !s.Wrote {
		t.Error("it could not write its own directory")
	}
	t.Logf("own /proc: %v, showing %d processes", c.OwnProc, s.Procs)
	// A /proc of its own shows the box's few processes, never the machine's.
	if c.OwnProc && (s.Procs == 0 || s.Procs > 4) {
		t.Errorf("its /proc shows %d processes", s.Procs)
	}
	// None held, and none it could be handed back: the bounding set too.
	if s.CapEff != "0000000000000000" || s.CapBnd != "0000000000000000" {
		t.Errorf("capabilities %q, bounding set %q", s.CapEff, s.CapBnd)
	}
	// Its own process numbers: the first process's threads take the first few.
	if s.UID != 0 || s.PID > 64 || s.Env != "yes" {
		t.Errorf("uid %d pid %d env %q", s.UID, s.PID, s.Env)
	}
	if _, err := os.Stat(filepath.Join(work, "out.txt")); err != nil {
		t.Error("what it wrote is not in its directory")
	}
}

func TestAProgramIsStoppedWhenItsTimeIsUp(t *testing.T) {
	n := native(t)
	start := time.Now()
	res, err := n.Run(context.Background(), Spec{Program: os.Args[0], Args: []string{"agentbox-program", "sleep"},
		Workdir: t.TempDir(), Wall: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stopped == "" || time.Since(start) > 10*time.Second {
		t.Fatalf("%+v after %s", res, time.Since(start))
	}
}

func TestABoxThatCannotCloseDoesNotRunTheProgram(t *testing.T) {
	n := native(t)
	_, err := n.Run(context.Background(), Spec{Program: "relative", Workdir: t.TempDir()})
	if err == nil {
		t.Fatal("a relative program was run")
	}
	if _, err := n.Run(context.Background(), Spec{Program: os.Args[0]}); err == nil {
		t.Fatal("a box without a directory was opened")
	}
}
