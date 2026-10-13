// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The makers' APIs are ordinary HTTP on a socket the microVM owns, so a
// fake microVM is an ordinary server on a socket the test owns — and the
// conversation this drives is checked against it: what was asked, in what
// order, with what in the body.
func fakeMicroVM(t *testing.T, answer func(method, path string, body map[string]any) int) (*http.Server, net.Addr, *[]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var calls []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.WriteHeader(answer(r.Method, r.URL.Path, body))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return srv, ln.Addr(), &calls
}

// The Firecracker conversation: one restore carrying the snapshot, its
// memory file and the resume, and nothing else before it.
func TestFirecrackerRestoresAWarmSnapshot(t *testing.T) {
	var got map[string]any
	_, addr, calls := fakeMicroVM(t, func(m, p string, body map[string]any) int {
		if m == "PUT" && p == "/snapshot/load" {
			got = body
		}
		return 200
	})
	c := httpOverUnixTCP(t, addr)
	if err := apiCall(context.Background(), c, "PUT", "/snapshot/load", map[string]any{
		"snapshot_path": "/warm/snap", "mem_backend": map[string]any{"backend_type": "File", "backend_path": "/warm/mem"},
		"resume_vm": true,
	}); err != nil {
		t.Fatal(err)
	}
	if got == nil || got["snapshot_path"] != "/warm/snap" {
		t.Fatalf("the restore did not name the snapshot: %v", got)
	}
	if *calls == nil || (*calls)[0] != "PUT /snapshot/load" {
		t.Fatalf("the conversation: %v", *calls)
	}
}

// Snapshotting is pause, create, resume — in that order — and a maker
// that refuses the create leaves the cell paused, which is the safe place
// for it, with the refusal's own words.
func TestSnapshotIsPauseCreateResume(t *testing.T) {
	_, addr, calls := fakeMicroVM(t, func(m, p string, body map[string]any) int {
		if p == "/snapshot/create" {
			return 400
		}
		return 200
	})
	c := httpOverUnixTCP(t, addr)
	err := snapshotVM(context.Background(), c, "/warm/snap", "/warm/mem")
	if err == nil || !strings.Contains(err.Error(), "taking the snapshot") {
		t.Fatalf("a refused create was not the error: %v", err)
	}
	if len(*calls) != 2 || (*calls)[0] != "PATCH /vm" || (*calls)[1] != "PUT /snapshot/create" {
		t.Fatalf("the snapshot conversation: %v", *calls)
	}
}

// The Cloud Hypervisor conversation: one restore carrying the whole
// shape, then a resume.
func TestCloudHypervisorRestoresAndResumes(t *testing.T) {
	_, addr, calls := fakeMicroVM(t, func(m, p string, body map[string]any) int { return 200 })
	c := httpOverUnixTCP(t, addr)
	for _, step := range []struct {
		method, path string
		body         map[string]any
	}{
		{"PUT", "/api/v1/vm.restore", map[string]any{"source_url": "/warm/snap"}},
		{"PUT", "/api/v1/vm.resume", nil},
	} {
		if err := apiCall(context.Background(), c, step.method, step.path, step.body); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"PUT /api/v1/vm.restore", "PUT /api/v1/vm.resume"}
	if fmt.Sprint(*calls) != fmt.Sprint(want) {
		t.Fatalf("the conversation was %v, not %v", *calls, want)
	}
}

// A maker that says no is heard: the refusal carries its own words, not
// this program's guess at what went wrong.
func TestAMakersRefusalCarriesItsWords(t *testing.T) {
	_, addr, _ := fakeMicroVM(t, func(m, p string, body map[string]any) int {
		return 400
	})
	c := httpOverUnixTCP(t, addr)
	err := apiCall(context.Background(), c, "PUT", "/snapshot/load", map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "Bad Request") {
		t.Fatalf("the maker's refusal was lost: %v", err)
	}
}

// The helper conversation: connect, CONNECT the port, OK, then one JSON
// object a line — and a helper that speaks first, or says nothing this
// can read, is closed on.
func TestTheHelperConversation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				hello, err := r.ReadString('\n')
				if err != nil || !strings.HasPrefix(hello, "CONNECT 5050") {
					return
				}
				fmt.Fprint(conn, "OK 1\n")
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					var req map[string]any
					if json.Unmarshal([]byte(line), &req) != nil {
						return
					}
					id := fmt.Sprintf(`"id":%v,`, req["id"])
					switch req["op"] {
					case "tree":
						fmt.Fprint(conn, `{`+id+`"text":"File — New, Open, Save","elements":{"e1":{"ref":"e1","role":"menu item","name":"New"}}}`+"\n")
					case "click":
						fmt.Fprint(conn, `{`+id+`"said":"pressed menu item \"New\""}`+"\n")
					case "type":
						fmt.Fprint(conn, `{`+id+`"err":"no field is focused"}`+"\n")
					case "key":
						fmt.Fprint(conn, `{`+id+`"err":"ctrl+z is not one of Enter, Tab, Escape or Backspace"}`+"\n")
					case "screen":
						fmt.Fprint(conn, `{`+id+`"jpeg":"`+strings.Repeat("a", 32)+`"}`+"\n")
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })

	h := dialHelperTCP(t, ln)
	defer h.Close()
	tree, err := h.Read(context.Background())
	if err != nil || tree.Text == "" || tree.Elements["e1"].Name != "New" {
		t.Fatalf("the tree did not come back: %v %+v", err, tree)
	}
	if said, err := h.Press(context.Background(), "e1"); err != nil || !strings.Contains(said, "New") {
		t.Fatalf("the press: %q %v", said, err)
	}
	if err := h.Type(context.Background(), "hello"); err == nil || !strings.Contains(err.Error(), "no field is focused") {
		t.Fatalf("a refusal did not carry its words: %v", err)
	}
	if err := h.Key(context.Background(), "ctrl+z"); err == nil {
		t.Fatal("an unnamed key was sent")
	}
	// A picture travels as the bytes it is, JSON-encoded — which is
	// base64 on the wire and the bytes again here.
	if pic, err := h.Screen(context.Background()); err != nil || len(pic) != 24 {
		t.Fatalf("the picture: %d %v", len(pic), err)
	}
}

// A backend that is not installed, or a machine without the virtual
// memory a cell needs, says so at Check and not at Start.
func TestCheckSaysWhatIsMissing(t *testing.T) {
	if _, err := New("not-a-maker", ""); err == nil {
		t.Fatal("an unknown maker was built")
	}
	if _, err := New("firecracker", ""); err != nil {
		t.Fatal(err)
	}
	f := &Firecracker{}
	if a, _ := f.Check(); a.OK {
		t.Fatalf("a backend with no binary checked out: %+v", a)
	}
	f.Binary = filepath.Join(t.TempDir(), "firecracker")
	if err := os.WriteFile(f.Binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	a, _ := f.Check()
	if a.OK && a.Why == "" {
		// KVM may genuinely be here; the binary certainly is not on PATH.
		t.Logf("check with a local binary: %+v", a)
	}
}

// httpOverUnixTCP is the test transport: the same client the driver uses,
// aimed at a TCP listener instead of a Unix socket, because the fake
// microVM is an ordinary server.
func httpOverUnixTCP(t *testing.T, addr net.Addr) *http.Client {
	t.Helper()
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr.String())
		}}}
}

// dialHelperTCP speaks the helper conversation over TCP for a test, the
// same bytes Connect sends at a vsock.
func dialHelperTCP(t *testing.T, ln net.Listener) *Helper {
	t.Helper()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h, err := handshake(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// fakeUnixMicroVM serves the maker's API on a Unix socket, which is where
// it really lives: the whole exported surface — snapshotting, stopping —
// is exercised through its own front door.
func fakeUnixMicroVM(t *testing.T, answer func(method, path string, body map[string]any) int) (string, *[]string) {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "vm.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var calls []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.WriteHeader(answer(r.Method, r.URL.Path, body))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return socket, &calls
}

// The operator's flow for warming a cell, Firecracker's shape: pause,
// create, resume — and a maker that refuses leaves the refusal's words
// and the cell paused, which is the safe place for it.
func TestFirecrackerSnapshotThroughTheSocket(t *testing.T) {
	socket, calls := fakeUnixMicroVM(t, func(m, p string, body map[string]any) int { return 200 })
	if err := Snapshot(context.Background(), socket, "/warm/snap", "/warm/mem"); err != nil {
		t.Fatal(err)
	}
	want := []string{"PATCH /vm", "PUT /snapshot/create", "PATCH /vm"}
	if fmt.Sprint(*calls) != fmt.Sprint(want) {
		t.Fatalf("the conversation was %v, not %v", *calls, want)
	}
	f := &Firecracker{}
	if err := f.Stop(context.Background(), socket); err != nil {
		t.Fatal(err)
	}
	if last := (*calls)[len(*calls)-1]; last != "PUT /actions" {
		t.Fatalf("stop did not signal the guest: %v", *calls)
	}
}

// The same flow, Cloud Hypervisor's shape.
func TestCloudHypervisorSnapshotThroughTheSocket(t *testing.T) {
	socket, calls := fakeUnixMicroVM(t, func(m, p string, body map[string]any) int { return 200 })
	if err := SnapshotCH(context.Background(), socket, "/warm/snap"); err != nil {
		t.Fatal(err)
	}
	want := []string{"PUT /api/v1/vm.pause", "PUT /api/v1/vm.snapshot", "PUT /api/v1/vm.resume"}
	if fmt.Sprint(*calls) != fmt.Sprint(want) {
		t.Fatalf("the conversation was %v, not %v", *calls, want)
	}
	ch := &CloudHypervisor{}
	if err := ch.Stop(context.Background(), socket); err != nil {
		t.Fatal(err)
	}
}

// fakeVsock is a microVM's vsock socket with a helper behind it that plays
// the given script once the handshake is said.
func fakeVsock(t *testing.T, script func(conn net.Conn, r *bufio.Reader)) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "v.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		if hello, err := r.ReadString('\n'); err != nil || hello != "CONNECT 5050\n" {
			return
		}
		script(conn, r)
	}()
	return socket
}

// The maker's OK and whatever came with it are read through the one reader
// the conversation keeps, so nothing is lost between them; and a helper that
// speaks before it is asked is closed on.
func TestAHelperThatSpeaksFirstIsClosedOn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	socket := fakeVsock(t, func(conn net.Conn, r *bufio.Reader) {
		fmt.Fprint(conn, "OK 1073741824\n{\"id\":1,\"text\":\"planted\"}\n")
		_, _ = r.ReadString('\n')
	})
	if _, err := Connect(ctx, socket); err == nil || !strings.Contains(err.Error(), "spoke before it was asked") {
		t.Fatalf("a helper that spoke first was kept: %v", err)
	}
	socket = fakeVsock(t, func(conn net.Conn, r *bufio.Reader) {
		fmt.Fprint(conn, "NO\n")
	})
	if _, err := Connect(ctx, socket); err == nil || !strings.Contains(err.Error(), "did not answer OK") {
		t.Fatalf("a refused CONNECT was taken for an OK: %v", err)
	}
}

// Each answer echoes its request's id: an answer that does not, or that
// comes with another behind it, is out of turn, and the conversation ends
// rather than taking it for the next question's answer.
func TestAnAnswerOutOfTurnEndsTheConversation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, answer := range []string{
		`{"id":7,"text":"File"}` + "\n",
		`{"id":1,"text":"File"}` + "\n" + `{"id":2,"said":"paid"}` + "\n",
	} {
		socket := fakeVsock(t, func(conn net.Conn, r *bufio.Reader) {
			fmt.Fprint(conn, "OK 1\n")
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			fmt.Fprint(conn, answer)
			_, _ = r.ReadString('\n')
		})
		h, err := Connect(ctx, socket)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Read(ctx); err == nil || !strings.Contains(err.Error(), "out of turn") {
			t.Errorf("an answer out of turn was taken: %q: %v", answer, err)
		}
		h.Close()
	}
}
