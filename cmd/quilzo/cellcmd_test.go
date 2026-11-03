// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
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

	"github.com/quilzo/quilzo/internal/auth"
)

// runningCell is a microVM's API socket with nothing behind it but a
// record of what it was asked, in order, with each request's body.
func runningCell(t *testing.T) (socket string, asked func() []string, bodies map[string]map[string]any) {
	t.Helper()
	dir, err := os.MkdirTemp("", "cell")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket = filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var calls []string
	bodies = map[string]map[string]any{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		bodies[r.URL.Path] = body
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return socket, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), calls...)
	}, bodies
}

// A cell is warmed by this program: the operator brings one up and sets
// its desktop up by hand, and quilzo cell warm pauses it, writes its
// snapshot where the settings say, in the shape its maker restores, and
// resumes it. The setting said the operator made the snapshot with the
// microVM's own tools, the code said this program did, and nothing did:
// cell.Snapshot and SnapshotCH ran only in tests.
func TestACellIsWarmedWhereItsSettingsSay(t *testing.T) {
	root := demoStore(t)
	set := func(kv ...string) {
		t.Helper()
		for i := 0; i < len(kv); i += 2 {
			if err := cmdConfig(root, []string{"set", kv[i], kv[i+1]}); err != nil {
				t.Fatal(err)
			}
		}
	}

	socket, asked, _ := runningCell(t)
	if err := cmdCell(root, []string{"warm", "--socket", socket}); err == nil || !strings.Contains(err.Error(), "cell.backend") {
		t.Fatalf("warmed with no backend to say the shape: %v", err)
	}
	set("cell.backend", "firecracker", "cell.snapshot", "/warm/snap")
	if err := cmdCell(root, []string{"warm", "--socket", socket}); err == nil || !strings.Contains(err.Error(), "cell.memory") {
		t.Fatalf("warmed Firecracker with nowhere for its memory: %v", err)
	}
	if len(asked()) != 0 {
		t.Fatalf("a refused warm asked the cell %v", asked())
	}

	set("cell.memory", "/warm/mem")
	socket, asked, bodies := runningCell(t)
	if err := cmdCell(root, []string{"warm", "--socket", socket}); err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(asked()), "[PATCH /vm PUT /snapshot/create PATCH /vm]"; got != want {
		t.Fatalf("Firecracker was asked %s, not %s", got, want)
	}
	if b := bodies["/snapshot/create"]; b["snapshot_path"] != "/warm/snap" || b["mem_file_path"] != "/warm/mem" {
		t.Errorf("the snapshot went to %v", b)
	}

	set("cell.backend", "cloud-hypervisor")
	socket, asked, bodies = runningCell(t)
	if err := cmdCell(root, []string{"warm", "--socket", socket, "--snapshot", "/warm/other"}); err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(asked()), "[PUT /api/v1/vm.pause PUT /api/v1/vm.snapshot PUT /api/v1/vm.resume]"; got != want {
		t.Fatalf("Cloud Hypervisor was asked %s, not %s", got, want)
	}
	if b := bodies["/api/v1/vm.snapshot"]; b["destination_url"] != "file:///warm/other" {
		t.Errorf("--snapshot did not say where: %v", b)
	}
}

// What every agent's desktop starts as is an administrator's to make, as
// the settings that name it are: reading whether a cell can run stays a
// reader's.
func TestWarmingACellIsAnAdministrators(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	for _, kv := range [][2]string{{"cell.backend", "cloud-hypervisor"}, {"cell.snapshot", "/warm/snap"}} {
		if err := cmdConfig(root, []string{"set", kv[0], kv[1]}); err != nil {
			t.Fatal(err)
		}
	}
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"erin", "author"})
	ts, _ := loadTokens(root)
	token := map[string]string{}
	for who, role := range map[string]auth.Role{"dana": auth.RoleAdmin, "erin": auth.RoleAuthor} {
		secret, _, err := ts.Issue(who, who, role, "/", time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		token[who] = secret
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	old := flagToken
	t.Cleanup(func() { flagToken = old })

	socket, asked, _ := runningCell(t)
	flagToken = token["erin"]
	if err := authoriseCommand(root, "cell", []string{"status"}); err != nil {
		t.Errorf("an author may not read whether a cell runs: %v", err)
	}
	if err := cmdCell(root, []string{"warm", "--socket", socket}); err == nil || !strings.Contains(err.Error(), "grant") {
		t.Errorf("an author warmed a cell: %v", err)
	}
	if len(asked()) != 0 {
		t.Fatalf("a refused warm asked the cell %v", asked())
	}
	flagToken = token["dana"]
	if err := cmdCell(root, []string{"warm", "--socket", socket}); err != nil {
		t.Errorf("an administrator could not warm a cell: %v", err)
	}
}
