// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agentexec"
	"github.com/quilzo/quilzo/internal/out"
)

// An undelivered write is kept, privately, with no more than which call
// it was and what came back; the oldest go past the limit; and a person
// takes one, or all, off the list.
func TestUndeliveredWritesAreKeptAndSettled(t *testing.T) {
	root := demoStore(t)
	keep := keepUndelivered(root)
	for i := 0; i < 3; i++ {
		keep(agentexec.Undelivered{At: time.Now(), Agent: "errands", Run: "run-1", Step: i, Integration: "crm",
			Tool: "createContact", Key: fmt.Sprintf("qz-%d", i), Error: "crm answered 503"})
	}
	list, err := loadUndelivered(root)
	if err != nil || len(list) != 3 || list[0].Key != "qz-0" {
		t.Fatalf("%+v %v", list, err)
	}
	info, _ := os.Stat(undeliveredPath(root))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%v", info.Mode())
	}
	if err := integrationsUndelivered(root, nil); err != nil {
		t.Fatal(err)
	}
	if err := integrationsUndelivered(root, []string{"--dismiss", "2"}); err != nil {
		t.Fatal(err)
	}
	list, _ = loadUndelivered(root)
	if len(list) != 2 || list[1].Key != "qz-2" {
		t.Fatalf("%+v", list)
	}
	if err := integrationsUndelivered(root, []string{"--dismiss", "9"}); err == nil {
		t.Fatal("dismissed one that is not there")
	}
	if err := integrationsUndelivered(root, []string{"--clear"}); err != nil {
		t.Fatal(err)
	}
	if list, _ := loadUndelivered(root); len(list) != 0 {
		t.Fatal("cleared and still there")
	}
	for i := 0; i < MaxUndelivered+5; i++ {
		keep(agentexec.Undelivered{Agent: "a", Integration: "b", Tool: "c", Key: fmt.Sprintf("k%d", i)})
	}
	if list, _ := loadUndelivered(root); len(list) != MaxUndelivered || list[0].Key != "k5" {
		t.Fatalf("%d, oldest %s", len(list), list[0].Key)
	}
	log, _ := os.ReadFile(auditPath(root))
	if !strings.Contains(string(log), "integration.undelivered") {
		t.Fatal("not on the record")
	}
}

// What the far side said of a write that did not get through is printed as
// text.
//
// It is the server's words, kept as it answered, and the list printed them
// as they came: a server that failed a write could clear the line saying so
// and print one of its own, and the person settling the write would read
// that it had got through, or nothing at all.
func TestWhatTheFarSideSaidOfAnUndeliveredWriteIsText(t *testing.T) {
	root := demoStore(t)
	keepUndelivered(root)(agentexec.Undelivered{At: time.Now(), Agent: "errands", Run: "run-1", Step: 1, Integration: "crm",
		Tool: "createContact", Key: "qz-1", Error: "crm refused tools/call: no\x1b[1A\x1b[2K\u009b2Kdelivered after all (code -32000)"})
	_, printed := captureStdout(t)
	saved := w
	w = out.New(false)
	t.Cleanup(func() { w = saved })
	err := integrationsUndelivered(root, nil)
	listed := printed()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(listed, "\x1b\u009b") || !strings.Contains(listed, "delivered after all") {
		t.Errorf("an undelivered write was listed with what drives a terminal: %q", listed)
	}
}
