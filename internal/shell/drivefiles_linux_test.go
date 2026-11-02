// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package shell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
)

// Code runs with the interpreter the declaration names. Without "writes"
// it reads the workspace and changes nothing in it, whatever it tries;
// with it, it changes the workspace, and a person sees the code whole
// first. It never reaches the network.
func TestCodeRunsAndChangesNothingUnlessItSays(t *testing.T) {
	if _, err := Find("python3"); err != nil {
		t.Skip("no python3 here")
	}
	d, kept := testDriver(t, &agent.Shell{Programs: []string{"python3"}})
	if _, err := do(t, d, "file_write", map[string]any{"path": "data.csv", "text": "a,b\n1,2\n3,4\n"}); err != nil {
		t.Fatal(err)
	}
	sum := `import csv
rows = list(csv.DictReader(open("data.csv")))
print(sum(int(r["b"]) for r in rows))
try:
    open("made.txt", "w").write("x")
    print("wrote")
except OSError as e:
    print("could not write")
`
	a := agent.Action{Op: "code_run", Input: map[string]any{"language": "python", "code": sum}}
	if why := d.Weighs(a); why != "" {
		t.Fatalf("code that only reads waited for a person: %s", why)
	}
	out, err := do(t, d, "code_run", a.Input)
	if err != nil || !strings.Contains(out, "python3 code: exit 0") || !strings.Contains(out, "\n6\n") ||
		!strings.Contains(out, "could not write") {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(d.Workspace.Dir, "made.txt")); err == nil {
		t.Fatal("code that only reads wrote the workspace")
	}
	if n := len(*kept); n != 1 || !strings.HasPrefix((*kept)[0].Input, "code sha256:") || (*kept)[0].Kind != "reads" {
		t.Fatalf("%+v", *kept)
	}
	// Saying it writes: a person sees the code whole, and then it writes.
	write := map[string]any{"language": "py", "code": `open("made.txt", "w").write("x")`, "writes": true}
	why := d.Weighs(agent.Action{Op: "code_run", Input: write})
	if !strings.Contains(why, "may change or delete anything") || !strings.Contains(why, `open("made.txt", "w")`) {
		t.Fatalf("%q", why)
	}
	if c := agent.CommitOf(agent.Action{Op: "code_run", Input: write}, why, agent.WaitAsk, false); c != "deletes" {
		t.Errorf("code that may delete anything commits to %q", c)
	}
	if out, err := do(t, d, "code_run", write); err != nil || !strings.Contains(out, "added made.txt") {
		t.Fatalf("%q %v", out, err)
	}
	// No network, whatever it is told.
	net := `import urllib.request
try:
    urllib.request.urlopen("http://example.com", timeout=3)
    print("reached")
except Exception:
    print("no network")
`
	if out, _ := do(t, d, "code_run", map[string]any{"language": "python", "code": net}); !strings.Contains(out, "no network") {
		t.Fatalf("%q", out)
	}
	// A language the declaration names no interpreter for, and code too
	// long for a person to read when it writes.
	if _, err := do(t, d, "code_run", map[string]any{"language": "ruby", "code": "puts 1"}); err == nil ||
		!strings.Contains(err.Error(), "names none of ruby") {
		t.Errorf("%v", err)
	}
	long := map[string]any{"language": "python", "code": strings.Repeat("x = 1\n", MaxAskedCode), "writes": true}
	if _, err := do(t, d, "code_run", long); err == nil || !strings.Contains(err.Error(), "shown whole") {
		t.Errorf("%v", err)
	}
	// A run that only reads runs code that only reads, and nothing else.
	d.Session.Manifest().Shell.ReadOnly = true
	if _, err := do(t, d, "code_run", write); err == nil {
		t.Error("a run that only reads ran code that writes")
	}
}

// The file actions through the driver: an edit given as a model gives it,
// a search, a deletion and what waits for whom.
func TestTheFileActionsAreDone(t *testing.T) {
	d, _ := testDriver(t, &agent.Shell{Programs: []string{"ls"}, Ask: []string{"write"}})
	if _, err := do(t, d, "file_write", map[string]any{"path": "notes.md", "text": "one\nthree\n"}); err != nil {
		t.Fatal(err)
	}
	out, err := do(t, d, "file_edit", map[string]any{"path": "notes.md", "line": float64(1), "insert": "two"})
	if err != nil || !strings.Contains(out, "after line 1") || !strings.Contains(out, "changed notes.md") {
		t.Fatalf("%q %v", out, err)
	}
	if out, err := do(t, d, "file_edit", map[string]any{"path": "notes.md", "old": "three", "new": "four"}); err != nil ||
		!strings.Contains(out, "replaced one place") {
		t.Fatalf("%q %v", out, err)
	}
	if out, err := do(t, d, "file_read", map[string]any{"path": "notes.md", "from": float64(2), "lines": float64(2)}); err != nil ||
		out != "notes.md, lines 2 to 3 of 3:\ntwo\nfour\n" {
		t.Fatalf("%q %v", out, err)
	}
	if out, err := do(t, d, "file_search", map[string]any{"text": "four"}); err != nil || !strings.Contains(out, "notes.md:3: four") {
		t.Fatalf("%q %v", out, err)
	}
	// Each change waits for a person when the declaration asks about
	// writing; into the bin is a write, out of it for good is a deletion,
	// and that one waits whatever the declaration says.
	for op, in := range map[string]map[string]any{"file_edit": {"path": "notes.md"}, "file_move": {"from": "a", "to": "b"},
		"file_delete": {"path": "notes.md"}} {
		if why := d.Weighs(agent.Action{Op: op, Input: in}); why == "" {
			t.Errorf("%s did not wait though the declaration asks about writing", op)
		}
	}
	out, err = do(t, d, "file_delete", map[string]any{"path": "notes.md"})
	if err != nil || !strings.Contains(out, "file_move brings it back") {
		t.Fatalf("%q %v", out, err)
	}
	inBin := strings.Fields(strings.SplitN(out, " as ", 2)[1])[0]
	inBin = strings.TrimSuffix(inBin, ";")
	free, _ := testDriver(t, &agent.Shell{Programs: []string{"ls"}})
	why := free.Weighs(agent.Action{Op: "file_delete", Input: map[string]any{"path": inBin}})
	if !strings.Contains(why, "nothing brings back") {
		t.Fatalf("deleting from the bin did not wait: %q", why)
	}
	if c := agent.CommitOf(agent.Action{Op: "file_delete"}, why, agent.WaitAsk, false); c != "deletes" {
		t.Errorf("deleting for good commits to %q", c)
	}
	if why := free.Weighs(agent.Action{Op: "file_delete", Input: map[string]any{"path": "x.md"}}); why != "" {
		t.Errorf("into the bin waited with nothing asked: %q", why)
	}
}

// What the browser keeps goes through the workspace's own rules: its
// quota, and nothing for a run that only reads.
func TestWhatTheBrowserKeepsIsHeldToTheWorkspace(t *testing.T) {
	d, _ := testDriver(t, &agent.Shell{Programs: []string{"ls"}, QuotaMB: 1})
	if used, err := d.SaveFile("downloads/prices.csv", []byte("loaf,3\n")); err != nil || used != "downloads/prices.csv" {
		t.Fatalf("%q %v", used, err)
	}
	if _, err := d.SaveFile("big.bin", make([]byte, 2<<20)); err == nil || !strings.Contains(err.Error(), "over its 1 MiB") {
		t.Errorf("%v", err)
	}
	if b, err := d.LoadFile("downloads/prices.csv"); err != nil || string(b) != "loaf,3\n" || !d.Session.Tainted() {
		t.Errorf("%q %v tainted=%v", b, err, d.Session.Tainted())
	}
	d.Session.Manifest().Shell.ReadOnly = true
	if _, err := d.SaveFile("x.txt", []byte("x")); err == nil {
		t.Error("a run that only reads saved a file")
	}
}
