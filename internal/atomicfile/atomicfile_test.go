package atomicfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// A reader must never see half a file.
//
// This reproduces what happened: two processes share a store, one writes a
// state file while the other reads it, and os.WriteFile's truncate-then-write
// leaves a window where the file is empty or partial. The reader does not get
// stale data, it gets a parse error — and a store whose token file will not
// parse is correctly treated as one nobody may write to, so the site process
// refused to start.
//
// Written against a JSON document because that is what every state file here
// is, and because a partial write is only detectable if the content has a
// shape. A reader that sees fewer bytes than it should of a plain text file
// cannot tell.
func TestAReaderNeverSeesAPartialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")

	// Big enough that a single write is not atomic at the syscall level, which
	// is what makes the naive version fail.
	doc := func(n int) []byte {
		m := map[string]any{"generation": n}
		for i := 0; i < 400; i++ {
			m[fmt.Sprintf("token-%03d", i)] = strings.Repeat("a", 64)
		}
		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := Write(path, doc(0), 0o600); err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	var reads, torn atomic.Int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; !stop.Load(); i++ {
			if err := Write(path, doc(i), 0o600); err != nil {
				t.Errorf("write: %v", err)
				return
			}
		}
	}()

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 600; i++ {
				b, err := os.ReadFile(path)
				if err != nil {
					torn.Add(1)
					continue
				}
				var m map[string]any
				if json.Unmarshal(b, &m) != nil {
					torn.Add(1)
					continue
				}
				reads.Add(1)
			}
		}()
	}

	// Readers finish on their own count; the writer runs until they do.
	go func() {
		for reads.Load()+torn.Load() < 2400 {
		}
		stop.Store(true)
	}()
	wg.Wait()

	if reads.Load() == 0 {
		t.Fatal("nothing was read, so this test is checking nothing")
	}
	if n := torn.Load(); n > 0 {
		t.Fatalf("%d of %d reads got a file that would not parse; a reader "+
			"landing in a write window must see the previous file, not a "+
			"partial one", n, reads.Load()+n)
	}
}

// The mode is the mode asked for, not the one CreateTemp picks.
func TestTheModeIsWhatWasAskedFor(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o600, 0o644} {
		path := filepath.Join(dir, fmt.Sprintf("f%o", mode))
		if err := Write(path, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != mode {
			t.Errorf("wrote %s with mode %o, want %o", path, got, mode)
		}
	}
}

// A failed write leaves neither litter nor damage.
func TestAFailedWriteLeavesThePreviousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := Write(path, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory that cannot be written to.
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := Write(filepath.Join(locked, "x.json"), []byte("{}"), 0o600); err == nil {
		t.Skip("running as a user that can write to a read-only directory")
	}

	b, err := os.ReadFile(path)
	if err != nil || string(b) != `{"v":1}` {
		t.Fatalf("the earlier file was damaged: %q %v", b, err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}
