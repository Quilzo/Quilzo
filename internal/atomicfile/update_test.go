// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Many writers changing one file at once lose nothing, and what one of them
// removes is not put back by another that read the file earlier.
func TestConcurrentUpdatesLoseNothingAndUndoNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Update(path, func(m *map[string]bool) error {
		*m = map[string]bool{"revoked": true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := Update(path, func(m *map[string]bool) error {
				if *m == nil {
					*m = map[string]bool{}
				}
				(*m)[fmt.Sprint("writer-", i)] = true
				return nil
			}); err != nil {
				t.Error(err)
			}
		}(i)
		if i == 20 {
			if err := Update(path, func(m *map[string]bool) error {
				delete(*m, "revoked")
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	wg.Wait()
	var got map[string]bool
	if err := Update(path, func(m *map[string]bool) error { got = *m; return ErrUnchanged }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 40 {
		t.Errorf("%d of 40 writes survived", len(got))
	}
	if got["revoked"] {
		t.Error("a removal was undone by a writer that read the file before it")
	}
}

// A change that fails writes nothing, and an absent file starts empty.
func TestAFailedChangeWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	boom := errors.New("refused")
	if err := Update(path, func(m *map[string]int) error { (*m) = map[string]int{"x": 1}; return boom }); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a refused change was written")
	}
}
