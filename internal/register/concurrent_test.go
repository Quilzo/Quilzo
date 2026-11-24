// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"fmt"
	"sync"
	"testing"
)

// A server reads the register from many requests at once while a write
// lands: the index is taken under the register's lock and the write under
// the store's, so every reader sees the register at one commit or the next
// and never half of one, and the race detector finds nothing.
func TestReadsDuringAWriteSeeOneCommitOrTheNext(t *testing.T) {
	b := newBench(t)
	mustPut(t, b, dana, control("AC-00"))
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				ix, err := b.Index()
				if err != nil {
					errs <- err
					return
				}
				if n := len(ix.Rows(KindControl)); n < 1 || n > 11 {
					errs <- fmt.Errorf("an index of %d controls", n)
				}
				if _, _, err := b.List(KindControl, 0, 5); err != nil {
					errs <- err
				}
			}
		}()
	}
	for i := 1; i <= 10; i++ {
		if _, err := b.Put(dana, "one more control", control(fmt.Sprintf("AC-%02d", i))); err != nil {
			t.Fatal(err)
		}
	}
	// And the ledger of surfaces, which every surface's init writes.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			Offer("concurrent-test", SurfaceCLI, fmt.Sprintf("quilzo concurrent-%d", i))
			_ = Modules()
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	ix, err := b.Rebuild()
	if err != nil || len(ix.Rows(KindControl)) != 11 {
		t.Errorf("after the writes the register holds %d controls: %v", len(ix.Rows(KindControl)), err)
	}
	ledgerMu.Lock()
	delete(ledger, "concurrent-test")
	ledgerMu.Unlock()
}
