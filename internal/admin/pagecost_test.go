// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/taxonomy"
)

// allocated is how many bytes f allocates, all goroutines together.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// A screen that reads the whole site does not read it again for each person
// looking at it.
//
// Every admin screen decoded the store on every request: the Structure
// screen read the draft and then the live site, each page read from disk
// twice, hashed and unmarshalled, about 75 MB for a store of two thousand
// pages. Each request in flight held its own copy, so memory rose by some
// twenty megabytes per request at once, and a burst against the admin, the
// API and the agent interface, which share the one process, ended with it
// killed for memory at twelve gigabytes. The public site had decoded once
// per commit all along (internal/public/pagecache.go).
//
// The bar is a decode of the store once, measured here on the same store
// opened afresh: requests at once, between them, may not cost that much
// each, or every one of them is still reading the site for itself.
func TestAScreenDoesNotDecodeTheWholeStoreForEachRequest(t *testing.T) {
	srv, tok := setup(t)
	pages := map[string]any{}
	for i := 0; i < 2000; i++ {
		pages[fmt.Sprintf("p%04d", i)] = map[string]any{
			"title": fmt.Sprintf("Page %d", i),
			"body":  strings.Repeat("Some words of body text. ", 80),
			"tags":  []any{"news", "local"},
		}
	}
	if _, err := site.SaveDraft(srv.Store, pages, "two thousand pages", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(srv.Store, ""); err != nil {
		t.Fatal(err)
	}
	srv.Structure = &Structure{
		Vocabularies: func() (*taxonomy.Set, error) { return &taxonomy.Set{}, nil },
		Menus:        func() (*menu.Set, error) { return &menu.Set{}, nil },
	}
	if w := get(t, srv, "/structure", tok); w.Code != http.StatusOK {
		t.Fatalf("the Structure screen answered %d", w.Code)
	}

	fresh, err := store.Open(srv.Store.Root())
	if err != nil {
		t.Fatal(err)
	}
	once := allocated(func() {
		if _, err := site.PagesAt(fresh, site.RefDraft); err != nil {
			t.Fatal(err)
		}
	})

	const together = 8
	each := allocated(func() {
		var wg sync.WaitGroup
		for i := 0; i < together; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				get(t, srv, "/structure", tok)
			}()
		}
		wg.Wait()
	}) / together
	t.Logf("one decode of the store: %.1f MB; each of %d requests at once: %.1f MB",
		float64(once)/1e6, together, float64(each)/1e6)
	if each >= once {
		t.Errorf("each request to the Structure screen allocated %.1f MB, and decoding "+
			"the store once is %.1f MB: every request is reading the whole site for itself",
			float64(each)/1e6, float64(once)/1e6)
	}
}
