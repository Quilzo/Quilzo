// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/vault"
)

func titleOf(t *testing.T, pages map[string]any, name string) string {
	t.Helper()
	body, ok := pages[name].(map[string]any)
	if !ok {
		t.Fatalf("%s is not there: %v", name, pages)
	}
	title, _ := body["title"].(string)
	return title
}

// A save is read at once, and so is a publish: the key is the commit the
// ref names, read afresh on every call, so a write that moves the ref is a
// different key and nothing remembered for the old one can answer.
func TestNoReadIsStaleAfterASaveOrAPublish(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "First"}}, "first", "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{RefDraft, RefLive} {
		got, err := PagesAt(s, ref)
		if err != nil {
			t.Fatal(err)
		}
		if title := titleOf(t, got, "index"); title != "First" {
			t.Fatalf("%s read %q", ref, title)
		}
	}

	if _, err := SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Second"},
		"about": map[string]any{"title": "About"}}, "second", "t"); err != nil {
		t.Fatal(err)
	}
	draft, err := PagesAt(s, RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if title := titleOf(t, draft, "index"); title != "Second" {
		t.Errorf("the draft read %q after a save of %q", title, "Second")
	}
	if _, ok := draft["about"]; !ok {
		t.Error("a page added by the save is not in the draft")
	}
	live, err := PagesAt(s, RefLive)
	if err != nil {
		t.Fatal(err)
	}
	if title := titleOf(t, live, "index"); title != "First" {
		t.Errorf("the live site read %q before anything was published", title)
	}

	if _, err := Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	live, err = PagesAt(s, RefLive)
	if err != nil {
		t.Fatal(err)
	}
	if title := titleOf(t, live, "index"); title != "Second" {
		t.Errorf("the live site read %q after %q was published", title, "Second")
	}
}

// Callers change what they are given: the editor adds the page it is saving
// to the map it read and writes the map back. One caller's change is never
// what the next one reads.
func TestWhatOneCallerChangesTheNextDoesNotRead(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home", "tags": []any{"a", "b"},
			"hero": map[string]any{"alt": "A view"}}}, "first", "t"); err != nil {
		t.Fatal(err)
	}
	first, err := PagesAt(s, RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	body := first["index"].(map[string]any)
	body["title"] = "Changed"
	body["tags"].([]any)[0] = "changed"
	body["hero"].(map[string]any)["alt"] = "changed"
	first["added"] = map[string]any{"title": "Added"}
	delete(first, "index")

	second, err := PagesAt(s, RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := second["added"]; ok {
		t.Error("a page one caller added to its map is in the next caller's")
	}
	again := second["index"].(map[string]any)
	if again["title"] != "Home" || again["tags"].([]any)[0] != "a" ||
		again["hero"].(map[string]any)["alt"] != "A view" {
		t.Errorf("one caller's edits reached the next: %v", again)
	}
}

// A commit is decoded once, however many ask for it at once: the rest wait
// for that one and are each given a copy, which is a fraction of a decode.
// Measured, because sharing is the whole point and a memo that every caller
// misses looks exactly like one that works.
func TestACommitIsDecodedOnceForEverybodyAskingAtOnce(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{}
	for i := 0; i < 500; i++ {
		pages[fmt.Sprintf("p%03d", i)] = map[string]any{
			"title": fmt.Sprintf("Page %d", i),
			"body":  strings.Repeat("Some words of body text. ", 80)}
	}
	cid, err := SaveDraft(s, pages, "five hundred pages", "t")
	if err != nil {
		t.Fatal(err)
	}

	measure := func(f func()) uint64 {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		f()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	const together = 8
	all := measure(func() {
		var wg sync.WaitGroup
		for i := 0; i < together; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if got, err := PagesAt(s, cid); err != nil || len(got) != len(pages) {
					t.Errorf("%d pages, %v", len(got), err)
				}
			}()
		}
		wg.Wait()
	})
	// A second store on the directory is a key of its own, so this is a
	// decode of the same commit from the disk.
	other, err := store.Open(s.Root())
	if err != nil {
		t.Fatal(err)
	}
	once := measure(func() {
		if _, err := PagesAt(other, cid); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("one decode: %.1f MB; %d callers at once, all told: %.1f MB",
		float64(once)/1e6, together, float64(all)/1e6)
	if all >= 2*once {
		t.Errorf("%d callers at once allocated %.1f MB between them and one decode is "+
			"%.1f MB: they decoded it each", together, float64(all)/1e6, float64(once)/1e6)
	}
}

// A store without the key is not handed what a store with it decrypted,
// although both are opened on the same directory: the store, not its
// directory, is the key, because the key is what decides what may be read.
func TestAStoreWithoutTheKeyIsNotHandedWhatOneWithItRead(t *testing.T) {
	dir := t.TempDir()
	keyed, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := vault.NewKeyring("k1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keyed.WithKeys(kr)
	if _, err := SaveDraft(keyed, map[string]any{
		"index": map[string]any{"title": "Unannounced"}}, "first", "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := PagesAt(keyed, RefDraft); err != nil {
		t.Fatal(err)
	}
	keyless, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := PagesAt(keyless, RefDraft); err == nil {
		t.Errorf("a store with no key read the encrypted draft: %v", got)
	}
}

// A read that failed is not remembered: the object that was missing can be
// put back, a key can be supplied, and the next read must see it.
func TestAFailedReadIsNotRemembered(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cid, err := SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home"}}, "first", "t")
	if err != nil {
		t.Fatal(err)
	}
	ids, err := PageIDsAt(s, cid)
	if err != nil {
		t.Fatal(err)
	}
	oid := ids["index"]
	path := filepath.Join(s.Root(), "objects", oid[:2], oid[2:])
	aside := path + ".aside"
	if err := os.Rename(path, aside); err != nil {
		t.Fatal(err)
	}
	if _, err := PagesAt(s, cid); err == nil {
		t.Fatal("a commit with a page missing read without an error")
	}
	if err := os.Rename(aside, path); err != nil {
		t.Fatal(err)
	}
	got, err := PagesAt(s, cid)
	if err != nil {
		t.Fatalf("the page was put back and the read still failed: %v", err)
	}
	if title := titleOf(t, got, "index"); title != "Home" {
		t.Errorf("read %q", title)
	}
}
