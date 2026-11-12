// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// concurrentRig is a store with one page in its draft, run by its local
// operator with no token, and the home directory its commands run under.
func concurrentRig(t *testing.T) (root, home string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("QUILZO_TOKEN", "")
	if w == nil {
		w = out.New(false)
	}
	old := flagToken
	flagToken = ""
	t.Cleanup(func() { flagToken = old })
	root = t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdAdd(root, []string{"index=" + fileOf(t, "index.json", `{"title":"Home","body":"Welcome."}`)}); err != nil {
		t.Fatal(err)
	}
	return root, home
}

// draftNames is every page in the draft, sorted.
func draftNames(t *testing.T, root string) []string {
	t.Helper()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	return sortedKeys(pages)
}

// quilzoAt runs the command line itself, as its own process, on a store:
// what a script, a CI job and a person's terminal each are.
func quilzoAt(t *testing.T, home, root string, args ...string) (string, error) {
	cmd := exec.Command(os.Args[0], append([]string{"quilzo-main", "--root", root}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "QUILZO_TOKEN=")
	b, err := cmd.CombinedOutput()
	return string(b), err
}

// Ten `quilzo add` at once, each adding a page of its own, all land.
//
// Each read the draft, added its page and wrote the whole set back with no
// base, the form SaveDraftFrom takes as "whatever the draft is now". So
// whichever wrote last dropped every page the others had added in between:
// ten exits of 0, ten "draft ... page(s)" lines, and two or three of the ten
// pages in the draft, with the next publish going out without the rest.
// Separate processes, because that is what collided: a script, a CI job and
// a person's terminal do not share a lock in memory, only the store's.
func TestConcurrentAddsAllLand(t *testing.T) {
	root, home := concurrentRig(t)

	const writers = 10
	var wg sync.WaitGroup
	failed := make([]string, writers)
	for i := range writers {
		page := fileOf(t, fmt.Sprintf("p%d.json", i), fmt.Sprintf(`{"title":"Page %d","body":"written by %d"}`, i, i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := quilzoAt(t, home, root, "add", fmt.Sprintf("conc-%d=%s", i, page)); err != nil {
				failed[i] = fmt.Sprintf("writer %d: %v\n%s", i, err, got)
			}
		}()
	}
	wg.Wait()

	names := draftNames(t, root)
	var missing []string
	for i := range writers {
		name := fmt.Sprintf("conc-%d", i)
		if i := sort.SearchStrings(names, name); i == len(names) || names[i] != name {
			missing = append(missing, name)
		}
	}
	// A refusal would at least have been told; a page missing after an exit
	// of 0 is the loss itself.
	for _, f := range failed {
		if f != "" {
			t.Errorf("an add with nothing in common with the others was refused: %s", f)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%d of %d concurrent adds are not in the draft (%s); it holds %s",
			len(missing), writers, strings.Join(missing, ", "), strings.Join(names, ", "))
	}
}

// A section edit keeps a page somebody saved while it was being made.
//
// The variant of the lost add: the section commands read the pages, made
// their change, and wrote back with the draft as it was at the write as
// their base, which is no check at all. The change runs between the read and
// the write, so a save made from inside it is exactly a save that lands in
// that window.
func TestASectionEditKeepsAPageSavedWhileItWasMade(t *testing.T) {
	root, _ := concurrentRig(t)
	err := editSections(root, "index", func(body any) (map[string]any, string, error) {
		if err := cmdAdd(root, []string{"about=" + fileOf(t, "about.json", `{"title":"About"}`)}); err != nil {
			t.Fatal(err)
		}
		next := map[string]any{}
		for k, v := range body.(map[string]any) {
			next[k] = v
		}
		next["title"] = "Home, edited"
		return next, "retitle index", nil
	})
	if err != nil {
		t.Fatalf("an edit to a page nobody else touched was refused: %v", err)
	}
	if names := draftNames(t, root); strings.Join(names, ",") != "about,index" {
		t.Fatalf("the draft holds %s; the page saved during the edit was lost", strings.Join(names, ", "))
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if got := pages["index"].(map[string]any)["title"]; got != "Home, edited" {
		t.Errorf("the edit itself did not land: index is titled %v", got)
	}
}

// A move run while others add pages keeps every one of them.
//
// The same read, change and write back as a section edit, with the base
// taken at the write; run beside ten adds, the move dropped whichever of
// them landed while it worked out what to rename.
func TestAMoveKeepsThePagesAddedWhileItRan(t *testing.T) {
	root, home := concurrentRig(t)
	if err := cmdAdd(root, []string{"old=" + fileOf(t, "old.json", `{"title":"Old"}`)}); err != nil {
		t.Fatal(err)
	}
	const writers = 10
	var wg sync.WaitGroup
	failed := make([]string, writers+1)
	for i := range writers {
		page := fileOf(t, fmt.Sprintf("m%d.json", i), fmt.Sprintf(`{"title":"Page %d"}`, i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := quilzoAt(t, home, root, "add", fmt.Sprintf("conc-%d=%s", i, page)); err != nil {
				failed[i] = fmt.Sprintf("add %d: %v\n%s", i, err, got)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if got, err := quilzoAt(t, home, root, "move", "old", "new"); err != nil {
			failed[writers] = fmt.Sprintf("move: %v\n%s", err, got)
		}
	}()
	wg.Wait()
	for _, f := range failed {
		if f != "" {
			t.Errorf("a write with nothing in common with the others was refused: %s", f)
		}
	}
	names := strings.Join(draftNames(t, root), ",")
	want := []string{"index", "new"}
	for i := range writers {
		want = append(want, fmt.Sprintf("conc-%d", i))
	}
	sort.Strings(want)
	if names != strings.Join(want, ",") {
		t.Fatalf("the draft holds %s, not %s", names, strings.Join(want, ","))
	}
}

// A feature installed while somebody adds a page keeps that page.
//
// The install reads the draft, then checks and writes the feature's types,
// forms, menus, hooks and assistants, and only then writes its pages back,
// with no base, so a page added in that time was dropped by the install's
// write. The webhooks file's lock is held here to stop the install between
// the two, once its types are written: the add lands exactly in the window.
func TestAFeatureInstallKeepsAPageAddedWhileItRan(t *testing.T) {
	root, home := concurrentRig(t)
	path := writePackage(t, func(p *feature.Package) {
		withoutAddress(p)
		p.Webhooks = append(p.Webhooks, feature.Webhook{URL: "https://hooks.example.com/samples", Note: "where samples are announced"})
	})
	unlock, err := atomicfile.Lock(hooksPath(root) + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- installFeatureFile(root, path, "", "", asAdmin("dana")) }()
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(10 * time.Millisecond) {
		if st, err := schema.Load(root); err == nil {
			if _, ok := st.Registry.Get("sample"); ok {
				break
			}
		}
		select {
		case err := <-done:
			unlock()
			t.Fatalf("the install finished before it reached its webhooks: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			unlock()
			t.Fatal("the install never wrote its types")
		}
	}
	if got, err := quilzoAt(t, home, root, "add", "about="+fileOf(t, "about.json", `{"title":"About"}`)); err != nil {
		unlock()
		t.Fatalf("the add was refused: %v\n%s", err, got)
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatalf("an install with nothing in common with the add was refused: %v", err)
	}
	if names := strings.Join(draftNames(t, root), ","); names != "about,index,samples" {
		t.Fatalf("the draft holds %s, not about, index and samples", names)
	}
}
