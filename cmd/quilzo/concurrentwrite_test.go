// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/mcp"
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

// writePagesAtOnce calls write_page from n agents at once, each through a
// server of its own as /mcp builds one per request, and returns what each
// was told: "" for a write that landed.
func writePagesAtOnce(t *testing.T, root string, n int, args func(i int) map[string]any) []*mcp.Error {
	t.Helper()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	refused := make([]*mcp.Error, n)
	var wg sync.WaitGroup
	for i := range n {
		srv := buildMCP(root, s, asAdmin(fmt.Sprintf("agent%d", i)), t.TempDir())
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, refused[i] = callTool(t, srv, "quilzo_write", "write_page", args(i))
		}()
	}
	wg.Wait()
	return refused
}

// Ten agents writing ten different pages at once all land.
//
// write_page read the draft itself and wrote against what it read, so the
// first write to land made every other one in flight fail with "the draft
// moved while you were working", naming a page it had not touched, and
// marked retryable:false, so a well-behaved client gave up: one write of
// ten, from agents whose work did not overlap at all.
func TestConcurrentWritePagesToDifferentPagesAllLand(t *testing.T) {
	root, _ := concurrentRig(t)
	const writers = 10
	refused := writePagesAtOnce(t, root, writers, func(i int) map[string]any {
		return map[string]any{"page": fmt.Sprintf("conc-%d", i),
			"fields": map[string]any{"title": fmt.Sprintf("Page %d", i)}}
	})
	for i, r := range refused {
		if r != nil {
			t.Errorf("writer %d, whose page nobody else wrote, was refused: %s %v", i, r.Message, r.Data)
		}
	}
	names := draftNames(t, root)
	if len(names) != writers+1 {
		t.Fatalf("the draft holds %d pages, not %d: %s", len(names), writers+1, strings.Join(names, ", "))
	}
}

// Agents that really do collide, on one field of one page, are told to read
// again and retry, which is now true: each call reads the draft itself.
//
// Every refusal carried retryable:false, beside a comment saying a retry
// against the same stale base fails forever. There is no stale base to
// retry against: the next call reads the draft as it is then.
func TestAWritePageConflictSaysItCanBeRetried(t *testing.T) {
	root, _ := concurrentRig(t)
	refused := writePagesAtOnce(t, root, 10, func(i int) map[string]any {
		return map[string]any{"page": "index",
			"fields": map[string]any{"title": fmt.Sprintf("Home, as agent %d has it", i)}}
	})
	n := 0
	for i, r := range refused {
		if r == nil {
			continue
		}
		n++
		data, _ := r.Data.(map[string]any)
		if data["retryable"] != true {
			t.Errorf("writer %d was refused a write that would land if read and sent again, as not retryable: %s %v",
				i, r.Message, r.Data)
		}
		if !strings.Contains(r.Message, "again and send what you still mean to") {
			t.Errorf("writer %d is not told what to do before retrying: %s", i, r.Message)
		}
	}
	t.Logf("%d of 10 refused", n)
}

// Records written from the command line while pages are added keep every
// page and every record.
//
// `quilzo records add` and `delete` read the draft's tree, made their
// change to it, and only then took the ref lock to make the result the
// draft: so a page or a record that landed in between was not in the tree
// they wrote. Ten adds of pages beside ten adds of records left five or six
// of the ten pages and two to five of the ten records, and every one of the
// twenty exited 0. The agent interface, the admin and the content API
// already made the same change under the lock.
func TestRecordsWrittenBesidePagesKeepEveryOne(t *testing.T) {
	root, home := concurrentRig(t)
	if got, err := quilzoAt(t, home, root, "--json", "records", "add", "devices", "hostname=gone"); err != nil {
		t.Fatalf("%v\n%s", err, got)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := draftTree(s)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := collection.List(s, tree, "devices", collection.Query{})
	if err != nil || len(before) != 1 {
		t.Fatalf("the record to delete is not there: %v %v", before, err)
	}
	gone := before[0].ID

	const writers = 10
	var wg sync.WaitGroup
	failed := make([]string, 2*writers+1)
	for i := range writers {
		page := fileOf(t, fmt.Sprintf("r%d.json", i), fmt.Sprintf(`{"title":"Page %d"}`, i))
		wg.Add(2)
		go func() {
			defer wg.Done()
			if got, err := quilzoAt(t, home, root, "add", fmt.Sprintf("conc-%d=%s", i, page)); err != nil {
				failed[i] = fmt.Sprintf("add %d: %v\n%s", i, err, got)
			}
		}()
		go func() {
			defer wg.Done()
			if got, err := quilzoAt(t, home, root, "records", "add", "devices", fmt.Sprintf("hostname=h%d", i)); err != nil {
				failed[writers+i] = fmt.Sprintf("records add %d: %v\n%s", i, err, got)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if got, err := quilzoAt(t, home, root, "records", "delete", "devices", gone); err != nil {
			failed[2*writers] = fmt.Sprintf("records delete: %v\n%s", err, got)
		}
	}()
	wg.Wait()
	for _, f := range failed {
		if f != "" {
			t.Errorf("a write with nothing in common with the others failed: %s", f)
		}
	}

	names := strings.Join(draftNames(t, root), ",")
	want := []string{"index"}
	for i := range writers {
		want = append(want, fmt.Sprintf("conc-%d", i))
	}
	sort.Strings(want)
	if names != strings.Join(want, ",") {
		t.Errorf("the draft holds the pages %s, not %s", names, strings.Join(want, ","))
	}
	if tree, err = draftTree(s); err != nil {
		t.Fatal(err)
	}
	recs, _, err := collection.List(s, tree, "devices", collection.Query{})
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, r := range recs {
		hosts = append(hosts, fmt.Sprint(r.Fields["hostname"]))
	}
	sort.Strings(hosts)
	var wantHosts []string
	for i := range writers {
		wantHosts = append(wantHosts, fmt.Sprintf("h%d", i))
	}
	if strings.Join(hosts, ",") != strings.Join(wantHosts, ",") {
		t.Errorf("the draft holds the records %s, not %s", strings.Join(hosts, ","), strings.Join(wantHosts, ","))
	}
}

// Pages imported into a store with nothing in it yet, while others add
// pages, keep every page.
//
// `quilzo import` took the draft ref as its base, and a store with no draft
// has none, which SaveDraftFrom reads as "whatever the draft is now": so
// on a new store, an import beside five adds wrote its pages over whichever
// add had landed while it converted the file, and that add had exited 0.
func TestImportsIntoANewStoreKeepThePagesAddedBesideThem(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("QUILZO_TOKEN", "")
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	const writers = 5
	var wg sync.WaitGroup
	failed := make([]string, 2*writers)
	var want []string
	for i := range writers {
		md := fileOf(t, fmt.Sprintf("e%d.md", i), fmt.Sprintf("---\ntitle: Imported %d\nslug: imp-%d\n---\nbody\n", i, i))
		page := fileOf(t, fmt.Sprintf("a%d.json", i), fmt.Sprintf(`{"title":"Added %d"}`, i))
		want = append(want, fmt.Sprintf("add-%d", i), fmt.Sprintf("imp-%d", i))
		wg.Add(2)
		go func() {
			defer wg.Done()
			if got, err := quilzoAt(t, home, root, "import", md); err != nil {
				failed[i] = fmt.Sprintf("import %d: %v\n%s", i, err, got)
			}
		}()
		go func() {
			defer wg.Done()
			if got, err := quilzoAt(t, home, root, "add", fmt.Sprintf("add-%d=%s", i, page)); err != nil {
				failed[writers+i] = fmt.Sprintf("add %d: %v\n%s", i, err, got)
			}
		}()
	}
	wg.Wait()
	for _, f := range failed {
		if f != "" {
			t.Errorf("a write with nothing in common with the others failed: %s", f)
		}
	}
	sort.Strings(want)
	if names := strings.Join(draftNames(t, root), ","); names != strings.Join(want, ",") {
		t.Fatalf("the draft holds %s, not %s", names, strings.Join(want, ","))
	}
}

// A page saved while the assistant thinks, on a store with nothing in it
// yet, is kept when the proposal is written.
//
// `quilzo assist` takes the draft as its base before the model is asked, to
// guard the seconds the model takes. A store with no draft has no base,
// which the write took as "whatever the draft is by then", so a page saved
// in exactly that window was written over by the proposal.
func TestAnAssistOnANewStoreKeepsAPageSavedWhileItThought(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("QUILZO_TOKEN", "")
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	about := fileOf(t, "about.json", `{"title":"About"}`)
	model := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// Somebody else's save, made while the model is thinking.
		if got, err := quilzoAt(t, home, root, "add", "about="+about); err != nil {
			t.Errorf("the save made while the model thought was refused: %v\n%s", err, got)
		}
		reply, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": `{"pages":{"pricing":{"title":"Prices"}}}`}}}})
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(reply)
	}))
	t.Cleanup(model.Close)
	t.Setenv("QUILZO_MODEL_URL", model.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")

	if err := cmdAssist(root, []string{"write the prices", "--author", "dana", "--templates", filepath.Join(t.TempDir(), "tpl")}); err != nil {
		t.Fatalf("a proposal touching nothing the other save did was refused: %v", err)
	}
	if names := strings.Join(draftNames(t, root), ","); names != "about,pricing" {
		t.Fatalf("the draft holds %s, not about and pricing: the page saved while the model thought was lost", names)
	}
}

// A page added while the demonstration installs is not written over.
//
// `quilzo demo` found the store empty, then wrote its media, types, forms
// and the rest, and only then its pages, with an empty base: "whatever the
// draft is by then". A `quilzo add` run beside it landed in that time every
// time it was tried, exited 0, and its page was gone. Either may go first;
// what must not happen is an add that says it wrote a page nobody can find.
func TestAnAddBesideTheDemonstrationIsNotWrittenOver(t *testing.T) {
	for round := range 3 {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		t.Setenv("QUILZO_TOKEN", "")
		if w == nil {
			w = out.New(false)
		}
		root := t.TempDir() + "/st"
		if err := cmdInit(root); err != nil {
			t.Fatal(err)
		}
		page := fileOf(t, "mine.json", `{"title":"Mine"}`)
		var wg sync.WaitGroup
		var demoErr, addErr error
		var demoSaid, addSaid string
		wg.Add(2)
		go func() {
			defer wg.Done()
			demoSaid, demoErr = quilzoAt(t, home, root, "demo", "--publish=false",
				"--templates", filepath.Join(root, "tpl"), "--examples", filepath.Join(root, "ex"))
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(round*20) * time.Millisecond)
			addSaid, addErr = quilzoAt(t, home, root, "add", "mine="+page)
		}()
		wg.Wait()
		if demoErr != nil && addErr != nil {
			t.Fatalf("round %d: neither landed:\n%s\n%s", round, demoSaid, addSaid)
		}
		names := "," + strings.Join(draftNames(t, root), ",") + ","
		if addErr == nil && !strings.Contains(names, ",mine,") {
			t.Errorf("round %d: the add exited 0 and its page is not in the draft (%s)", round, names)
		}
		if demoErr == nil && !strings.Contains(names, ",index,") {
			t.Errorf("round %d: the demonstration said it was installed and its pages are not in the draft (%s)", round, names)
		}
	}
}
