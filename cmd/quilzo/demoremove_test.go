// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/demo"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/shield"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/taxonomy"
)

// installedDemo is a store with the demonstration installed and published,
// and the folders its template and examples went to.
func installedDemo(t *testing.T) (root, tpl, ex string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	w = out.New(false)
	base := t.TempDir()
	root = filepath.Join(base, "st")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	tpl = filepath.Join(base, "templates")
	ex = filepath.Join(base, "examples")
	if err := cmdDemo(root, []string{"--templates", tpl, "--examples", ex}); err != nil {
		t.Fatal(err)
	}
	return root, tpl, ex
}

func gone(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	return errors.Is(err, fs.ErrNotExist)
}

func pagesIn(t *testing.T, root, ref string) map[string]any {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if s.GetRef(ref) == "" {
		return map[string]any{}
	}
	pages, err := site.PagesAt(s, ref)
	if err != nil {
		t.Fatal(err)
	}
	return pages
}

func recordsIn(t *testing.T, root, coll string) []collection.Record {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := draftTree(s)
	if err != nil {
		t.Fatal(err)
	}
	recs, _, err := collection.List(s, tree, coll, collection.Query{})
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// addOwnPage drafts a page of a person's own, says who wrote it, and
// publishes the draft, as somebody building their site would.
func addOwnPage(t *testing.T, root, tpl, name string, body map[string]any) {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := draftPages(root)
	if err != nil {
		t.Fatal(err)
	}
	pages[name] = body
	if err := saveDraft(root, s, pages, "our page", "rae", ""); err != nil {
		t.Fatal(err)
	}
	publishOurs(t, root, tpl, name)
}

func publishOurs(t *testing.T, root, tpl string, pages ...string) {
	t.Helper()
	for _, name := range pages {
		if err := cmdProvenance(root, []string{"set", name, "--source", "humanEdits", "--author", "rae"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdPublish(root, []string{"--templates", tpl}); err != nil {
		t.Fatal(err)
	}
}

// Installed and taken straight back out, the store is as empty as a new
// one: nothing of the demonstration is left in it or beside it, the live site
// no longer serves it, the settings are what they were — and so it can be
// installed again.
func TestTheDemonstrationComesBackOutWhole(t *testing.T) {
	root, tpl, ex := installedDemo(t)
	d := demo.Marginalia()
	before := pagesIn(t, root, site.RefDraft)
	if len(before) == 0 || len(pagesIn(t, root, site.RefLive)) == 0 {
		t.Fatal("the demonstration installed no pages, so there is nothing to test")
	}

	// Without --yes it says what it would do, and writes nothing at all.
	listing, _ := os.ReadDir(root)
	if err := removeDemo(root, false, resolveCaller(root, "")); err != nil {
		t.Fatal(err)
	}
	if len(pagesIn(t, root, site.RefDraft)) != len(before) || gone(t, demoManifestPath(root)) {
		t.Fatal("asking what removal would do removed something")
	}
	if after, _ := os.ReadDir(root); len(after) != len(listing) {
		t.Error("asking what removal would do wrote into the store")
	}

	if err := removeDemo(root, true, resolveCaller(root, "")); err != nil {
		t.Fatal(err)
	}
	if got := pagesIn(t, root, site.RefDraft); len(got) != 0 {
		t.Errorf("pages left in the draft: %v", keysOf(got))
	}
	if got := pagesIn(t, root, site.RefLive); len(got) != 0 {
		t.Errorf("the live site still serves %v", keysOf(got))
	}
	for name := range d.Records {
		if got := recordsIn(t, root, name); len(got) != 0 {
			t.Errorf("%d record(s) left in %s", len(got), name)
		}
	}
	types, err := schema.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range d.Types {
		if _, ok := types.Registry.Get(typ.Name); ok {
			t.Errorf("type %s is left", typ.Name)
		}
	}
	if len(types.Collections) != 0 || len(types.Bound) != 0 {
		t.Errorf("bindings left: %v %v", types.Collections, types.Bound)
	}
	listings, _ := loadListings(root)
	forms, _ := loadForms(root)
	menus, _ := loadMenus(root)
	vocab := &taxonomy.Set{}
	_ = loadJSON(vocabPath(root), vocab)
	if len(listings.Listings)+len(forms.Forms)+len(menus.Menus)+len(vocab.Vocabularies) != 0 {
		t.Errorf("left: %d listings, %d forms, %d menus, %d vocabularies",
			len(listings.Listings), len(forms.Forms), len(menus.Menus), len(vocab.Vocabularies))
	}
	if !gone(t, brandPath(root)) {
		t.Error("the claim rules are left")
	}
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	if files, _ := lib.List(); len(files) != 0 {
		t.Errorf("%d image(s) left in the library", len(files))
	}
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range demoSettings {
		def, _ := config.Lookup(key)
		if cfg.Raw(key) != def.Default {
			t.Errorf("%s is %q, not back to %q", key, cfg.Raw(key), def.Default)
		}
	}
	for _, rp := range d.Research {
		if !gone(t, filepath.Join(researchStore(root).Dir, rp.Name)) {
			t.Errorf("the research project %s is left", rp.Name)
		}
	}
	for _, path := range []string{tpl, ex, demoManifestPath(root)} {
		if !gone(t, path) {
			t.Errorf("%s is left", path)
		}
	}
	evs, _ := audit.Read(auditPath(root))
	found := false
	for _, e := range evs {
		found = found || (e.Action == "demo.remove" && e.Outcome == audit.Success && e.Detail["manifest"] == "none")
	}
	if !found {
		t.Error("the removal is not in the audit log")
	}

	// An emptied store takes the demonstration again.
	if err := cmdDemo(root, []string{"--templates", tpl, "--examples", ex}); err != nil {
		t.Fatalf("the demonstration does not install into the store it was removed from: %v", err)
	}
}

// What somebody changed or added is theirs, and stays: an edited page, a page
// and a record they wrote, an enquiry from the public, and a file they edited.
// So does what those still use: the type their record satisfies, the image it
// shows, the template and the name their pages render with, the vocabulary
// they are tagged from — and their pages are told apart from records even
// when a page's name has a slash in it.
func TestWhatSomebodyChangedOrAddedStays(t *testing.T) {
	root, tpl, ex := installedDemo(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := draftPages(root)
	if err != nil {
		t.Fatal(err)
	}
	edited := ""
	for _, name := range keysOf(pages) {
		if body, ok := pages[name].(map[string]any); ok {
			if title, ok := body["title"].(string); ok {
				body["title"] = title + " (ours)"
				edited = name
				break
			}
		}
	}
	if edited == "" {
		t.Fatal("no demonstration page has a title to edit")
	}
	pages["blog/notes"] = map[string]any{"title": "Our notes", "body": "Written by us.",
		"terms": map[string]any{"materials": []any{"paper"}}}
	if err := saveDraft(root, s, pages, "our edits", "rae", ""); err != nil {
		t.Fatal(err)
	}
	products := recordsIn(t, root, "products")
	if len(products) == 0 {
		t.Fatal("the demonstration has no products")
	}
	ours := map[string]any{}
	for k, v := range products[0].Fields {
		ours[k] = v
	}
	ours["slug"], ours["name"] = "our-own-notebook", "Our own notebook"
	if _, err := putCheckedRecords(root, "products", []map[string]any{ours}, resolveCaller(root, "")); err != nil {
		t.Fatal(err)
	}
	image, _ := ours["image"].(string)
	publishOurs(t, root, tpl, edited, "blog/notes")

	subs, err := openSubmissions(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := subs.Put(form.Submission{ID: strings.Repeat("ab", 16), Form: "wholesale",
		At: time.Now().Unix(), Values: map[string]string{"name": "Asha"}}); err != nil {
		t.Fatal(err)
	}
	readme := filepath.Join(ex, "evolve", "README.txt")
	if err := os.WriteFile(readme, []byte("our notes on the example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := removeDemo(root, true, resolveCaller(root, "")); err != nil {
		t.Fatal(err)
	}

	for _, ref := range []string{site.RefDraft, site.RefLive} {
		left := pagesIn(t, root, ref)
		if len(left) != 2 {
			t.Errorf("%s holds %v; only the edited page and ours should be", ref, keysOf(left))
		}
		for _, want := range []string{edited, "blog/notes"} {
			if _, ok := left[want]; !ok {
				t.Errorf("%s lost %s", ref, want)
			}
		}
	}
	if got := recordsIn(t, root, "products"); len(got) != 1 || got[0].Fields["slug"] != "our-own-notebook" {
		t.Errorf("products left: %d; only the one somebody added should be", len(got))
	}
	types, err := schema.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if typ, ok := types.Collections["products"]; !ok {
		t.Error("the products collection lost its type while a record in it is left")
	} else if _, ok := types.Registry.Get(typ); !ok {
		t.Errorf("type %s went while a record still satisfies it", typ)
	}
	vocab := &taxonomy.Set{}
	_ = loadJSON(vocabPath(root), vocab)
	if _, ok := vocab.Get("materials"); !ok {
		t.Error("a vocabulary went while a page that stays is tagged from it")
	}
	forms, _ := loadForms(root)
	if len(forms.Forms) != 1 || forms.Forms[0].Name != "wholesale" {
		t.Errorf("forms left: %v; the one holding an enquiry should stay", forms.Forms)
	}
	if got, _ := subs.List("wholesale"); len(got) != 1 {
		t.Error("an enquiry from the public was lost")
	}
	if gone(t, filepath.Join(tpl, "page.html")) {
		t.Error("the template went while pages still render through it")
	}
	if cfg, _ := loadConfig(root); cfg.Raw("site.name") == "" {
		t.Error("the site's name went while pages still render with it")
	}
	if gone(t, readme) {
		t.Error("an example somebody edited was removed")
	}
	if !gone(t, filepath.Join(ex, "evolve", "judge.py")) {
		t.Error("an example nobody touched is left")
	}
	if image != "" {
		lib, err := openMedia(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lib.Stat(strings.TrimPrefix(image, "/media/")); err != nil {
			t.Errorf("the image a kept record shows was removed: %v", err)
		}
	}
	if gone(t, demoManifestPath(root)) {
		t.Fatal("the record of what is left was dropped, so a later removal cannot finish")
	}

	// Run again, it takes nothing more and fails at nothing.
	if err := removeDemo(root, true, resolveCaller(root, "")); err != nil {
		t.Fatalf("a second removal failed: %v", err)
	}
	if len(pagesIn(t, root, site.RefDraft)) != 2 {
		t.Error("a second removal took somebody's page")
	}
}

// Removing while the draft holds unpublished work is refused, because
// publishing the removal would publish that work too.
func TestUnpublishedWorkStopsTheRemoval(t *testing.T) {
	root, _, _ := installedDemo(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, _ := draftPages(root)
	pages["draft-only"] = map[string]any{"title": "Not ready", "body": "Half written."}
	if err := saveDraft(root, s, pages, "unfinished", "rae", ""); err != nil {
		t.Fatal(err)
	}
	draft := s.GetRef(site.RefDraft)
	if err := removeDemo(root, true, resolveCaller(root, "")); !errors.Is(err, errDraftAhead) {
		t.Fatalf("a removal over unpublished work answered %v", err)
	}
	if s.GetRef(site.RefDraft) != draft || gone(t, demoManifestPath(root)) {
		t.Error("a refused removal changed something")
	}
}

// A refused publish leaves the live site whole: what it reads beside the
// store is put back, and once publishing can go ahead the same command
// finishes the job.
func TestARefusedPublishPutsEverythingBack(t *testing.T) {
	root, _, _ := installedDemo(t)
	listingsBefore, _ := os.ReadFile(listingPath(root))
	p, _, err := shield.Apply(root, shield.Protection{Kind: shield.Freeze, Reason: "testing",
		By: "rae", Until: time.Now().Add(time.Hour)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := removeDemo(root, true, resolveCaller(root, "")); err == nil {
		t.Fatal("the removal reported success while publishing was frozen")
	}
	if after, _ := os.ReadFile(listingPath(root)); string(after) != string(listingsBefore) {
		t.Error("the listings were taken while the live site still shows them")
	}
	if len(pagesIn(t, root, site.RefLive)) == 0 {
		t.Error("the live site lost its pages")
	}
	if _, err := shield.Lift(root, p.ID, "rae", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := removeDemo(root, true, resolveCaller(root, "")); err != nil {
		t.Fatalf("the removal did not finish once publishing could: %v", err)
	}
	if len(pagesIn(t, root, site.RefLive)) != 0 || !gone(t, demoManifestPath(root)) {
		t.Error("the second run left the demonstration behind")
	}
}

// Things already gone are not waited for: taken by hand, they drop out of
// the record, and the store takes the demonstration again.
func TestWhatIsAlreadyGoneDropsOut(t *testing.T) {
	root, tpl, ex := installedDemo(t)
	set, _ := loadListings(root)
	_ = set.Remove("search")
	if err := saveJSON(listingPath(root), set); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(researchStore(root).Dir, "repeat-orders")); err != nil {
		t.Fatal(err)
	}
	if err := removeDemo(root, true, resolveCaller(root, "")); err != nil {
		t.Fatal(err)
	}
	if !gone(t, demoManifestPath(root)) {
		t.Error("the record outlived everything in it")
	}
	if err := cmdDemo(root, []string{"--templates", tpl, "--examples", ex}); err != nil {
		t.Fatalf("the store does not take the demonstration again: %v", err)
	}
}

// The site's icon is an image too.
func TestTheSitesIconStays(t *testing.T) {
	root, _, _ := installedDemo(t)
	m, err := trustedManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	icon := m.Media[0]
	if err := cmdConfig(root, []string{"set", "site.icon", icon}); err != nil {
		t.Fatal(err)
	}
	if err := removeDemo(root, true, resolveCaller(root, "")); err != nil {
		t.Fatal(err)
	}
	lib, _ := openMedia(root)
	if _, err := lib.Stat(icon); err != nil {
		t.Errorf("the site's icon was removed: %v", err)
	}
}

// A demo.json somebody changed is not acted on.
func TestAChangedRecordIsNotTrusted(t *testing.T) {
	root, _, _ := installedDemo(t)
	body, err := os.ReadFile(demoManifestPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	m["config"] = map[string]any{"publish.require_a11y": map[string]any{"was": "false", "set": "true"}}
	changed, _ := json.Marshal(m)
	if err := os.WriteFile(demoManifestPath(root), changed, 0o600); err != nil {
		t.Fatal(err)
	}
	pagesBefore := len(pagesIn(t, root, site.RefLive))
	if err := removeDemo(root, true, resolveCaller(root, "")); err == nil ||
		!strings.Contains(err.Error(), "not the record") {
		t.Fatalf("a changed record answered %v", err)
	}
	if len(pagesIn(t, root, site.RefLive)) != pagesBefore {
		t.Error("a changed record was acted on")
	}
}

// With --json, standard output is one document, the publishing included.
func TestTheRemovalSaysOneDocument(t *testing.T) {
	root, _, _ := installedDemo(t)
	r, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved, savedW := os.Stdout, w
	os.Stdout = pw
	w = out.New(true)
	runErr := removeDemo(root, true, resolveCaller(root, ""))
	pw.Close()
	os.Stdout, w = saved, savedW
	got, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatal(runErr)
	}
	var doc map[string]any
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("standard output is not one JSON document: %v\n%s", err, got)
	}
	if doc["published"] == "" || doc["kept"] == nil {
		t.Errorf("the document leaves out what happened: %s", got)
	}
}

// Taking the demonstration out is a person's act, and needs a record of it
// having been installed.
func TestRemovingTheDemonstrationIsAPersonsDecision(t *testing.T) {
	root, _, _ := installedDemo(t)
	model := *resolveCaller(root, "")
	model.Kind = audit.KindAI
	if err := removeDemo(root, true, &model); err == nil {
		t.Fatal("a model removed the demonstration")
	}
	if gone(t, demoManifestPath(root)) || len(pagesIn(t, root, site.RefDraft)) == 0 {
		t.Fatal("a refused removal removed something")
	}

	empty := t.TempDir()
	if err := cmdInit(empty); err != nil {
		t.Fatal(err)
	}
	if err := removeDemo(empty, true, resolveCaller(empty, "")); err == nil ||
		!strings.Contains(err.Error(), "no record") {
		t.Fatalf("a store with no demonstration answered %v", err)
	}
}

// The demonstration does not install twice, over anything somebody made,
// or over a template somebody already has.
func TestTheDemonstrationRefusesAStoreWithSomethingInIt(t *testing.T) {
	root, tpl, ex := installedDemo(t)
	err := cmdDemo(root, []string{"--templates", tpl, "--examples", ex})
	if err == nil || !strings.Contains(err.Error(), "already installed") {
		t.Fatalf("a second install answered %v", err)
	}

	mine := t.TempDir()
	if err := cmdInit(mine); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(menuPath(mine), map[string]any{"menus": []any{map[string]any{"name": "main", "label": "Main"}}}); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(mine, []string{"--templates", filepath.Join(mine, "tpl")}); err == nil {
		t.Fatal("the demonstration wrote over a menu somebody made")
	}

	theirs := t.TempDir()
	if err := cmdInit(theirs); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(theirs, "tpl")
	if err := os.MkdirAll(own, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(own, "page.html"), []byte("ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(theirs, []string{"--templates", own}); err == nil {
		t.Fatal("the demonstration wrote over somebody's template")
	}
	if b, _ := os.ReadFile(filepath.Join(own, "page.html")); string(b) != "ours" {
		t.Error("somebody's template was changed")
	}
}

// An install that stops part of the way still leaves the record, so what it
// did write can be taken back.
func TestAFailedInstallCanBeTakenBack(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	w = out.New(false)
	base := t.TempDir()
	root := filepath.Join(base, "st")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(base, "examples")
	if err := os.WriteFile(blocked, []byte("a file where a folder goes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"--templates", filepath.Join(base, "templates"), "--examples", blocked}); err == nil {
		t.Fatal("the install went ahead with nowhere to put its examples")
	}
	if err := removeDemo(root, true, resolveCaller(root, "")); err != nil {
		t.Fatalf("what a failed install wrote cannot be taken back: %v", err)
	}
	if len(pagesIn(t, root, site.RefDraft)) != 0 {
		t.Error("a failed install's pages were left")
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
