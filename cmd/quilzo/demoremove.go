// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/demo"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/research"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/taxonomy"
)

// Taking the demonstration back out.
//
// Somebody installs the demonstration to see the product working, and then
// wants their own site in the same store. Removing it by hand means finding a
// dozen pages and products, the listings, forms and menus, the types under
// them, the images, the template and the research project — and knowing which
// of those they have changed since and mean to keep.
//
// So the install writes down what it wrote (demo.json, beside the store), and
// `quilzo demo remove` takes back exactly that, each thing only while it is
// still what the demonstration put there. Anything somebody changed since is
// theirs now: kept, and listed. So is anything their own content still uses.
// Pages and records a person added, what the public sent through a form, and
// files somebody edited are never touched.
//
// # demo.json is not trusted on its own say
//
// It sits in the store, so whoever can write the store can write it. Its
// digest goes into the audit log when the install writes it, and a removal
// refuses a manifest whose digest is not the last one the log recorded. In a
// deployment where a separate account writes the log, that is a check the
// store's own account cannot forge. Beyond that, a removal only ever touches
// what this program's demonstration can have written: its four settings, its
// research projects by name, and its template and example files by name.
//
// # The live site never serves half a demonstration
//
// Listings, forms, menus and types apply to the live site the moment they
// change. So the draft's removal is published as that exact commit, through
// the same gates as `quilzo publish`, and if publishing is refused those
// changes are put back. Removing is refused while the draft holds work that is
// not published, because publishing the removal would publish it too.
//
// It says what it would do and changes nothing until it is run with --yes.

// demoManifestFormat is the manifest format this program reads and writes.
const demoManifestFormat = 1

func demoManifestPath(root string) string { return filepath.Join(root, "demo.json") }

// demoSettings are the only settings the demonstration changes, and so the
// only ones a removal puts back.
var demoSettings = []string{"site.base_url", "site.catalogue", "site.name", "ucp.catalogue"}

// demoTemplateFiles are the only files it writes into the template folder.
var demoTemplateFiles = []string{"page.html", "site.css"}

// demoManifest is what an install wrote.
type demoManifest struct {
	Format int       `json:"format"`
	Name   string    `json:"name"`
	At     time.Time `json:"at"`
	By     string    `json:"by"`

	// Tree is every path the demonstration wrote into the draft, its pages
	// and its records, with the object it wrote there. A path still holding
	// that object is the demonstration's; any other is somebody's edit.
	Tree map[string]string `json:"tree"`
	// Blocks are its content types, collection bindings, listings, forms and
	// menus, as "kind name", with the digest of each definition.
	Blocks map[string]string `json:"blocks"`
	// Bound is the type each of its pages is bound to.
	Bound map[string]string `json:"bound,omitempty"`
	// Vocabularies are its vocabularies, with the digest of each.
	Vocabularies map[string]string `json:"vocabularies,omitempty"`
	// Brand is the digest of the claim rules it wrote, when it wrote any.
	Brand string `json:"brand,omitempty"`
	// Media are the images it stored.
	Media []string `json:"media,omitempty"`
	// Config is each setting it changed.
	Config map[string]demoSetting `json:"config,omitempty"`
	// Templates and Examples are the folders outside the store it wrote into.
	Templates demoFolder `json:"templates"`
	Examples  demoFolder `json:"examples"`
	// Research is each project it started, with every file in its folder.
	Research map[string]map[string]string `json:"research,omitempty"`
}

// demoSetting is one setting the install changed: what it was, and what the
// install made it.
type demoSetting struct {
	Was string `json:"was"`
	Set string `json:"set"`
}

// demoFolder is files the install wrote into one folder on disk.
type demoFolder struct {
	Dir string `json:"dir,omitempty"`
	// Files are by slash-separated path under Dir, with their digests.
	Files map[string]string `json:"files,omitempty"`
	// Made are the folders the install created, under Dir ("." for Dir
	// itself): they go once empty, and folders somebody already had stay.
	Made []string `json:"made,omitempty"`
}

func (m *demoManifest) empty() bool {
	return len(m.Tree)+len(m.Blocks)+len(m.Bound)+len(m.Vocabularies)+len(m.Media)+
		len(m.Config)+len(m.Research)+len(m.Templates.Files)+len(m.Examples.Files) == 0 &&
		m.Brand == ""
}

func demoDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// blockDigest is the digest of a definition once it is canonical JSON, so the
// same definition read back from its file digests the same.
func blockDigest(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return demoDigest(raw)
	}
	b, _ := json.Marshal(v)
	return demoDigest(b)
}

func blockKey(kind, name string) string { return kind + " " + name }

// madeDirs makes dir and returns, relative to base, every folder that did not
// exist before: dir itself and any parents up to base.
func madeDirs(base, dir string) ([]string, error) {
	var made []string
	for d := dir; ; d = filepath.Dir(d) {
		rel, err := filepath.Rel(base, d)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			break
		}
		if _, err := os.Lstat(d); err == nil {
			break
		}
		made = append(made, filepath.ToSlash(rel))
		if rel == "." {
			break
		}
	}
	return made, os.MkdirAll(dir, 0o700)
}

// folderDigests is every file under dir with its digest, read through a root
// so nothing outside dir is read. Lock files are left out: they are how a
// store guards a write, not what it holds.
func folderDigests(dir string) (map[string]string, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := map[string]string{}
	err = fs.WalkDir(r.FS(), ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() || strings.HasSuffix(p, ".lock") {
			return nil
		}
		if !e.Type().IsRegular() {
			out[p] = "not a regular file"
			return nil
		}
		b, rerr := r.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		out[p] = demoDigest(b)
		return nil
	})
	return out, err
}

// saveDemoManifest writes the manifest and returns the digest the audit log
// records for it.
func saveDemoManifest(root string, m *demoManifest) (string, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := atomicfile.Write(demoManifestPath(root), b, 0o600); err != nil {
		return "", err
	}
	return demoDigest(b), nil
}

// recordDemo works out what the install wrote and saves it, returning the
// manifest's digest. It runs when the install finishes, and when it fails
// part of the way, so what a failed install left can be taken back too. m
// arrives holding what only the install knows: the media, settings and files
// it wrote.
func recordDemo(root string, s *store.Store, d *demo.Site, m *demoManifest) (string, error) {
	m.Format = demoManifestFormat
	m.Name = d.Name
	m.Tree = map[string]string{}
	if cid := s.GetRef(site.RefDraft); cid != "" {
		c, err := s.GetCommit(cid)
		if err != nil {
			return "", err
		}
		if m.Tree, err = s.GetNested(c.Tree); err != nil {
			return "", err
		}
	}

	st, _, err := featureState(root)
	if err != nil {
		return "", err
	}
	m.Blocks = map[string]string{}
	add := func(kind, name string) {
		if raw, ok := st.Current[feature.Ref{Kind: kind, Name: name}]; ok {
			m.Blocks[blockKey(kind, name)] = blockDigest(raw)
		}
	}
	for _, t := range d.Types {
		add("type", t.Name)
	}
	for name := range d.BindCollection {
		add("collection", name)
	}
	for _, l := range d.Listings {
		add("listing", l.Name)
	}
	for _, f := range d.Forms {
		add("form", f.Name)
	}
	if d.Menus != nil {
		for _, mn := range d.Menus.Menus {
			add("menu", mn.Name)
		}
	}
	types, err := schema.Load(root)
	if err != nil {
		return "", err
	}
	m.Bound = map[string]string{}
	for page, typ := range d.Bind {
		if types.Bound[page] == typ {
			m.Bound[page] = typ
		}
	}

	vocab := &taxonomy.Set{}
	if err := loadJSON(vocabPath(root), vocab); err != nil {
		return "", err
	}
	m.Vocabularies = map[string]string{}
	if d.Vocabularies != nil {
		for _, v := range d.Vocabularies.Vocabularies {
			if got, ok := vocab.Get(v.Name); ok {
				b, _ := json.Marshal(got)
				m.Vocabularies[v.Name] = blockDigest(b)
			}
		}
	}

	if len(d.ClaimRules.Terms) > 0 {
		if b, err := os.ReadFile(brandPath(root)); err == nil {
			m.Brand = demoDigest(b)
		}
	}

	rs := researchStore(root)
	m.Research = map[string]map[string]string{}
	for _, rp := range d.Research {
		files, err := folderDigests(filepath.Join(rs.Dir, rp.Name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		m.Research[rp.Name] = files
	}
	return saveDemoManifest(root, m)
}

// trustedManifest reads demo.json and checks it is the one the audit log
// last recorded.
func trustedManifest(root string) (*demoManifest, error) {
	body, err := os.ReadFile(demoManifestPath(root))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("there is no record of a demonstration installed in this store, " +
			"so there is nothing this can take back. A demonstration installed " +
			"before Quilzo kept that record is removed by hand, or by starting " +
			"again in an empty directory")
	}
	if err != nil {
		return nil, err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, fmt.Errorf("the audit log could not be read, and it is what shows "+
			"demo.json is the one the install wrote: %w", err)
	}
	want := ""
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.Action != "demo.install" && e.Action != "demo.remove" {
			continue
		}
		if d, ok := e.Detail["manifest"]; ok {
			want = d
			break
		}
	}
	if want == "" || want != demoDigest(body) {
		return nil, errBlocked{fmt.Errorf("%s is not the record the demonstration wrote: "+
			"its digest is not the one the audit log holds for it, so nothing in it is "+
			"trusted and nothing was removed", demoManifestPath(root))}
	}
	var m demoManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("%s could not be read: %w", demoManifestPath(root), err)
	}
	if m.Format != demoManifestFormat {
		return nil, fmt.Errorf("%s is format %d, and this program reads format %d",
			demoManifestPath(root), m.Format, demoManifestFormat)
	}
	return &m, nil
}

// demoInstallable refuses a store, or folders, already holding anything the
// install would write over.
//
// Content rather than refs: a store the demonstration was installed in and
// then removed from has refs pointing at empty trees, and is as empty as a
// new one.
func demoInstallable(root string, s *store.Store, d *demo.Site, tplDir, exDir string) error {
	if _, err := os.Lstat(demoManifestPath(root)); err == nil {
		return errors.New("the demonstration is already installed here.\n" +
			"  quilzo demo remove        says what taking it out would remove\n" +
			"  quilzo demo remove --yes  takes it out")
	}
	full := false
	for _, ref := range []string{site.RefDraft, site.RefLive} {
		tree, err := treeOf(s, ref)
		if err != nil {
			return err
		}
		paths, err := s.GetNested(tree)
		if err != nil {
			return err
		}
		full = full || len(paths) > 0
	}
	listings, err := loadListings(root)
	if err != nil {
		return err
	}
	forms, err := loadForms(root)
	if err != nil {
		return err
	}
	menus, err := loadMenus(root)
	if err != nil {
		return err
	}
	vocab := &taxonomy.Set{}
	if err := loadJSON(vocabPath(root), vocab); err != nil {
		return err
	}
	full = full || len(listings.Listings) > 0 || len(forms.Forms) > 0 ||
		len(menus.Menus) > 0 || len(vocab.Vocabularies) > 0
	if _, err := os.Lstat(brandPath(root)); err == nil && len(d.ClaimRules.Terms) > 0 {
		full = true
	}
	types, err := schema.Load(root)
	if err != nil {
		return err
	}
	for _, t := range d.Types {
		if _, taken := types.Registry.Get(t.Name); taken {
			full = true
		}
	}
	for page := range d.Bind {
		if _, taken := types.Bound[page]; taken {
			full = true
		}
	}
	for c := range d.BindCollection {
		if _, taken := types.Collections[c]; taken {
			full = true
		}
	}
	for _, rp := range d.Research {
		if _, err := os.Lstat(filepath.Join(researchStore(root).Dir, rp.Name)); err == nil {
			full = true
		}
	}
	if full {
		return errors.New(
			"this store already has content, and the demonstration would " +
				"write over the content types, listings, menus and forms that " +
				"share a name with its own.\n  Run it in an empty directory:\n" +
				"    mkdir shop && cd shop && quilzo init && quilzo demo")
	}
	for _, name := range demoTemplateFiles {
		if _, err := os.Lstat(filepath.Join(tplDir, name)); err == nil {
			return fmt.Errorf("%s already has a %s, which the demonstration would "+
				"write over.\n  Give it a folder of its own: quilzo demo --templates DIR",
				tplDir, name)
		}
	}
	for rel := range d.Examples {
		if _, err := os.Lstat(filepath.Join(exDir, filepath.FromSlash(rel))); err == nil {
			return fmt.Errorf("%s already has %s, which the demonstration would "+
				"write over.\n  Give it a folder of its own: quilzo demo --examples DIR",
				exDir, rel)
		}
	}
	return nil
}

// demoRemoval is what removing the demonstration would do, worked out
// against what the store holds now.
type demoRemoval struct {
	m           *demoManifest
	draft, live string // the commits this was worked out against

	paths   []string // tree paths to delete
	pages   []string // the pages among them
	records int
	left    int // pages left once they are gone

	unbind      []string // page bindings
	collections []string
	types       []string
	listings    []string
	forms       []string
	menus       []string
	vocab       []string
	brand       bool
	settings    []string
	research    []string
	media       []string
	templates   []string
	examples    []string

	// publish is whether the removal is published: whenever there is a live
	// site, which then shows exactly the draft once the removal is in it.
	publish bool

	keep []string     // what stays, and why
	kept demoManifest // what stays on record, for a later run
}

func (p *demoRemoval) keepf(format string, a ...any) {
	p.keep = append(p.keep, fmt.Sprintf(format, a...))
}

func treeOf(s *store.Store, ref string) (string, error) {
	cid := s.GetRef(ref)
	if cid == "" {
		return "", nil
	}
	c, err := s.GetCommit(cid)
	if err != nil {
		return "", err
	}
	return c.Tree, nil
}

// errDraftAhead is a draft holding work the live site does not have.
var errDraftAhead = errBlocked{errors.New(
	"the draft holds changes the live site does not have, and publishing the " +
		"removal would publish them too. Publish them first (quilzo publish), " +
		"then remove the demonstration")}

// planDemoRemoval works out the removal. It writes nothing.
func planDemoRemoval(root string, s *store.Store, m *demoManifest) (*demoRemoval, error) {
	p := &demoRemoval{m: m, draft: s.GetRef(site.RefDraft), live: s.GetRef(site.RefLive)}
	p.kept = demoManifest{Format: m.Format, Name: m.Name, At: m.At, By: m.By,
		Tree: map[string]string{}, Blocks: map[string]string{}, Bound: map[string]string{},
		Vocabularies: map[string]string{}, Config: map[string]demoSetting{},
		Research:  map[string]map[string]string{},
		Templates: demoFolder{Dir: m.Templates.Dir, Made: m.Templates.Made, Files: map[string]string{}},
		Examples:  demoFolder{Dir: m.Examples.Dir, Made: m.Examples.Made, Files: map[string]string{}}}

	draftTree, err := treeOf(s, site.RefDraft)
	if err != nil {
		return nil, err
	}
	liveTree, err := treeOf(s, site.RefLive)
	if err != nil {
		return nil, err
	}
	if p.draft == "" {
		draftTree = liveTree
	}
	now, err := s.GetNested(draftTree)
	if err != nil {
		return nil, err
	}
	live, err := s.GetNested(liveTree)
	if err != nil {
		return nil, err
	}

	// The draft may differ from the live site only by the demonstration's
	// own paths already taken out of it, by a removal whose publishing was
	// refused. Anything else is somebody's unpublished work.
	if p.live != "" {
		for path := range joinKeys(now, live) {
			d, inDraft := now[path]
			l := live[path]
			if inDraft && d == l {
				continue
			}
			if !inDraft && m.Tree[path] != "" && m.Tree[path] == l {
				continue
			}
			return nil, errDraftAhead
		}
	}

	rootEntries := map[string]string{}
	if draftTree != "" {
		if rootEntries, err = s.GetTree(draftTree); err != nil {
			return nil, err
		}
	}
	isPage := func(path string) bool {
		oid, atRoot := rootEntries[path]
		return atRoot && !s.IsTree(oid)
	}

	remaining := maps.Clone(now)
	for _, path := range slices.Sorted(maps.Keys(m.Tree)) {
		cur, ok := now[path]
		switch {
		case !ok:
			// Gone already: somebody removed it, which is what was wanted.
		case cur == m.Tree[path]:
			p.paths = append(p.paths, path)
			delete(remaining, path)
			if isPage(path) {
				p.pages = append(p.pages, path)
			} else {
				p.records++
			}
		default:
			p.kept.Tree[path] = m.Tree[path]
			if coll, id, isRecord := collection.IsCollectionPath(path); isRecord {
				p.keepf("record %s/%s: changed since it was installed", coll, short(id))
			} else {
				p.keepf("page %s: changed since it was installed", path)
			}
		}
	}
	p.publish = p.live != "" && !maps.Equal(remaining, live)

	// What is left once the removal is in: the draft, and so the live site.
	pagesLeft, recordsLeft, err := contentIn(s, remaining, isPage)
	if err != nil {
		return nil, err
	}
	p.left = len(pagesLeft)

	st, _, err := featureState(root)
	if err != nil {
		return nil, err
	}
	unchanged := func(kind, name string) bool {
		raw, ok := st.Current[feature.Ref{Kind: kind, Name: name}]
		return ok && blockDigest(raw) == m.Blocks[blockKey(kind, name)]
	}
	exists := func(kind, name string) bool {
		_, ok := st.Current[feature.Ref{Kind: kind, Name: name}]
		return ok
	}
	blocks := map[string][]string{}
	for key := range m.Blocks {
		kind, name, _ := strings.Cut(key, " ")
		blocks[kind] = append(blocks[kind], name)
	}
	for kind := range blocks {
		sort.Strings(blocks[kind])
	}
	keepBlock := func(kind, name, format string, a ...any) {
		p.kept.Blocks[blockKey(kind, name)] = m.Blocks[blockKey(kind, name)]
		p.keepf(kind+" "+name+": "+format, a...)
	}

	// Types, the pages bound to them and the collections typed by them.
	types, err := schema.Load(root)
	if err != nil {
		return nil, err
	}
	bound := maps.Clone(types.Bound)
	colls := maps.Clone(types.Collections)
	for _, page := range slices.Sorted(maps.Keys(m.Bound)) {
		if bound[page] != m.Bound[page] {
			continue
		}
		if _, still := remaining[page]; still {
			p.kept.Bound[page] = m.Bound[page]
			continue
		}
		p.unbind = append(p.unbind, page)
		delete(bound, page)
	}
	for _, name := range blocks["collection"] {
		if !exists("collection", name) {
			continue
		}
		if !unchanged("collection", name) {
			keepBlock("collection", name, "its type was changed since it was installed")
			continue
		}
		left := 0
		for path := range remaining {
			if c, _, ok := collection.IsCollectionPath(path); ok && c == name {
				left++
			}
		}
		if left > 0 {
			keepBlock("collection", name, "still holds %d record(s) the demonstration did not write", left)
			continue
		}
		p.collections = append(p.collections, name)
		delete(colls, name)
	}
	for _, name := range blocks["type"] {
		if !exists("type", name) {
			continue
		}
		if !unchanged("type", name) {
			keepBlock("type", name, "changed since it was installed")
			continue
		}
		var users []string
		for page, typ := range bound {
			if typ == name {
				users = append(users, "page "+page)
			}
		}
		for c, typ := range colls {
			if typ == name {
				users = append(users, "collection "+c)
			}
		}
		if len(users) > 0 {
			sort.Strings(users)
			keepBlock("type", name, "still used by %s", strings.Join(users, ", "))
			continue
		}
		p.types = append(p.types, name)
	}

	// Listings, forms and menus, unless a page that stays shows one.
	shown := map[string][]string{}
	for page, body := range pagesLeft {
		for _, name := range listing.On(body) {
			shown[blockKey("listing", name)] = append(shown[blockKey("listing", name)], page)
		}
		for _, name := range stringsUnder(body, "form", 0) {
			shown[blockKey("form", name)] = append(shown[blockKey("form", name)], page)
		}
	}
	for _, kind := range []string{"listing", "form", "menu"} {
		for _, name := range blocks[kind] {
			if !exists(kind, name) {
				continue
			}
			if !unchanged(kind, name) {
				keepBlock(kind, name, "changed since it was installed")
				continue
			}
			if by := shown[blockKey(kind, name)]; len(by) > 0 {
				sort.Strings(by)
				keepBlock(kind, name, "still shown by %s", strings.Join(by, ", "))
				continue
			}
			switch kind {
			case "listing":
				p.listings = append(p.listings, name)
			case "form":
				// What the public sent is personal data somebody is
				// answerable for, and the form is how it is read.
				if n, err := submissionsFor(root, name); err != nil {
					return nil, err
				} else if n > 0 {
					keepBlock(kind, name, "holds %d submission(s) from the public", n)
					continue
				}
				p.forms = append(p.forms, name)
			case "menu":
				p.menus = append(p.menus, name)
			}
		}
	}

	// Vocabularies, unless content that stays is tagged from one.
	vocab := &taxonomy.Set{}
	if err := loadJSON(vocabPath(root), vocab); err != nil {
		return nil, err
	}
	for _, name := range slices.Sorted(maps.Keys(m.Vocabularies)) {
		v, ok := vocab.Get(name)
		if !ok {
			continue
		}
		b, _ := json.Marshal(v)
		if blockDigest(b) != m.Vocabularies[name] {
			p.kept.Vocabularies[name] = m.Vocabularies[name]
			p.keepf("vocabulary %s: changed since it was installed", name)
			continue
		}
		var tagged []string
		for _, content := range []map[string]map[string]any{pagesLeft, recordsLeft} {
			for where, body := range content {
				if len(taxonomy.Of(body, name)) > 0 {
					tagged = append(tagged, where)
				}
			}
		}
		if len(tagged) > 0 {
			sort.Strings(tagged)
			p.kept.Vocabularies[name] = m.Vocabularies[name]
			p.keepf("vocabulary %s: still used by %s", name, strings.Join(tagged, ", "))
			continue
		}
		p.vocab = append(p.vocab, name)
	}

	// The claim rules.
	if m.Brand != "" {
		if b, err := os.ReadFile(brandPath(root)); err == nil {
			if demoDigest(b) == m.Brand {
				p.brand = true
			} else {
				p.kept.Brand = m.Brand
				p.keepf("the claim rules: changed since they were installed")
			}
		}
	}

	// Settings, back to what they were: only the demonstration's own, only
	// while nobody has set them since, only while nothing left depends on
	// them, and never to a value weaker than the shipped default.
	cfg, err := loadConfig(root)
	if err != nil {
		return nil, err
	}
	catalogue := cfg.Raw("site.catalogue")
	catalogueGone := slices.Contains(p.listings, catalogue) || !exists("listing", catalogue)
	for _, key := range demoSettings {
		set, ok := m.Config[key]
		if !ok {
			continue
		}
		def, known := config.Lookup(key)
		if !known {
			continue
		}
		keepSetting := func(format string, a ...any) {
			p.kept.Config[key] = set
			p.keepf("setting "+key+": "+format, a...)
		}
		switch {
		case cfg.Raw(key) != set.Set:
			keepSetting("changed since it was installed")
		case (key == "site.name" || key == "site.base_url") && p.left > 0:
			keepSetting("%d page(s) left still use it", p.left)
		case (key == "site.catalogue" || key == "ucp.catalogue") && !catalogueGone:
			keepSetting("the catalogue listing %s stays", catalogue)
		default:
			if weaker, _ := def.IsWeaker(set.Was); weaker {
				keepSetting("putting back %q would be weaker than the default", set.Was)
				continue
			}
			p.settings = append(p.settings, key)
		}
	}

	// Research projects, only the demonstration's own, unless somebody has
	// worked in one. The research folder itself must be a folder, not a link
	// somewhere else.
	rs := researchStore(root)
	ownProjects := map[string]bool{}
	for _, rp := range demo.Marginalia().Research {
		ownProjects[rp.Name] = true
	}
	researchDir := false
	if info, err := os.Lstat(rs.Dir); err == nil && info.IsDir() {
		researchDir = true
	}
	for _, name := range slices.Sorted(maps.Keys(m.Research)) {
		dir := filepath.Join(rs.Dir, name)
		info, err := os.Lstat(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if !ownProjects[name] || !research.ValidName(name) || !researchDir || err != nil || !info.IsDir() {
			p.kept.Research[name] = m.Research[name]
			p.keepf("research project %s: not one the demonstration can have made here", name)
			continue
		}
		now, err := folderDigests(dir)
		if err != nil || !maps.Equal(now, m.Research[name]) {
			p.kept.Research[name] = m.Research[name]
			p.keepf("research project %s: has work in it since it was installed", name)
			continue
		}
		p.research = append(p.research, name)
	}

	// Files outside the store. The template stays while any page is left to
	// render through it.
	if p.left > 0 {
		for _, rel := range slices.Sorted(maps.Keys(m.Templates.Files)) {
			p.kept.Templates.Files[rel] = m.Templates.Files[rel]
		}
		if len(m.Templates.Files) > 0 {
			p.keepf("the template in %s: %d page(s) left still render through it", m.Templates.Dir, p.left)
		}
	} else {
		p.templates = m.Templates.plan(demoTemplateFiles, &p.kept.Templates, p.keepf, "the template file")
	}
	var exampleNames []string
	for rel := range demo.Marginalia().Examples {
		exampleNames = append(exampleNames, rel)
	}
	p.examples = m.Examples.plan(exampleNames, &p.kept.Examples, p.keepf, "the example")

	// Images nothing left points at: not content, not the site's icon, not a
	// template file that stays. An image stays with its narrower copies when
	// anything uses any of them.
	used := map[string]bool{}
	for _, content := range []map[string]map[string]any{pagesLeft, recordsLeft} {
		for _, fields := range content {
			for _, id := range media.IDsIn(fields) {
				used[id] = true
			}
		}
	}
	if id, ok := media.IDIn(cfg.Raw("site.icon")); ok {
		used[id] = true
	}
	for rel := range p.kept.Templates.Files {
		for _, id := range m.Templates.idsIn(rel) {
			used[id] = true
		}
	}
	if len(m.Media) > 0 {
		lib, err := openMedia(root)
		if err != nil {
			return nil, err
		}
		for _, id := range m.Media {
			f, serr := lib.Stat(id)
			if serr != nil {
				continue
			}
			inUse := used[id]
			for _, r := range f.Renditions {
				inUse = inUse || used[r.ID]
			}
			if inUse {
				p.kept.Media = append(p.kept.Media, id)
				p.keepf("image %s: still used by the site", f.Name)
				continue
			}
			p.media = append(p.media, id)
		}
	}
	return p, nil
}

// contentIn is the pages and records at these tree paths: a page by its name,
// a record as collection/id.
func contentIn(s *store.Store, tree map[string]string, isPage func(string) bool) (
	pages, records map[string]map[string]any, err error) {

	pages, records = map[string]map[string]any{}, map[string]map[string]any{}
	for path, oid := range tree {
		if c, id, ok := collection.IsCollectionPath(path); ok {
			var r collection.Record
			if err := s.GetBlob(oid, &r); err != nil {
				return nil, nil, err
			}
			records[c+"/"+id] = r.Fields
			continue
		}
		if !isPage(path) {
			continue
		}
		var body any
		if err := s.GetBlob(oid, &body); err != nil {
			return nil, nil, err
		}
		m, _ := body.(map[string]any)
		if m == nil {
			m = map[string]any{}
		}
		pages[path] = m
	}
	return pages, records, nil
}

// stringsUnder collects every string held under key, at any depth.
func stringsUnder(v any, key string, depth int) []string {
	if depth > 16 {
		return nil
	}
	var out []string
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			if s, ok := vv.(string); ok && k == key && s != "" {
				out = append(out, s)
				continue
			}
			out = append(out, stringsUnder(vv, key, depth+1)...)
		}
	case []any:
		for _, item := range t {
			out = append(out, stringsUnder(item, key, depth+1)...)
		}
	}
	return out
}

// submissionsFor counts what the public sent through a form, without making
// the submissions folder when there is none.
func submissionsFor(root, name string) (int, error) {
	if _, err := os.Stat(submissionDir(root)); errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	subs, err := openSubmissions(root)
	if err != nil {
		return 0, err
	}
	got, err := subs.List(name)
	return len(got), err
}

func joinKeys(a, b map[string]string) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

// plan picks the files in this folder that go: those among the names this
// program writes there and still as the install wrote them. The rest stay on
// record in kept.
func (f demoFolder) plan(names []string, kept *demoFolder, keepf func(string, ...any), what string) []string {
	var gone []string
	known := map[string]bool{}
	for _, n := range names {
		known[n] = true
	}
	r, rerr := f.openRoot()
	if r != nil {
		defer r.Close()
	}
	for _, rel := range slices.Sorted(maps.Keys(f.Files)) {
		if rerr != nil || !known[rel] {
			kept.Files[rel] = f.Files[rel]
			keepf("%s %s: not one this program writes there", what, rel)
			continue
		}
		info, err := r.Lstat(filepath.FromSlash(rel))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			kept.Files[rel] = f.Files[rel]
			keepf("%s %s: no longer a plain file", what, rel)
			continue
		}
		b, err := r.ReadFile(filepath.FromSlash(rel))
		if err != nil || demoDigest(b) != f.Files[rel] {
			kept.Files[rel] = f.Files[rel]
			keepf("%s %s: changed since it was installed", what, rel)
			continue
		}
		gone = append(gone, rel)
	}
	return gone
}

// openRoot opens the folder for reading and removing within it only. A
// relative or missing folder opens nothing.
func (f demoFolder) openRoot() (*os.Root, error) {
	if f.Dir == "" || !filepath.IsAbs(f.Dir) {
		return nil, fmt.Errorf("%q is not a folder this program wrote", f.Dir)
	}
	return os.OpenRoot(f.Dir)
}

// reMediaID is a media id as it appears in a template or stylesheet.
var reMediaID = regexp.MustCompile(`[0-9a-f]{64}`)

// idsIn is every media id a file in this folder names.
func (f demoFolder) idsIn(rel string) []string {
	r, err := f.openRoot()
	if err != nil {
		return nil
	}
	defer r.Close()
	b, err := r.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		return nil
	}
	return reMediaID.FindAllString(string(b), -1)
}

// take removes the files planned, then the folders the install made once
// they are empty, all within the folder.
func (f demoFolder) take(files []string) (gone int) {
	r, err := f.openRoot()
	if err != nil {
		return 0
	}
	defer r.Close()
	for _, rel := range files {
		if r.Remove(filepath.FromSlash(rel)) == nil {
			gone++
		}
	}
	// Deepest first, and only while empty: Remove refuses a folder with
	// anything in it, which is the rule wanted.
	made := slices.Clone(f.Made)
	sort.Slice(made, func(i, j int) bool {
		return strings.Count(made[i], "/") > strings.Count(made[j], "/")
	})
	for _, rel := range made {
		if rel != "." && !strings.HasPrefix(rel, "..") {
			_ = r.Remove(filepath.FromSlash(rel))
		}
	}
	if slices.Contains(made, ".") {
		_ = os.Remove(f.Dir)
	}
	return gone
}

// demoRemove is `quilzo demo remove [--yes]`.
func demoRemove(root string, args []string) error {
	flags := flag.NewFlagSet("demo remove", flag.ContinueOnError)
	yes := flags.Bool("yes", false, "remove it; without this, only say what would go")
	dry := flags.Bool("dry-run", false, "only say what would go, even with --yes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return errors.New("usage: quilzo demo remove [--yes | --dry-run]")
	}
	return removeDemo(root, *yes && !*dry, resolveCaller(root, flagToken))
}

// removeDemo says what removing the demonstration would take, and with yes
// takes it.
func removeDemo(root string, yes bool, caller *Caller) error {
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return fmt.Errorf("the demonstration spans the whole site, so taking it out "+
			"takes the authority to publish it: %w", err)
	}
	if caller.Kind == audit.KindAI {
		return errors.New("the demonstration is removed by a person")
	}
	m, err := trustedManifest(root)
	if err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	p, err := planDemoRemoval(root, s, m)
	if err != nil {
		return err
	}
	if !yes {
		if w.JSON(p.summary(false, "", 0, 0)) {
			return nil
		}
		p.print(false)
		w.Human("\n  nothing has been removed. To remove it:\n    quilzo demo remove --yes\n")
		return nil
	}
	return p.apply(root, s, caller)
}

// sideFiles are the files beside the store a removal changes before it
// publishes, kept so a refused publish can put them back.
func sideFiles(root string) []string {
	return []string{filepath.Join(root, "types.json"), listingPath(root), formsPath(root),
		menuPath(root), vocabPath(root), brandPath(root)}
}

// apply carries the removal out.
func (p *demoRemoval) apply(root string, s *store.Store, caller *Caller) (err error) {
	m := p.m
	detail := map[string]string{"name": m.Name}
	wrote := false
	// Every way out after the first write is in the log, the failures too.
	defer func() {
		if !wrote {
			return
		}
		outcome := audit.Success
		if err != nil {
			outcome = audit.Failure
			detail["error"] = err.Error()
		}
		record(root, caller.auditRecord("demo.remove", "/", outcome, detail))
	}()

	// The draft first, against the commits the plan was worked out from.
	commit := p.draft
	if len(p.paths) > 0 {
		changes := make([]store.Change, 0, len(p.paths))
		for _, path := range p.paths {
			changes = append(changes, store.Change{Path: path, Delete: true})
		}
		err := s.WithRefLock(func() error {
			if s.GetRef(site.RefDraft) != p.draft || s.GetRef(site.RefLive) != p.live {
				return errors.New("the site changed while this was working, so nothing " +
					"was removed. Run it again")
			}
			base, err := treeOf(s, site.RefDraft)
			if err != nil {
				return err
			}
			if p.draft == "" {
				if base, err = treeOf(s, site.RefLive); err != nil {
					return err
				}
			}
			next, err := s.PutNested(base, changes)
			if err != nil {
				return err
			}
			if err := commitTreeNoLock(s, next, "remove the "+m.Name+" demonstration", caller.Name); err != nil {
				return err
			}
			commit = s.GetRef(site.RefDraft)
			return nil
		})
		if err != nil {
			return err
		}
		wrote = true
		detail["pages"] = strings.Join(p.pages, ",")
		detail["records"] = fmt.Sprint(p.records)
	}

	// What the live site reads beside the store, kept as it was until the
	// removal is published.
	saved := map[string][]byte{}
	for _, path := range sideFiles(root) {
		if b, err := os.ReadFile(path); err == nil {
			saved[path] = b
		}
	}
	restore := func() {
		for _, path := range sideFiles(root) {
			if b, ok := saved[path]; ok {
				_ = atomicfile.Write(path, b, 0o600)
			} else {
				_ = os.Remove(path)
			}
		}
	}
	if err := p.applySideFiles(root); err != nil {
		restore()
		return err
	}
	if len(p.types)+len(p.collections)+len(p.unbind)+len(p.listings)+len(p.forms)+
		len(p.menus)+len(p.vocab) > 0 || p.brand {
		wrote = true
	}

	// Published as that exact commit, through every gate. Refused, the live
	// site keeps the demonstration whole and the record stays as it was.
	published := ""
	if p.publish {
		wrote = true
		args := []string{}
		if m.Templates.Dir != "" {
			args = append(args, "--templates", m.Templates.Dir)
		}
		if perr := cmdPublish(root, append(args, commit)); perr != nil {
			restore()
			detail["published"] = "refused"
			return errBlocked{fmt.Errorf("the demonstration was taken out of the draft, "+
				"and publishing that was refused, so the live site still serves all of "+
				"it: %w\n  Once publishing can go ahead, run quilzo demo remove --yes again", perr)}
		}
		published = s.GetRef(site.RefLive)
		detail["published"] = short(published)
	}

	// Now nothing live uses the rest.
	if len(p.pages) > 0 {
		if idx, err := loadProvenance(root); err == nil {
			changed := false
			for _, page := range p.pages {
				if _, has := idx.Records[page]; has {
					delete(idx.Records, page)
					changed = true
				}
			}
			if changed {
				if err := saveJSON(provPath(root), idx); err != nil {
					return err
				}
			}
		}
	}
	images := 0
	if len(p.media) > 0 {
		wrote = true
		lib, err := openMedia(root)
		if err != nil {
			return err
		}
		for _, id := range p.media {
			f, serr := lib.Stat(id)
			if serr != nil {
				continue
			}
			if err := lib.Remove(id); err != nil {
				return err
			}
			for _, r := range f.Renditions {
				_ = lib.Remove(r.ID)
			}
			images++
		}
		detail["images"] = fmt.Sprint(images)
	}
	if len(p.settings) > 0 {
		wrote = true
		if err := p.applySettings(root, caller); err != nil {
			return err
		}
		detail["settings"] = strings.Join(p.settings, ",")
	}
	if len(p.research) > 0 {
		wrote = true
		r, err := os.OpenRoot(researchStore(root).Dir)
		if err != nil {
			return err
		}
		for _, name := range p.research {
			if err := r.RemoveAll(name); err != nil {
				r.Close()
				return err
			}
		}
		r.Close()
		detail["research"] = strings.Join(p.research, ",")
	}
	files := 0
	if len(p.templates)+len(p.examples) > 0 {
		wrote = true
		files = m.Templates.take(p.templates) + m.Examples.take(p.examples)
		detail["files"] = fmt.Sprint(files)
	}

	// What was not taken stays on record, so running this again after undoing
	// an edit takes the rest. Its digest goes in the log, or it is not trusted.
	wrote = true
	if p.kept.empty() {
		if err := os.Remove(demoManifestPath(root)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		detail["manifest"] = "none"
	} else {
		digest, err := saveDemoManifest(root, &p.kept)
		if err != nil {
			return err
		}
		detail["manifest"] = digest
	}
	detail["kept"] = fmt.Sprint(len(p.keep))

	if w.JSON(p.summary(true, published, images, files)) {
		return nil
	}
	p.print(true)
	w.Human("  %-14s %d\n  %-14s %d\n", "images", images, "files", files)
	switch {
	case published != "":
		w.Human("\n  published: the live site no longer serves it\n")
		if images > 0 {
			w.Human("  %sthe images are deleted, so a rollback brings the pages back without them%s\n", dim, reset)
		}
	case p.live == "":
		w.Human("\n  nothing was live, so there was nothing to publish\n")
	}
	return nil
}

// applySideFiles removes the types, bindings, listings, forms, menus,
// vocabularies and claim rules the plan took.
func (p *demoRemoval) applySideFiles(root string) error {
	if len(p.unbind)+len(p.collections)+len(p.types) > 0 {
		types, err := schema.Load(root)
		if err != nil {
			return err
		}
		for _, page := range p.unbind {
			delete(types.Bound, page)
		}
		for _, c := range p.collections {
			types.UnbindCollection(c)
		}
		for _, name := range p.types {
			delete(types.Registry.Types, name)
		}
		if err := types.Save(); err != nil {
			return err
		}
	}
	if len(p.listings) > 0 {
		set, err := loadListings(root)
		if err != nil {
			return err
		}
		for _, name := range p.listings {
			_ = set.Remove(name)
		}
		if err := saveJSON(listingPath(root), set); err != nil {
			return err
		}
	}
	if len(p.forms) > 0 {
		set, err := loadForms(root)
		if err != nil {
			return err
		}
		kept := set.Forms[:0]
		for _, f := range set.Forms {
			if !slices.Contains(p.forms, f.Name) {
				kept = append(kept, f)
			}
		}
		set.Forms = kept
		if err := saveJSON(formsPath(root), set); err != nil {
			return err
		}
	}
	if len(p.menus) > 0 {
		set, err := loadMenus(root)
		if err != nil {
			return err
		}
		for _, name := range p.menus {
			_ = set.Remove(name)
		}
		if err := saveJSON(menuPath(root), set); err != nil {
			return err
		}
	}
	if len(p.vocab) > 0 {
		set := &taxonomy.Set{}
		if err := loadJSON(vocabPath(root), set); err != nil {
			return err
		}
		set.Vocabularies = slices.DeleteFunc(set.Vocabularies, func(v taxonomy.Vocabulary) bool {
			return slices.Contains(p.vocab, v.Name)
		})
		if err := saveJSON(vocabPath(root), set); err != nil {
			return err
		}
	}
	if p.brand {
		if err := os.Remove(brandPath(root)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// applySettings puts the demonstration's settings back, each recorded the way
// `quilzo config set` records it. No reason is given, so a value weaker than
// the default is refused rather than accepted in the remover's name.
func (p *demoRemoval) applySettings(root string, caller *Caller) error {
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	type change struct{ key, from, to string }
	var done []change
	for _, key := range p.settings {
		was, from := p.m.Config[key].Was, cfg.Raw(key)
		if def, _ := config.Lookup(key); was == def.Default {
			err = cfg.Unset(key)
		} else {
			err = cfg.Set(key, was, "", caller.Name)
		}
		if err != nil {
			return fmt.Errorf("setting %s: %w", key, err)
		}
		done = append(done, change{key, from, cfg.Raw(key)})
	}
	if err := saveConfig(root, cfg); err != nil {
		return err
	}
	for _, c := range done {
		record(root, caller.auditRecord("config.set", "/", audit.Success, map[string]string{
			"setting": c.key, "from": c.from, "to": c.to, "by": "demo remove"}))
	}
	return nil
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// summary is the removal as data, for --json.
func (p *demoRemoval) summary(done bool, published string, images, files int) map[string]any {
	out := map[string]any{
		"removed":      done,
		"name":         p.m.Name,
		"pages":        orEmpty(p.pages),
		"records":      p.records,
		"types":        orEmpty(p.types),
		"collections":  orEmpty(p.collections),
		"listings":     orEmpty(p.listings),
		"forms":        orEmpty(p.forms),
		"menus":        orEmpty(p.menus),
		"vocabularies": orEmpty(p.vocab),
		"claim_rules":  p.brand,
		"settings":     orEmpty(p.settings),
		"research":     orEmpty(p.research),
		"images":       orEmpty(p.media),
		"templates":    orEmpty(p.templates),
		"examples":     orEmpty(p.examples),
		"publishes":    p.publish,
		"kept":         orEmpty(p.keep),
	}
	if done {
		out["published"] = published
		out["images_removed"] = images
		out["files_removed"] = files
	}
	return out
}

func (p *demoRemoval) print(done bool) {
	verb := "would remove"
	if done {
		verb = "removed"
	}
	nothing := len(p.paths)+len(p.types)+len(p.collections)+len(p.listings)+len(p.forms)+
		len(p.menus)+len(p.vocab)+len(p.settings)+len(p.research)+len(p.media)+
		len(p.templates)+len(p.examples) == 0 && !p.brand && !p.publish
	if nothing {
		w.Human("%s%s%s: nothing is left that it can take\n", bold, p.m.Name, reset)
	} else {
		w.Human("%s%s%s: %s\n", bold, p.m.Name, reset, verb)
	}
	line := func(what string, names []string) {
		if len(names) > 0 {
			w.Human("  %-14s %s\n", what, strings.Join(names, ", "))
		}
	}
	line("pages", p.pages)
	if p.records > 0 {
		w.Human("  %-14s %d\n", "records", p.records)
	}
	line("types", p.types)
	line("collections", p.collections)
	line("listings", p.listings)
	line("forms", p.forms)
	line("menus", p.menus)
	line("vocabularies", p.vocab)
	if p.brand {
		w.Human("  %-14s the claim rules\n", "brand")
	}
	line("settings", p.settings)
	line("research", p.research)
	line("template", p.templates)
	line("examples", p.examples)
	if !done && len(p.media) > 0 {
		w.Human("  %-14s %d\n", "images", len(p.media))
	}
	if !done && p.publish {
		w.Human("  and publishes the removal, through the same gates as quilzo publish\n")
	}
	if len(p.keep) > 0 {
		w.Human("\n  %skept, because somebody changed or uses them:%s\n", bold, reset)
		for _, k := range p.keep {
			w.Human("    %s\n", k)
		}
	}
}
