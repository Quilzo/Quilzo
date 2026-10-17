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
	"github.com/quilzo/quilzo/internal/form"
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
// theirs now: kept, and listed. Pages and records a person added, what the
// public sent through a form, and files somebody edited are never touched.
//
// It says what it would do and changes nothing until it is run with --yes.

// demoManifestFormat is the manifest format this program reads and writes.
const demoManifestFormat = 1

func demoManifestPath(root string) string { return filepath.Join(root, "demo.json") }

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

// folderDigests is every file under dir with its digest. Lock files are left
// out: they are how a store guards a write, not what it holds.
func folderDigests(dir string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, ".lock") {
			return nil
		}
		if !e.Type().IsRegular() {
			out[rel] = "not a regular file"
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		out[rel] = demoDigest(b)
		return nil
	})
	return out, err
}

// recordDemo writes the manifest, once the install has written everything
// else. m arrives holding what only the install knows: the media, settings
// and folders it wrote.
func recordDemo(root string, s *store.Store, d *demo.Site, m *demoManifest) error {
	m.Format = demoManifestFormat
	m.Name = d.Name
	if c, err := s.GetCommit(s.GetRef(site.RefDraft)); err == nil {
		tree, terr := s.GetNested(c.Tree)
		if terr != nil {
			return terr
		}
		m.Tree = tree
	} else {
		return err
	}

	st, _, err := featureState(root)
	if err != nil {
		return err
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
	m.Bound = map[string]string{}
	for page, typ := range d.Bind {
		m.Bound[page] = typ
	}

	vocab := &taxonomy.Set{}
	if err := loadJSON(vocabPath(root), vocab); err != nil {
		return err
	}
	m.Vocabularies = map[string]string{}
	for _, v := range vocab.Vocabularies {
		b, _ := json.Marshal(v)
		m.Vocabularies[v.Name] = blockDigest(b)
	}

	if len(d.ClaimRules.Terms) > 0 {
		b, err := os.ReadFile(brandPath(root))
		if err != nil {
			return err
		}
		m.Brand = demoDigest(b)
	}

	rs := researchStore(root)
	m.Research = map[string]map[string]string{}
	for _, rp := range d.Research {
		files, err := folderDigests(filepath.Join(rs.Dir, rp.Name))
		if err != nil {
			return err
		}
		m.Research[rp.Name] = files
	}

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(demoManifestPath(root), b, 0o600)
}

// demoInstallable refuses a store that already holds content the install
// would collide with.
//
// Content rather than refs: a store the demonstration was installed in and
// then removed from has refs pointing at empty trees, and is as empty as a
// new one.
func demoInstallable(root string, s *store.Store, d *demo.Site) error {
	if _, err := os.Lstat(demoManifestPath(root)); err == nil {
		return errors.New("the demonstration is already installed here.\n" +
			"  quilzo demo remove      says what taking it out would remove\n" +
			"  quilzo demo remove --yes  takes it out")
	}
	full := false
	for _, ref := range []string{site.RefDraft, site.RefLive} {
		cid := s.GetRef(ref)
		if cid == "" {
			continue
		}
		c, err := s.GetCommit(cid)
		if err != nil {
			return err
		}
		tree, err := s.GetNested(c.Tree)
		if err != nil {
			return err
		}
		full = full || len(tree) > 0
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
	if full {
		return errors.New(
			"this store already has content, and the demonstration would " +
				"write over the content types, listings, menus and forms that " +
				"share a name with its own.\n  Run it in an empty directory:\n" +
				"    mkdir shop && cd shop && quilzo init && quilzo demo")
	}
	return nil
}

// demoRemoval is what removing the demonstration would do, worked out
// against what the store holds now.
type demoRemoval struct {
	m     *demoManifest
	draft string // the draft commit this was worked out against

	paths     []string // tree paths to delete
	pages     []string // the pages among them
	records   int
	remaining map[string]string // the draft's tree once they are gone

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

	// publish is whether the removal is published as well: only when the
	// draft held nothing the live site does not, so publishing it publishes
	// the removal and nothing somebody has not finished.
	publish bool

	keep []string // what stays, and why
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

// planDemoRemoval works out the removal. It writes nothing.
func planDemoRemoval(root string, s *store.Store, m *demoManifest) (*demoRemoval, error) {
	p := &demoRemoval{m: m, draft: s.GetRef(site.RefDraft)}

	draftTree, err := treeOf(s, site.RefDraft)
	if err != nil {
		return nil, err
	}
	liveTree, err := treeOf(s, site.RefLive)
	if err != nil {
		return nil, err
	}
	now, err := s.GetNested(draftTree)
	if err != nil {
		return nil, err
	}
	p.remaining = map[string]string{}
	for path, oid := range now {
		p.remaining[path] = oid
	}
	paths := make([]string, 0, len(m.Tree))
	for path := range m.Tree {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		cur, ok := now[path]
		switch {
		case !ok:
			// Gone already: somebody removed it, which is what was wanted.
		case cur == m.Tree[path]:
			p.paths = append(p.paths, path)
			delete(p.remaining, path)
			if _, _, isRecord := collection.IsCollectionPath(path); isRecord {
				p.records++
			} else {
				p.pages = append(p.pages, path)
			}
		default:
			if coll, id, isRecord := collection.IsCollectionPath(path); isRecord {
				p.keepf("record %s/%s: changed since it was installed", coll, short(id))
			} else {
				p.keepf("page %s: changed since it was installed", path)
			}
		}
	}
	p.publish = liveTree != "" && liveTree == draftTree && len(p.paths) > 0

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

	// Types, the pages bound to them and the collections typed by them.
	types, err := schema.Load(root)
	if err != nil {
		return nil, err
	}
	bound := map[string]string{}
	for page, typ := range types.Bound {
		bound[page] = typ
	}
	colls := map[string]string{}
	for c, typ := range types.Collections {
		colls[c] = typ
	}
	pages := make([]string, 0, len(m.Bound))
	for page := range m.Bound {
		pages = append(pages, page)
	}
	sort.Strings(pages)
	for _, page := range pages {
		if bound[page] != m.Bound[page] {
			continue
		}
		if _, still := p.remaining[page]; still {
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
			p.keepf("collection %s: its type was changed since it was installed", name)
			continue
		}
		left := 0
		for path := range p.remaining {
			if c, _, ok := collection.IsCollectionPath(path); ok && c == name {
				left++
			}
		}
		if left > 0 {
			p.keepf("collection %s: still holds %d record(s) the demonstration did not write", name, left)
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
			p.keepf("type %s: changed since it was installed", name)
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
			p.keepf("type %s: still used by %s", name, strings.Join(users, ", "))
			continue
		}
		p.types = append(p.types, name)
	}

	// Listings, forms and menus.
	subs, err := openSubmissions(root)
	if err != nil {
		return nil, err
	}
	for _, kind := range []string{"listing", "form", "menu"} {
		for _, name := range blocks[kind] {
			if !exists(kind, name) {
				continue
			}
			if !unchanged(kind, name) {
				p.keepf("%s %s: changed since it was installed", kind, name)
				continue
			}
			switch kind {
			case "listing":
				p.listings = append(p.listings, name)
			case "form":
				// What the public sent is personal data somebody is
				// answerable for, and the form is how it is read.
				if got, lerr := subs.List(name); lerr != nil {
					return nil, lerr
				} else if len(got) > 0 {
					p.keepf("form %s: holds %d submission(s) from the public", name, len(got))
					continue
				}
				p.forms = append(p.forms, name)
			case "menu":
				p.menus = append(p.menus, name)
			}
		}
	}

	// Vocabularies, unless content that stays is tagged from one.
	content, err := treeContent(s, p.remaining)
	if err != nil {
		return nil, err
	}
	vocab := &taxonomy.Set{}
	if err := loadJSON(vocabPath(root), vocab); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(m.Vocabularies))
	for name := range m.Vocabularies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		v, ok := vocab.Get(name)
		if !ok {
			continue
		}
		b, _ := json.Marshal(v)
		if blockDigest(b) != m.Vocabularies[name] {
			p.keepf("vocabulary %s: changed since it was installed", name)
			continue
		}
		var tagged []string
		for where, body := range content {
			if len(taxonomy.Of(body, name)) > 0 {
				tagged = append(tagged, where)
			}
		}
		if len(tagged) > 0 {
			sort.Strings(tagged)
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
				p.keepf("the claim rules: changed since they were installed")
			}
		}
	}

	// Settings, back to what they were, unless somebody has set them since.
	if cfg, err := loadConfig(root); err == nil {
		keys := make([]string, 0, len(m.Config))
		for key := range m.Config {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if _, known := config.Lookup(key); !known {
				continue
			}
			if cfg.Raw(key) != m.Config[key].Set {
				p.keepf("setting %s: changed since it was installed", key)
				continue
			}
			p.settings = append(p.settings, key)
		}
	}

	// Research projects, unless somebody has worked in one.
	rs := researchStore(root)
	projects := make([]string, 0, len(m.Research))
	for name := range m.Research {
		projects = append(projects, name)
	}
	sort.Strings(projects)
	for _, name := range projects {
		if !research.ValidName(name) {
			continue
		}
		dir := filepath.Join(rs.Dir, name)
		if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		now, err := folderDigests(dir)
		if err != nil || !maps.Equal(now, m.Research[name]) {
			p.keepf("research project %s: has work in it since it was installed", name)
			continue
		}
		p.research = append(p.research, name)
	}
	return p, nil
}

// treeContent is the pages and records at these tree paths: a page by its
// name, a record as collection/id.
func treeContent(s *store.Store, tree map[string]string) (map[string]map[string]any, error) {
	out := map[string]map[string]any{}
	for path, oid := range tree {
		if c, id, ok := collection.IsCollectionPath(path); ok {
			var r collection.Record
			if err := s.GetBlob(oid, &r); err != nil {
				return nil, err
			}
			out[c+"/"+id] = r.Fields
			continue
		}
		if strings.Contains(path, "/") {
			continue
		}
		var body any
		if err := s.GetBlob(oid, &body); err != nil {
			return nil, err
		}
		if m, ok := body.(map[string]any); ok {
			out[path] = m
		}
	}
	return out, nil
}

// demoRemove is `quilzo demo remove [--yes]`.
func demoRemove(root string, args []string) error {
	flags := flag.NewFlagSet("demo remove", flag.ContinueOnError)
	yes := flags.Bool("yes", false, "remove it; without this, only say what would go")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return errors.New("usage: quilzo demo remove [--yes]")
	}
	return removeDemo(root, *yes, resolveCaller(root, flagToken))
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

	body, err := os.ReadFile(demoManifestPath(root))
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("there is no record of a demonstration installed in this store, " +
			"so there is nothing this can take back. A demonstration installed " +
			"before Quilzo kept that record is removed by hand, or by starting " +
			"again in an empty directory")
	}
	if err != nil {
		return err
	}
	var m demoManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return fmt.Errorf("%s could not be read: %w", demoManifestPath(root), err)
	}
	if m.Format != demoManifestFormat {
		return fmt.Errorf("%s is format %d, and this program reads format %d",
			demoManifestPath(root), m.Format, demoManifestFormat)
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	p, err := planDemoRemoval(root, s, &m)
	if err != nil {
		return err
	}
	if !yes {
		if w.JSON(p.summary(false, nil, nil)) {
			return nil
		}
		p.print(false)
		w.Human("\n  nothing has been removed. To remove it:\n    quilzo demo remove --yes\n")
		return nil
	}
	return p.apply(root, s, caller)
}

// apply carries the removal out.
func (p *demoRemoval) apply(root string, s *store.Store, caller *Caller) error {
	m := p.m

	// The draft first, against the commit the plan was worked out from: a
	// draft that moved in between was worked out wrongly.
	if len(p.paths) > 0 {
		changes := make([]store.Change, 0, len(p.paths))
		for _, path := range p.paths {
			changes = append(changes, store.Change{Path: path, Delete: true})
		}
		err := s.WithRefLock(func() error {
			if s.GetRef(site.RefDraft) != p.draft {
				return errors.New("the draft changed while this was working, so nothing was " +
					"removed. Run it again")
			}
			base, err := treeOf(s, site.RefDraft)
			if err != nil {
				return err
			}
			next, err := s.PutNested(base, changes)
			if err != nil {
				return err
			}
			return commitTreeNoLock(s, next, "remove the "+m.Name+" demonstration", caller.Name)
		})
		if err != nil {
			return err
		}
	}

	// Types and bindings.
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

	// Listings, forms, menus and vocabularies.
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
		set.Forms = slices.DeleteFunc(set.Forms, func(f form.Form) bool {
			return slices.Contains(p.forms, f.Name)
		})
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

	// Published, when publishing it publishes nothing but the removal. The
	// same command as `quilzo publish`, so every gate runs.
	published := false
	var publishErr error
	if p.publish {
		args := []string{}
		if m.Templates.Dir != "" {
			args = append(args, "--templates", m.Templates.Dir)
		}
		w.Human("publishing the removal, through the same gates as quilzo publish\n")
		if publishErr = cmdPublish(root, args); publishErr == nil {
			published = true
		}
	}

	// What is left, now the live site is what it is going to be.
	draftContent, err := contentAt(s, site.RefDraft)
	if err != nil {
		return err
	}
	liveContent := map[string]map[string]any{}
	if s.GetRef(site.RefLive) != "" {
		if liveContent, err = contentAt(s, site.RefLive); err != nil {
			return err
		}
	}
	pagesLeft := 0
	for where := range draftContent {
		if !strings.Contains(where, "/") {
			pagesLeft++
		}
	}
	for where := range liveContent {
		if !strings.Contains(where, "/") {
			pagesLeft++
		}
	}

	// The provenance of pages no longer anywhere.
	if idx, err := loadProvenance(root); err == nil {
		changed := false
		for _, page := range p.pages {
			_, inDraft := draftContent[page]
			_, inLive := liveContent[page]
			if _, has := idx.Records[page]; has && !inDraft && !inLive {
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

	// Images nothing left points at, with the narrower copies made of them.
	used := map[string]bool{}
	for _, content := range []map[string]map[string]any{draftContent, liveContent} {
		for _, fields := range content {
			for _, id := range media.IDsIn(fields) {
				used[id] = true
			}
		}
	}
	var keptMedia []string
	images := 0
	if len(m.Media) > 0 {
		lib, err := openMedia(root)
		if err != nil {
			return err
		}
		for _, id := range m.Media {
			f, serr := lib.Stat(id)
			if serr != nil {
				continue
			}
			if used[id] {
				keptMedia = append(keptMedia, id)
				p.keepf("image %s: still used by the site", f.Name)
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
	}

	// Settings.
	if len(p.settings) > 0 {
		cfg, err := loadConfig(root)
		if err != nil {
			return err
		}
		for _, key := range p.settings {
			was := m.Config[key].Was
			if def, _ := config.Lookup(key); was == def.Default {
				err = cfg.Unset(key)
			} else {
				err = cfg.Set(key, was, "the demonstration was removed", caller.Name)
			}
			if err != nil {
				return fmt.Errorf("setting %s: %w", key, err)
			}
		}
		if err := saveConfig(root, cfg); err != nil {
			return err
		}
	}

	// Research projects.
	rs := researchStore(root)
	for _, name := range p.research {
		if err := os.RemoveAll(filepath.Join(rs.Dir, name)); err != nil {
			return err
		}
	}

	// Files outside the store. The template stays while any page is left
	// to render through it.
	known := demo.Marginalia()
	var tplGone, tplKept []string
	if pagesLeft == 0 {
		tplGone, tplKept = m.Templates.take(map[string]bool{"page.html": true, "site.css": true})
	} else if len(m.Templates.Files) > 0 {
		p.keepf("the template in %s: %d page(s) still render through it", m.Templates.Dir, pagesLeft)
		tplKept = slices.Sorted(maps.Keys(m.Templates.Files))
	}
	names := map[string]bool{}
	for rel := range known.Examples {
		names[rel] = true
	}
	exGone, exKept := m.Examples.take(names)
	for _, rel := range exKept {
		p.keepf("the example %s: changed since it was installed", rel)
	}
	if pagesLeft == 0 {
		for _, rel := range tplKept {
			p.keepf("the template file %s: changed since it was installed", rel)
		}
	}

	// What was not taken stays on record, so running this again after
	// publishing or undoing an edit takes the rest.
	rest := m.without(p, keptMedia, tplKept, exKept)
	if rest == nil {
		if err := os.Remove(demoManifestPath(root)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else {
		b, err := json.MarshalIndent(rest, "", "  ")
		if err != nil {
			return err
		}
		if err := atomicfile.Write(demoManifestPath(root), b, 0o600); err != nil {
			return err
		}
	}

	files := len(tplGone) + len(exGone)
	record(root, caller.auditRecord("demo.remove", "/", audit.Success, map[string]string{
		"name":      m.Name,
		"pages":     fmt.Sprint(len(p.pages)),
		"records":   fmt.Sprint(p.records),
		"images":    fmt.Sprint(images),
		"files":     fmt.Sprint(files),
		"kept":      fmt.Sprint(len(p.keep)),
		"published": fmt.Sprint(published),
	}))

	if w.JSON(p.summary(true, &published, &images)) {
		return publishBlocked(publishErr)
	}
	p.print(true)
	w.Human("  %d image(s), %d file(s) beside the store\n", images, files)
	switch {
	case published:
		w.Human("\n  published: the live site no longer serves it\n")
		if images > 0 {
			w.Human("  %sthe images are deleted, so a rollback brings the pages back without them%s\n", dim, reset)
		}
	case publishErr != nil:
		w.Human("\n  %sthe removal is in the draft, and publishing it was refused:%s %v\n",
			yellow, reset, publishErr)
	case p.publish:
	case s.GetRef(site.RefLive) != "" && len(p.pages) > 0:
		w.Human("\n  the removal is in the draft. The live site serves the demonstration until it is published:\n    quilzo publish\n")
	}
	return publishBlocked(publishErr)
}

// publishBlocked reports a refused publish as a failure of the command, so a
// script removing the demonstration does not read success while the live
// site still serves it.
func publishBlocked(err error) error {
	if err == nil {
		return nil
	}
	return errBlocked{fmt.Errorf("the demonstration was removed from the draft; publishing the removal was refused: %w", err)}
}

// take removes the files still as the install wrote them, among the names
// this program writes there, then the folders the install made once they are
// empty. It returns what went and what stayed.
func (f demoFolder) take(known map[string]bool) (gone, kept []string) {
	if f.Dir == "" || !filepath.IsAbs(f.Dir) {
		return nil, slices.Sorted(maps.Keys(f.Files))
	}
	inside := func(rel string) (string, bool) {
		path := filepath.Join(f.Dir, filepath.FromSlash(rel))
		r, err := filepath.Rel(f.Dir, path)
		if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return "", false
		}
		return path, true
	}
	for _, rel := range slices.Sorted(maps.Keys(f.Files)) {
		path, ok := inside(rel)
		if !ok || !known[rel] {
			kept = append(kept, rel)
			continue
		}
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			kept = append(kept, rel)
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil || demoDigest(b) != f.Files[rel] {
			kept = append(kept, rel)
			continue
		}
		if os.Remove(path) != nil {
			kept = append(kept, rel)
			continue
		}
		gone = append(gone, rel)
	}
	// Deepest first, and only while empty: os.Remove refuses a folder with
	// anything in it, which is the rule wanted.
	made := slices.Clone(f.Made)
	sort.Slice(made, func(i, j int) bool {
		return strings.Count(made[i], "/") > strings.Count(made[j], "/") ||
			(strings.Count(made[i], "/") == strings.Count(made[j], "/") && made[i] == ".")
	})
	for _, rel := range made {
		if rel == "." {
			continue
		}
		if path, ok := inside(rel); ok {
			_ = os.Remove(path)
		}
	}
	if slices.Contains(made, ".") {
		_ = os.Remove(f.Dir)
	}
	return gone, kept
}

// without is the manifest less what a removal took, or nil when it took
// everything.
func (m *demoManifest) without(p *demoRemoval, media, tplKept, exKept []string) *demoManifest {
	rest := *m
	rest.Tree = map[string]string{}
	for path, oid := range m.Tree {
		if cur, ok := p.remaining[path]; ok && cur != "" && !slices.Contains(p.paths, path) {
			rest.Tree[path] = oid
		}
	}
	gone := map[string]bool{}
	for _, n := range p.collections {
		gone[blockKey("collection", n)] = true
	}
	for _, n := range p.types {
		gone[blockKey("type", n)] = true
	}
	for _, n := range p.listings {
		gone[blockKey("listing", n)] = true
	}
	for _, n := range p.forms {
		gone[blockKey("form", n)] = true
	}
	for _, n := range p.menus {
		gone[blockKey("menu", n)] = true
	}
	rest.Blocks = map[string]string{}
	for k, v := range m.Blocks {
		if !gone[k] {
			rest.Blocks[k] = v
		}
	}
	rest.Bound = map[string]string{}
	for page, typ := range m.Bound {
		if !slices.Contains(p.unbind, page) {
			rest.Bound[page] = typ
		}
	}
	rest.Vocabularies = map[string]string{}
	for k, v := range m.Vocabularies {
		if !slices.Contains(p.vocab, k) {
			rest.Vocabularies[k] = v
		}
	}
	if p.brand {
		rest.Brand = ""
	}
	rest.Media = media
	rest.Config = map[string]demoSetting{}
	for k, v := range m.Config {
		if !slices.Contains(p.settings, k) {
			rest.Config[k] = v
		}
	}
	rest.Research = map[string]map[string]string{}
	for k, v := range m.Research {
		if !slices.Contains(p.research, k) {
			rest.Research[k] = v
		}
	}
	keepFiles := func(f demoFolder, kept []string) demoFolder {
		out := demoFolder{Dir: f.Dir, Made: f.Made, Files: map[string]string{}}
		for _, rel := range kept {
			out.Files[rel] = f.Files[rel]
		}
		return out
	}
	rest.Templates = keepFiles(m.Templates, tplKept)
	rest.Examples = keepFiles(m.Examples, exKept)

	if len(rest.Tree)+len(rest.Blocks)+len(rest.Bound)+len(rest.Vocabularies)+
		len(rest.Media)+len(rest.Config)+len(rest.Research)+
		len(rest.Templates.Files)+len(rest.Examples.Files) == 0 && rest.Brand == "" {
		return nil
	}
	return &rest
}

// summary is the removal as data, for --json.
func (p *demoRemoval) summary(done bool, published *bool, images *int) map[string]any {
	out := map[string]any{
		"removed":       done,
		"name":          p.m.Name,
		"pages":         p.pages,
		"records":       p.records,
		"types":         p.types,
		"collections":   p.collections,
		"listings":      p.listings,
		"forms":         p.forms,
		"menus":         p.menus,
		"vocabularies":  p.vocab,
		"claim_rules":   p.brand,
		"settings":      p.settings,
		"research":      p.research,
		"publishes":     p.publish,
		"kept":          p.keep,
		"images_listed": len(p.m.Media),
	}
	if published != nil {
		out["published"] = *published
	}
	if images != nil {
		out["images"] = *images
	}
	return out
}

func (p *demoRemoval) print(done bool) {
	verb := "would remove"
	if done {
		verb = "removed"
	}
	w.Human("%s%s%s: %s\n", bold, p.m.Name, reset, verb)
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
	if !done {
		w.Human("  %-14s %d, unless something left still uses one\n", "images", len(p.m.Media))
		w.Human("  %-14s the template, unless a page is left to render through it; the example files\n", "files")
		if p.publish {
			w.Human("  and publishes the removal: the draft holds nothing the live site does not\n")
		}
	}
	if len(p.keep) > 0 {
		w.Human("\n  %skept, because somebody changed or uses them:%s\n", bold, reset)
		for _, k := range p.keep {
			w.Human("    %s\n", k)
		}
	}
}
