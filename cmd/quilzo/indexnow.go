// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/egress"
	"github.com/quilzo/quilzo/internal/experiment"
	"github.com/quilzo/quilzo/internal/i18n"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/personalise"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/seo"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// IndexNow: after a publish, the addresses of the pages that changed, sent
// once to the shared endpoint every IndexNow engine reads, with a key the
// site serves to show they are its own (site.indexnow; off by default).
// Only addresses, only of what changed, only of pages a search engine may
// list: never a page left out of results, a copy of one elsewhere, or a
// reusable block — a page that reuses a changed block is sent instead.

// indexNowEndpoint is where every IndexNow engine reads from.
var indexNowEndpoint = "https://api.indexnow.org/indexnow"

// MaxIndexNow is the most addresses one notice carries, as the protocol
// allows.
const MaxIndexNow = 10_000

var reIndexNowKey = regexp.MustCompile(`^[0-9a-f]{32}$`)

func indexNowKeyPath(root string) string   { return filepath.Join(root, "indexnow.key") }
func indexNowStatePath(root string) string { return filepath.Join(root, "indexnow.json") }

// indexNowKey is the site's IndexNow key, made the first time it is asked
// for. It is public by design: the site serves it.
func indexNowKey(root string) (string, error) {
	if b, err := os.ReadFile(indexNowKeyPath(root)); err == nil {
		if k := strings.TrimSpace(string(b)); reIndexNowKey.MatchString(k) {
			return k, nil
		}
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	k := hex.EncodeToString(b[:])
	return k, os.WriteFile(indexNowKeyPath(root), []byte(k+"\n"), 0o644)
}

// servedIndexNowKey is the key the public site serves, when IndexNow is on
// and a key has been made; the site makes none itself.
func servedIndexNowKey(root string) func() string {
	return func() string {
		if !mustConfig(root).Bool("site.indexnow") {
			return ""
		}
		b, err := os.ReadFile(indexNowKeyPath(root))
		if err != nil {
			return ""
		}
		if k := strings.TrimSpace(string(b)); reIndexNowKey.MatchString(k) {
			return k
		}
		return ""
	}
}

type indexNowState struct {
	Commit string    `json:"commit"`
	At     time.Time `json:"at"`
}

// indexNowChanged are the addresses of the pages that changed from one
// commit to another and a search engine may list: by the sitemap's rule
// (public.Listed), so not a variant that the running tests in exps or the
// enabled rules in rules serve at another page's address (either may be
// nil); the home page, named index, is never one, nor is a translation in
// one of the site's languages (locales, nil for a site in one). A changed
// record is sent as its own page and as the pages showing a listing over its
// collection, by the listings in listings (nil for none).
func indexNowChanged(s *store.Store, base, index, from, to string, exps *experiment.Set, rules *personalise.Set, locales *i18n.Config, listings *listing.Set) ([]string, error) {
	changes, err := site.Diff(s, from, to)
	if err != nil {
		return nil, err
	}
	pages, err := site.PagesAt(s, to)
	if err != nil {
		return nil, err
	}
	changed := map[string]bool{}
	uses := site.BlockUses(pages)
	var data site.Change
	for _, c := range changes {
		// Records live under data, beside the pages, and a tree there is not
		// a page: data was sent as https://SITE/data, which the site answers
		// 404, while the pages its records appear on were never sent.
		if (c.Before != "" && s.IsTree(c.Before)) || (c.After != "" && s.IsTree(c.After)) {
			if c.Path == "data" {
				data = c
			}
			continue
		}
		changed[c.Path] = true
		for _, u := range uses[c.Path] {
			changed[u] = true
		}
	}
	visible := site.Visible(pages, time.Now())
	var out []string
	if data.Path != "" && listings != nil {
		pagesOf, records, err := indexNowRecords(s, base, from, to, data, visible, listings)
		if err != nil {
			return nil, err
		}
		for _, name := range pagesOf {
			changed[name] = true
		}
		out = append(out, records...)
	}
	variants := public.Variants(exps, rules, visible, index, locales)
	for name := range changed {
		body, live := visible[name]
		if _, stands := render.DetailOf(pages[name]); stands {
			// A page that stands for records is no address of its own, as
			// the sitemap says: each record's page is.
			continue
		}
		if live && !public.Listed(base, name, index, body, variants) {
			continue
		}
		if _, isPage := pages[name]; isPage && !live {
			// A block, or a page not public now: not an address of its own.
			continue
		}
		// Removed pages are sent too: the engine finds them gone.
		out = append(out, seo.PageURL(base, name, index))
	}
	sort.Strings(out)
	return out, nil
}

// indexNowRecords is what a change to the records between two commits
// changed on the site: the pages showing a listing over a changed
// collection, and the address of each changed record a detail page's
// listing keeps, as the sitemap lists it, or kept before the change: a
// record taken away, or one its listing no longer keeps, has a page that is
// gone, and a removed page is sent so the engine finds it gone. data is the
// change to the store's data tree.
func indexNowRecords(s *store.Store, base, from, to string, data site.Change, visible map[string]any, listings *listing.Set) (pages, urls []string, err error) {
	collections := func(oid string) (map[string]string, error) {
		if oid == "" {
			return map[string]string{}, nil
		}
		return s.GetTree(oid)
	}
	before, err := collections(data.Before)
	if err != nil {
		return nil, nil, err
	}
	after, err := collections(data.After)
	if err != nil {
		return nil, nil, err
	}
	touched := map[string]bool{}
	for name, oid := range after {
		if before[name] != oid {
			touched[name] = true
		}
	}
	for name := range before {
		if _, kept := after[name]; !kept {
			touched[name] = true
		}
	}
	if len(touched) == 0 {
		return nil, nil, nil
	}
	treeOf := func(commit string) (string, error) {
		c, err := s.GetCommit(commit)
		if err != nil {
			return "", err
		}
		return c.Tree, nil
	}
	fromTree, err := treeOf(from)
	if err != nil {
		return nil, nil, err
	}
	toTree, err := treeOf(to)
	if err != nil {
		return nil, nil, err
	}
	// The records each touched collection changed, by id, read once.
	type changes struct {
		was, now *collection.Index
		ids      map[string]bool
	}
	read := map[string]*changes{}
	changedIn := func(name string) (*changes, error) {
		if c, ok := read[name]; ok {
			return c, nil
		}
		was, err := collection.Build(s, fromTree, name, nil)
		if err != nil {
			return nil, err
		}
		now, err := collection.Build(s, toTree, name, was)
		if err != nil {
			return nil, err
		}
		old := map[string]collection.Record{}
		for _, r := range was.Records {
			old[r.ID] = r
		}
		c := &changes{was: was, now: now, ids: map[string]bool{}}
		for _, r := range now.Records {
			// By what the record says: an identical re-import restamps it,
			// and no page reads differently for that.
			if o, ok := old[r.ID]; !ok || !reflect.DeepEqual(o.Fields, r.Fields) {
				c.ids[r.ID] = true
			}
			delete(old, r.ID)
		}
		// And the ones no longer there. Only the records still in the
		// collection were looked at, so a product withdrawn from a shop was
		// sent as the pages listing it and never as its own page.
		for id := range old {
			c.ids[id] = true
		}
		read[name] = c
		return c, nil
	}

	names := make([]string, 0, len(visible))
	for name := range visible {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := visible[name]
		if d, ok := render.DetailOf(body); ok {
			l, known := listings.Get(d.Listing)
			if !d.Declared() || !known || !touched[l.Collection] {
				continue
			}
			c, err := changedIn(l.Collection)
			if err != nil {
				return nil, nil, err
			}
			// As the listing keeps them now, and as it kept them before: a
			// changed record's page is at one address, at two if the change
			// was to the key it is addressed by, and only at the old one if
			// it is gone.
			sent := map[string]bool{}
			for _, idx := range []*collection.Index{c.now, c.was} {
				rows, _, err := listing.Every(l, idx, nil, MaxIndexNow)
				if err != nil {
					continue
				}
				for _, row := range rows {
					id, _ := row["id"].(string)
					key, _ := row[d.Key].(string)
					if !c.ids[id] || key == "" || strings.ContainsAny(key, "/?#") {
						continue
					}
					if u := base + "/" + name + "/" + url.PathEscape(key); !sent[u] {
						sent[u] = true
						urls = append(urls, u)
					}
				}
			}
			continue
		}
		for _, ln := range listing.On(body) {
			if l, known := listings.Get(ln); known && touched[l.Collection] {
				pages = append(pages, name)
				break
			}
		}
	}
	return pages, urls, nil
}

// indexNowAfterPublish tells IndexNow what changed since it was last told,
// and says what it did; "" when it did nothing.
func indexNowAfterPublish(ctx context.Context, root string) string {
	cfg := mustConfig(root)
	if !cfg.Bool("site.indexnow") {
		return ""
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.Raw("site.base_url")), "/")
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "IndexNow is on and site.base_url is not set, so nothing was sent"
	}
	s, err := openEncrypted(root)
	if err != nil {
		return ""
	}
	live := s.GetRef(site.RefLive)
	if live == "" {
		return ""
	}
	var st indexNowState
	if b, err := os.ReadFile(indexNowStatePath(root)); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.Commit == live {
		return ""
	}
	save := func() { _ = saveJSON(indexNowStatePath(root), indexNowState{Commit: live, At: time.Now().UTC()}) }
	if st.Commit == "" {
		// The first publish after it was turned on: a starting point, not a
		// list of every page the site has ever had; and the key, so the site
		// serves it before it is first needed.
		_, _ = indexNowKey(root)
		save()
		return ""
	}
	// Unreadable, none: the site serves no test or rule from a file it
	// cannot read either.
	exps, _ := experiment.Load(experimentsPath(root))
	rules, _ := personalise.Load(personalisePath(root))
	locales, _ := loadLocales(root)
	listings, _ := loadListings(root)
	urls, err := indexNowChanged(s, base, "index", st.Commit, live, exps, rules, locales, listings)
	if err != nil || len(urls) == 0 {
		save()
		return ""
	}
	if len(urls) > MaxIndexNow {
		urls = urls[:MaxIndexNow]
	}
	key, err := indexNowKey(root)
	if err != nil {
		return "IndexNow: " + err.Error()
	}
	if err := sendIndexNow(ctx, u.Hostname(), key, base+"/"+key+".txt", urls); err != nil {
		return "IndexNow: " + err.Error()
	}
	save()
	return fmt.Sprintf("told search engines about %s", plural2(len(urls), "a changed page", "changed pages"))
}

// sendIndexNow posts one notice.
func sendIndexNow(ctx context.Context, host, key, keyLocation string, urls []string) error {
	body, err := json.Marshal(map[string]any{"host": host, "key": key, "keyLocation": keyLocation, "urlList": urls})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, indexNowEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := egress.Client("indexnow", 15*time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("the endpoint answered %d", resp.StatusCode)
	}
	return nil
}
