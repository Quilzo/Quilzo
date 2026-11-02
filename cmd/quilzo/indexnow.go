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
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/egress"
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
// commit to another and a search engine may list.
func indexNowChanged(s *store.Store, base, index, from, to string) ([]string, error) {
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
	for _, c := range changes {
		changed[c.Path] = true
		for _, u := range uses[c.Path] {
			changed[u] = true
		}
	}
	visible := site.Visible(pages, time.Now())
	var out []string
	for name := range changed {
		body, live := visible[name]
		if live && !seo.InSitemap(base, name, index, body) {
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
	s, err := store.Open(root)
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
	urls, err := indexNowChanged(s, base, "index", st.Commit, live)
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
