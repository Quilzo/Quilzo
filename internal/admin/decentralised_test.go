// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/ipfs"
	"github.com/quilzo/quilzo/internal/site"
)

// The screen and the download give the identifier of the bundle the host
// hands them, which is the command line's, and the size guard still holds.
//
// The screen rendered a bundle of its own, the pages alone, so it gave a
// different identifier from `quilzo ipfs id` and the content_id tool for the
// same site. cmd/quilzo checks the three agree end to end; this checks the
// screen uses what it is given rather than its own render.
func TestThePermanentWebScreenUsesTheBundleItIsGiven(t *testing.T) {
	srv, token := setup(t)
	if _, err := site.Publish(srv.Store, srv.Store.GetRef(site.RefDraft)); err != nil {
		t.Fatal(err)
	}
	given := map[string][]byte{
		"index.html":  []byte("<!doctype html><title>Home</title>"),
		"sitemap.xml": []byte("<urlset></urlset>"),
	}
	node, err := ipfs.Tree(given)
	if err != nil {
		t.Fatal(err)
	}
	want := node.Block.CID
	pages := map[string]any{"index": map[string]any{"title": "Home"}}
	srv.Decentralised = &Decentralised{
		Pages:  func() (map[string]any, error) { return pages, nil },
		Bundle: func() (map[string][]byte, error) { return given, nil },
	}

	w := get(t, srv, "/decentralised/bundle", token)
	if w.Code != http.StatusOK {
		t.Fatalf("the download answered %d: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("X-Content-Id"); got != want {
		t.Errorf("the download is %s, and the bundle it was given is %s", got, want)
	}
	if page := get(t, srv, "/decentralised", token); !strings.Contains(page.Body.String(), want) {
		t.Errorf("the screen does not show %s, the identifier of the bundle it was given", want)
	}

	// Too large for a click, whichever renders it.
	big := map[string]any{}
	for i := 0; i <= MaxBundlePages; i++ {
		big[fmt.Sprintf("p%d", i)] = map[string]any{}
	}
	pages = big
	if page := get(t, srv, "/decentralised", token); strings.Contains(page.Body.String(), want) {
		t.Errorf("a site of %d pages was rendered on the screen", len(big))
	}
}
