// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/seo"
)

// A redirect added from the command line is in the site's map, replaces
// one from the same address, is refused when it would loop, and the
// running site's map picks it up without a restart.
func TestARedirectIsAddedAndTheSiteSeesIt(t *testing.T) {
	root := demoStore(t)
	start, err := servedRedirects(root, "")
	if err != nil {
		t.Fatal(err)
	}
	current := reloadingRedirects(root, "", start)
	if _, ok := current().Lookup("/old-prices"); ok {
		t.Fatal("a redirect before one was added")
	}
	if err := cmdRedirect(root, []string{"add", "/old-prices", "/shop"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdRedirect(root, []string{"add", "/old-prices", "/catalogue", "--temporary"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdRedirect(root, []string{"add", "/catalogue", "/old-prices"}); err == nil {
		t.Fatal("a loop was taken")
	}
	time.Sleep(1100 * time.Millisecond)
	r, ok := current().Lookup("/old-prices")
	if !ok || r.To != "/catalogue" || r.Permanent {
		t.Fatalf("%+v %v", r, ok)
	}
	if err := cmdRedirect(root, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdRedirect(root, []string{"remove", "/old-prices"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdRedirect(root, []string{"remove", "/old-prices"}); err == nil {
		t.Fatal("removed twice")
	}
	time.Sleep(1100 * time.Millisecond)
	if _, ok := current().Lookup("/old-prices"); ok {
		t.Fatal("the site still sends it after it was removed")
	}
}

// A redirect whose old address is typed percent-encoded is the one the site
// sends a request for that address on.
//
// `quilzo redirect add /%C3%BCr%C3%BCnler2 /shop` stored the address as
// typed and said it now went to /shop. The site is asked for the decoded
// path, so the rule never matched and the address stayed a 404, while the
// same address typed as /ürünler2 worked. Either spelling is one address:
// it is added once, and removed by the other.
func TestARedirectTypedPercentEncodedIsTheAddressTheSiteIsAskedFor(t *testing.T) {
	root := demoStore(t)
	if err := cmdRedirect(root, []string{"add", "/%C3%BCr%C3%BCnler2", "/shop"}); err != nil {
		t.Fatal(err)
	}
	m, err := servedRedirects(root, "")
	if err != nil {
		t.Fatal(err)
	}
	// What net/http hands the site for GET /%C3%BCr%C3%BCnler2.
	if r, ok := m.Lookup("/ürünler2"); !ok || r.To != "/shop" {
		t.Fatalf("a request for /%%C3%%BCr%%C3%%BCnler2 is not sent to /shop: %+v %v", r, ok)
	}
	if err := cmdRedirect(root, []string{"add", "/ürünler2", "/catalogue"}); err != nil {
		t.Fatal(err)
	}
	if m, err = servedRedirects(root, ""); err != nil {
		t.Fatal(err)
	}
	if r, _ := m.Lookup("/ürünler2"); r.To != "/catalogue" || m.Len() != 1 {
		t.Fatalf("the other spelling did not replace the rule: %+v, %d rule(s)", r, m.Len())
	}
	if err := cmdRedirect(root, []string{"remove", "/%c3%bcr%c3%bcnler2"}); err != nil {
		t.Fatalf("the rule is not removed by its encoded spelling: %v", err)
	}
}

// A site whose redirects name one address both ways still goes where it
// went.
//
// The encoded rule a site import wrote never matched, so an owner who added
// the address as it is written, to a page of another name, had both in the
// store's redirects, and the site served theirs. Read as one address, the
// first of the two was kept, which is the import's: the old link moved to a
// page that may no longer be there, with nobody having changed a rule. The
// rule written as the address is stays the one served, whichever file each
// is in.
func TestARuleWrittenAsItsAddressIsServedOverOneThatDecodesToIt(t *testing.T) {
	root := demoStore(t)
	encoded := seo.Redirect{From: "/%c3%bcr%c3%bcnlerimiz/", To: "/r-nlerimiz", Permanent: true}
	written := seo.Redirect{From: "/ürünlerimiz", To: "/urunler", Permanent: true}
	if err := saveJSON(storeRedirectsPath(root), redirectFile{Redirects: []seo.Redirect{encoded, written}}); err != nil {
		t.Fatal(err)
	}
	served := func(file string) string {
		t.Helper()
		m, err := servedRedirects(root, file)
		if err != nil {
			t.Fatalf("the site would not start: %v", err)
		}
		r, _ := m.Lookup("/ürünlerimiz")
		return r.To
	}
	if to := served(""); to != "/urunler" {
		t.Errorf("/ürünlerimiz goes to %q, and the site was sending it to /urunler", to)
	}
	// The import's own file given as well, as its report says to serve it.
	file := filepath.Join(t.TempDir(), "pkg.redirects.json")
	if err := saveJSON(file, redirectFile{Redirects: []seo.Redirect{encoded}}); err != nil {
		t.Fatal(err)
	}
	if to := served(file); to != "/urunler" {
		t.Errorf("with the import's file given, /ürünlerimiz goes to %q", to)
	}
	// A file still wins over the store for an address both write alike.
	if err := saveJSON(file, redirectFile{Redirects: []seo.Redirect{{From: "/ürünlerimiz/", To: "/yeni"}}}); err != nil {
		t.Fatal(err)
	}
	if to := served(file); to != "/yeni" {
		t.Errorf("the file given does not win for an address written alike: %q", to)
	}
	// And another redirect can still be added beside the two.
	if err := cmdRedirect(root, []string{"add", "/old", "/new"}); err != nil {
		t.Errorf("a redirect cannot be added to a store holding both spellings: %v", err)
	}
}

// An old address in an encoding other than UTF-8 is kept as it was typed.
//
// A site older than UTF-8 addresses has /caf%E9, which decodes to bytes
// that are not text. `redirect add` stored the address decoded, and those
// bytes do not survive being written to the file: the rule came back as
// another address, and the old link stayed a 404 after being told it now
// went somewhere.
func TestARedirectFromAnAddressThatIsNotUTF8IsKeptAsTyped(t *testing.T) {
	root := demoStore(t)
	if err := cmdRedirect(root, []string{"add", "/caf%E9", "/cafe"}); err != nil {
		t.Fatal(err)
	}
	m, err := servedRedirects(root, "")
	if err != nil {
		t.Fatal(err)
	}
	// What net/http hands the site for GET /caf%E9.
	if r, ok := m.Lookup("/caf\xe9"); !ok || r.To != "/cafe" {
		t.Fatalf("a request for /caf%%E9 is not sent to /cafe: %+v %v", r, ok)
	}
	if err := cmdRedirect(root, []string{"remove", "/caf%e9"}); err != nil {
		t.Fatalf("the rule is not removed: %v", err)
	}
}
