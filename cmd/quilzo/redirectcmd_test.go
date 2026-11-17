// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"
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
