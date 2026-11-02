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
