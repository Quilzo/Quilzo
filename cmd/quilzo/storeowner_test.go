// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// The account the store belongs to starts its servers without a token, and
// nobody else does.
//
// `quilzo init --admin NAME` ends by telling its reader to start the admin,
// the systemd unit starts the site as the store's account with no credential,
// and the image starts the admin as the account its store is owned by. All
// three were refused the moment the store had an administrator: serve and
// site needed publish, and none of them presents a token. The first thing a
// new install was told to do failed with "publish needs a verified identity".
func TestTheStoresOwnerStartsItsServersWithoutAToken(t *testing.T) {
	root := connectStore(t)
	t.Setenv("QUILZO_TOKEN", "")
	t.Setenv("HOME", t.TempDir())
	if err := cmdAuth(root, []string{"grant", "dana", "admin"}); err != nil {
		t.Fatal(err)
	}
	if !storeOwnedByMe(root) {
		t.Skip("this system does not say whose a directory is; servers start with a token here")
	}
	for _, c := range [][]string{{"serve", "--addr", "127.0.0.1:0"}, {"site", "--addr", "127.0.0.1:0"}, {"site", "--prepare"}} {
		if err := authoriseCommand(root, c[0], c[1:]); err != nil {
			t.Errorf("%v was refused to the account the store belongs to: %v", c, err)
		}
	}

	// Only the servers. The same account still needs a token to act on the
	// store, and `site new` is authoring, not a server.
	for _, c := range [][]string{{"publish"}, {"site", "new", "a bakery"}, {"auth", "grant", "eve", "admin"}} {
		if err := authoriseCommand(root, c[0], c[1:]); err == nil {
			t.Errorf("%v ran with no token because the store's account asked", c)
		}
	}

	// Somebody else: refused, and told who may start it.
	startedByStoreOwner = func(string) bool { return false }
	t.Cleanup(func() { startedByStoreOwner = storeOwnedByMe })
	for _, c := range []string{"serve", "site"} {
		err := authoriseCommand(root, c, nil)
		if err == nil {
			t.Fatalf("%s started for an account the store does not belong to, with no token", c)
		}
		if !strings.Contains(err.Error(), "the account the store belongs to") {
			t.Errorf("the refusal of %s does not say who may start it: %v", c, err)
		}
	}
}
