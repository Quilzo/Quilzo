// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// count added a bare s to every noun, and two of its callers handed it a
// word that does not take one: moving a page two menus link to said "2 menu
// entrys would be retargeted", and `memory forget` said "0 memorys removed".
func TestCountSpellsThePluralOfEveryWordItIsGiven(t *testing.T) {
	for _, c := range []struct {
		n    int
		noun string
		want string
	}{
		{1, "menu entry", "1 menu entry"},
		{2, "menu entry", "2 menu entries"},
		{0, "memory", "0 memories"},
		{1, "memory", "1 memory"},
		{3, "memory", "3 memories"},
		{2, "submission", "2 submissions"},
		{2, "day", "2 days"},
		{2, "key", "2 keys"},
		{2, "address", "2 addresses"},
		{2, "box", "2 boxes"},
		{2, "match", "2 matches"},
		{2, "time", "2 times"},
	} {
		if got := count(c.n, c.noun); got != c.want {
			t.Errorf("count(%d, %q) = %q, want %q", c.n, c.noun, got, c.want)
		}
	}
}

// The help said `quilzo webhook list | remove ID | test`, but an endpoint has
// no id: neither the list nor its JSON shows one, and `webhook remove` takes
// the address it was added with. An administrator following the help looked
// for an id that is not there.
func TestWebhookRemoveIsHelpedByTheAddressItTakes(t *testing.T) {
	help := helpFor("webhook", []string{"remove"})
	if !strings.Contains(help, "remove URL") || strings.Contains(help, "remove ID") {
		t.Errorf("the help for webhook remove does not name the address it takes:\n%s", help)
	}
	err := hookRemove(t.TempDir(), nil)
	if err == nil || !strings.Contains(err.Error(), "webhook remove URL") {
		t.Errorf("webhook remove's own usage does not agree with the help: %v", err)
	}
}

// `records list` showed each record by the first twelve characters of its
// id, which `records get` and `records delete` then refused as "not a
// record id: 32 hexadecimal characters". The help's own journey (list,
// then get or delete what it showed) could not be followed without --json.
func TestARecordIsListedByAnIDItsSiblingsTake(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	if _, e, code := cliRun(t, root, "", "records", "add", "products", "name=pen"); code != 0 {
		t.Fatalf("records add: %s", e)
	}
	o, e, code := cliRun(t, root, "", "records", "list", "products")
	if code != 0 {
		t.Fatalf("records list: %s", e)
	}
	shown := strings.Fields(o)[0]
	for _, verb := range []string{"get", "delete"} {
		if _, e, code := cliRun(t, root, "", "records", verb, "products", shown); code != 0 {
			t.Errorf("`records %s products %s`, the id the list showed, exited %d: %s", verb, shown, code, e)
		}
	}
}
