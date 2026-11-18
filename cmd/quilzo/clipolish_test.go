// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
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
