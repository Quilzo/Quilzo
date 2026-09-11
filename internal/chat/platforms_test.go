// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package chat

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Two platforms sharing a name is one platform, and the way it happens is a
// copy-paste.
//
//	Telegram Platform = "telegram"
//	Slack    Platform = "slack"
//	Discord  Platform = "slack"   // <- added by duplicating the line above
//
// Every credential check still passes: the constants are distinct identifiers,
// so the compiler is content, and each platform verifies its own credentials
// correctly. What breaks is that Discord and Slack now derive the same signing
// key and produce colliding handles — a cross-platform replay and a shared set
// of pages, from a line that looks right.
//
// The declared list is read out of the source rather than restated here,
// because a list maintained by hand is the thing that goes stale and this test
// exists to catch exactly that kind of drift.
func TestNoTwoPlatformsShareAName(t *testing.T) {
	src, err := os.ReadFile("chat.go")
	if err != nil {
		t.Fatal(err)
	}

	declared := regexp.MustCompile(`(?m)^\s*(\w+)\s+Platform\s*=\s*"([^"]*)"`).
		FindAllStringSubmatch(string(src), -1)
	if len(declared) < 2 {
		t.Fatalf("found %d platform constants in the source; the pattern is "+
			"matching almost nothing and this test would pass by checking "+
			"nothing", len(declared))
	}

	byValue := map[string]string{}
	for _, d := range declared {
		name, value := d[1], d[2]
		if first, clash := byValue[value]; clash {
			t.Errorf("%s and %s are both %q. They would derive the same "+
				"signing key and collide in handles, so they are one platform "+
				"wearing two names.", first, name, value)
		}
		byValue[value] = name

		// And every declared name has to satisfy the rules, or a credential
		// minted for it is unverifiable and a handle built from it is
		// ambiguous.
		if !Platform(value).Valid() {
			t.Errorf("%s is %q, which Platform.Valid refuses", name, value)
		}
	}
	t.Logf("%d platform(s) declared, all distinct and valid", len(declared))
}

// The rule that makes a handle unambiguous, checked against the failure it
// prevents rather than by restating itself.
//
// A platform name ending in a digit lets the boundary between the name and the
// id fall in two places, so two different accounts produce one handle — and a
// handle is what content is stored under.
func TestNoTwoAccountsCanShareAHandle(t *testing.T) {
	// The exact collision that motivated the rule.
	a := Account{Platform: "tele", ID: 4212}
	b := Account{Platform: "tele4", ID: 212}
	if !a.Platform.Valid() {
		t.Fatalf("%q was refused, and it is a legitimate name", a.Platform)
	}
	if b.Platform.Valid() {
		t.Fatalf("%q ends in a digit and was accepted; it collides with "+
			"%q + %d, both giving %q",
			b.Platform, a.Platform, a.ID, a.Handle())
	}

	// And a sweep, so the property is checked rather than the one example.
	// Every valid platform name paired with a range of ids must give a handle
	// nothing else gives.
	names := []Platform{"telegram", "slack", "discord", "matrix", "web3chat"}
	seen := map[string]string{}
	checked := 0
	for _, p := range names {
		if !p.Valid() {
			t.Errorf("%q was refused and should not have been", p)
			continue
		}
		for id := int64(1); id <= 2000; id++ {
			h := Account{Platform: p, ID: id}.Handle()
			key := fmt.Sprintf("%s/%d", p, id)
			if other, clash := seen[h]; clash {
				t.Fatalf("handle %q is produced by both %s and %s", h, other, key)
			}
			seen[h] = key
			checked++
		}
	}
	// Count what was examined: an empty sweep finds no collisions and looks
	// exactly like a pass.
	if checked != len(names)*2000 {
		t.Fatalf("checked %d handles, expected %d", checked, len(names)*2000)
	}
	t.Logf("%d handles checked across %d platforms, no collision",
		checked, len(names))
}

// A trailing digit is refused wherever it appears in the name, not only at the
// end of a word.
func TestATrailingDigitIsRefusedAnywhereItEndsTheName(t *testing.T) {
	for _, bad := range []string{"tele4", "x1", "9", "chat2026", "a0"} {
		if Platform(bad).Valid() {
			t.Errorf("%q ends in a digit and was accepted", bad)
		}
	}
	// Digits inside a name are fine: the split is still the trailing run.
	for _, good := range []string{"web3chat", "s3rvice", "matrix"} {
		if !Platform(good).Valid() {
			t.Errorf("%q was refused; only a trailing digit is ambiguous", good)
		}
		h := Account{Platform: Platform(good), ID: 42}.Handle()
		if want := good + strconv.FormatInt(42, 10); h != want {
			t.Errorf("handle for %q is %q, want %q", good, h, want)
		}
	}
}

// No two platforms produce the same handle for different people.
//
// A handle is a prefix followed immediately by a decimal id, and it is a
// content path — so a collision does not raise an error, it hands one person
// another's pages. Platform.Valid refuses a platform name ending in a digit
// for this reason and argues it at length; the prefix carries the same risk
// and nothing was checking it.
//
// Three rules, and the third is the one a new platform will trip on.
func TestNoTwoPlatformsShareAHandlePrefix(t *testing.T) {
	all := []Platform{Telegram, Slack, Discord}

	seen := map[string]Platform{}
	for _, p := range all {
		pre := p.Prefix()
		if pre == "" {
			t.Errorf("%s has no prefix, so its handles are bare numbers and "+
				"collide with every other platform", p)
			continue
		}
		// A prefix ending in a digit is ambiguous against the id that follows
		// it: prefix "s1" with id 23 and prefix "s" with id 123 are both
		// "s123".
		if last := pre[len(pre)-1]; last >= '0' && last <= '9' {
			t.Errorf("%s has prefix %q, which ends in a digit — the id runs "+
				"straight on from it, so the split is ambiguous", p, pre)
		}
		if other, clash := seen[pre]; clash {
			t.Errorf("%s and %s both use prefix %q, so the same id is one "+
				"handle for two people and one of them edits the other's pages",
				p, other, pre)
		}
		seen[pre] = p

		// And no prefix may be a prefix of another, for the same reason: "s"
		// and "sl" with the right ids meet in the middle.
		for _, q := range all {
			if q == p {
				continue
			}
			if strings.HasPrefix(q.Prefix(), pre) {
				t.Errorf("%s's prefix %q begins %s's %q; with the right ids "+
					"the two handles meet", p, pre, q, q.Prefix())
			}
		}
	}
}

// The handle the editor stores under is the handle this package computes.
//
// These disagreed. chat said "telegram123" and internal/telegram's editor
// wrote "tg123", so the identity layer and the thing that actually held
// somebody's work had different names for them. Nothing failed because only
// one of the two was ever used for a path.
func TestAHandleIsThePrefixAndTheID(t *testing.T) {
	a := Account{Platform: Telegram, ID: 4212}
	if got := a.Handle(); got != "tg4212" {
		t.Errorf("Telegram handle is %q; the editor has always written "+
			"tg4212 and that is a content path, so changing it moves "+
			"somebody's pages", got)
	}
	if got := (Account{Platform: Slack, ID: 7}).Handle(); got != "sl7" {
		t.Errorf("Slack handle is %q, want sl7", got)
	}
}
